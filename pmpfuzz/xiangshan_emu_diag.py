from __future__ import annotations

import argparse
import struct
from pathlib import Path


ELF_MAGIC = b"\x7fELF"
SHT_SYMTAB = 2
SHT_DYNSYM = 11
RESULT_OBSERVATION_SLOT_OFFSET = 32
XIANGSHAN_EMU_CPP_CANDIDATES = (
    Path("difftest/src/test/csrc/emu/emu.cpp"),
    Path("out/xiangshan/resources.dest/difftest-src/src/test/csrc/emu/emu.cpp"),
)
PATCH_MARKER = "PMPFuzz XiangShan tohost diagnostic hook"


def resolve_elf_symbol_address(image: Path, symbol: str) -> int | None:
    try:
        data = image.read_bytes()
    except OSError:
        return None
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        return None

    elf_class = data[4]
    data_encoding = data[5]
    if data_encoding == 1:
        endian = "<"
    elif data_encoding == 2:
        endian = ">"
    else:
        return None

    try:
        if elf_class == 2:
            header = _unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            shoff = header[5]
            shentsize = header[10]
            shnum = header[11]
            sh_fmt = endian + "IIQQQQIIQQ"
            sym_fmt = endian + "IBBHQQ"
        elif elf_class == 1:
            header = _unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            shoff = header[5]
            shentsize = header[10]
            shnum = header[11]
            sh_fmt = endian + "IIIIIIIIII"
            sym_fmt = endian + "IIIBBH"
        else:
            return None
    except struct.error:
        return None

    sections = []
    try:
        for index in range(shnum):
            off = shoff + index * shentsize
            sections.append(_unpack_from(sh_fmt, data, off))
    except struct.error:
        return None

    for section in sections:
        sh_type = section[1]
        if sh_type not in {SHT_SYMTAB, SHT_DYNSYM}:
            continue
        sh_offset = section[4]
        sh_size = section[5]
        sh_link = section[6]
        sh_entsize = section[9]
        if sh_link >= len(sections) or sh_entsize == 0:
            continue
        str_section = sections[sh_link]
        str_offset = str_section[4]
        str_size = str_section[5]
        strtab = data[str_offset : str_offset + str_size]
        if len(strtab) != str_size:
            continue
        count = sh_size // sh_entsize
        for index in range(count):
            try:
                sym = _unpack_from(sym_fmt, data, sh_offset + index * sh_entsize)
            except struct.error:
                break
            if elf_class == 2:
                st_name, _, _, _, st_value, _ = sym
            else:
                st_name, st_value, _, _, _, _ = sym
            if _elf_cstring(strtab, st_name) == symbol:
                return st_value
    return None


def xiangshan_diag_env_for_image(image: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    tohost_addr = resolve_elf_symbol_address(image, "tohost")
    if tohost_addr is not None:
        env["PMFUZZ_TOHOST_ADDR"] = f"0x{tohost_addr:x}"
    result_addr = resolve_elf_symbol_address(image, "result")
    if result_addr is not None:
        env["PMFUZZ_RESULT_SLOT_ADDR"] = f"0x{result_addr + RESULT_OBSERVATION_SLOT_OFFSET:x}"
    return env


def patch_emu_cpp_text(text: str) -> str:
    if PATCH_MARKER in text:
        return text

    helper_anchor = 'extern remote_bitbang_t *jtag;\n'
    helper = """extern remote_bitbang_t *jtag;\n\n// PMPFuzz XiangShan tohost diagnostic hook\nstatic bool pmfuzz_read_env_u64(const char *name, uint64_t *value) {\n  const char *text = getenv(name);\n  if (text == NULL || *text == '\\0') {\n    return false;\n  }\n  errno = 0;\n  char *end = NULL;\n  unsigned long long parsed = strtoull(text, &end, 0);\n  if (errno != 0 || end == text || (end != NULL && *end != '\\0')) {\n    return false;\n  }\n  *value = (uint64_t)parsed;\n  return true;\n}\n\nstatic bool pmfuzz_read_structured_payload(uint64_t *payload, const char **source) {\n  static bool initialized = false;\n  static bool has_tohost = false;\n  static bool has_result_slot = false;\n  static uint64_t tohost_addr = 0;\n  static uint64_t result_slot_addr = 0;\n  if (!initialized) {\n    initialized = true;\n    has_tohost = pmfuzz_read_env_u64(\"PMFUZZ_TOHOST_ADDR\", &tohost_addr);\n    has_result_slot = pmfuzz_read_env_u64(\"PMFUZZ_RESULT_SLOT_ADDR\", &result_slot_addr);\n  }\n\n  if (has_result_slot && result_slot_addr != 0) {\n    uint64_t result_value = pmem_read(result_slot_addr);\n    if (result_value != 0) {\n      *payload = result_value;\n      *source = \"result-slot\";\n      return true;\n    }\n  }\n\n  if (has_tohost && tohost_addr != 0) {\n    uint64_t tohost_value = pmem_read(tohost_addr);\n    if (tohost_value != 0) {\n      *payload = tohost_value;\n      *source = \"tohost\";\n      return true;\n    }\n  }\n\n  return false;\n}\n\nstatic void pmfuzz_print_tohost_diag_if_configured() {\n  uint64_t payload = 0;\n  const char *source = NULL;\n  if (!pmfuzz_read_structured_payload(&payload, &source)) {\n    return;\n  }\n  eprintf(\"PMFUZZ_DIAG tohost=0x%\" PRIx64 \" source=%s\\n\", payload, source ? source : \"unknown\");\n}\n"""
    if helper_anchor not in text:
        raise ValueError("failed to locate XiangShan emu helper anchor")
    patched = text.replace(helper_anchor, helper, 1)

    dump_anchor = """  if (trapCode != STATE_ABORT) {\n    trigger_stat_dump();\n  }\n}"""
    dump_insert = """  if (trapCode != STATE_ABORT) {\n    trigger_stat_dump();\n  }\n\n  if (trapCode == STATE_GOODTRAP || trapCode == STATE_BADTRAP) {\n    pmfuzz_print_tohost_diag_if_configured();\n  }\n}"""
    if dump_anchor in patched:
        return patched.replace(dump_anchor, dump_insert, 1)

    display_anchor = "    difftest[i]->display_stats();"
    display_insert = """    if (i == 0 && (trapCode == STATE_GOODTRAP || trapCode == STATE_BADTRAP)) {\n      pmfuzz_print_tohost_diag_if_configured();\n    }\n\n    difftest[i]->display_stats();"""
    if display_anchor not in patched:
        raise ValueError("failed to locate XiangShan emu display anchor")
    return patched.replace(display_anchor, display_insert, 1)


def patch_xiangshan_emu_tree(xiangshan_dir: Path) -> list[Path]:
    patched_paths: list[Path] = []
    for relative in XIANGSHAN_EMU_CPP_CANDIDATES:
        emu_cpp = xiangshan_dir / relative
        if not emu_cpp.is_file():
            continue
        text = emu_cpp.read_text(encoding="utf-8")
        patched = patch_emu_cpp_text(text)
        if patched != text:
            emu_cpp.write_text(patched, encoding="utf-8")
        patched_paths.append(emu_cpp)
    if not patched_paths:
        raise FileNotFoundError("failed to locate XiangShan emu.cpp to patch")
    return patched_paths


def _elf_cstring(data: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def _unpack_from(fmt: str, data: bytes, offset: int):
    return struct.unpack_from(fmt, data, offset)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Patch XiangShan emu.cpp to emit PMFUZZ_DIAG tohost lines")
    parser.add_argument("--xiangshan-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    patched_paths = patch_xiangshan_emu_tree(args.xiangshan_dir)
    for patched in patched_paths:
        print(patched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
