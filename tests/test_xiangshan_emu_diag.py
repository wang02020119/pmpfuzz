from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.xiangshan_emu_diag import (
    PATCH_MARKER,
    patch_emu_cpp_text,
    patch_xiangshan_emu_tree,
    resolve_elf_symbol_address,
    xiangshan_diag_env_for_image,
)


def _elf64_with_symbols(symbols: dict[str, int]) -> bytes:
    strtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name in symbols:
        name_offsets[name] = len(strtab)
        strtab.extend(name.encode("ascii"))
        strtab.append(0)

    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
    for name, value in symbols.items():
        symtab.extend(struct.pack("<IBBHQQ", name_offsets[name], 0x10, 0, 1, value, 0))

    header_size = 64
    strtab_offset = header_size
    symtab_offset = strtab_offset + len(strtab)
    if symtab_offset % 8:
        symtab_offset += 8 - (symtab_offset % 8)
    shoff = symtab_offset + len(symtab)
    if shoff % 8:
        shoff += 8 - (shoff % 8)

    ident = bytearray(b"\x7fELF")
    ident.extend((2, 1, 1, 0, 0))
    ident.extend(b"\x00" * (16 - len(ident)))
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        1,
        243,
        1,
        0,
        0,
        shoff,
        0,
        header_size,
        0,
        0,
        64,
        3,
        0,
    )
    null_sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    strtab_sh = struct.pack(
        "<IIQQQQIIQQ",
        0,
        3,
        0,
        0,
        strtab_offset,
        len(strtab),
        0,
        0,
        1,
        0,
    )
    symtab_sh = struct.pack(
        "<IIQQQQIIQQ",
        0,
        2,
        0,
        0,
        symtab_offset,
        len(symtab),
        1,
        1,
        8,
        24,
    )

    blob = bytearray()
    blob.extend(header)
    blob.extend(strtab)
    while len(blob) < symtab_offset:
        blob.append(0)
    blob.extend(symtab)
    while len(blob) < shoff:
        blob.append(0)
    blob.extend(null_sh)
    blob.extend(strtab_sh)
    blob.extend(symtab_sh)
    return bytes(blob)


class XiangShanEmuDiagTest(unittest.TestCase):
    def test_resolves_tohost_symbol_from_minimal_elf64(self):
        with TemporaryDirectory() as tmp:
            elf = Path(tmp) / "case.elf"
            elf.write_bytes(_elf64_with_symbols({"tohost": 0x80002080, "result": 0x80002040}))

            self.assertEqual(resolve_elf_symbol_address(elf, "tohost"), 0x80002080)
            self.assertEqual(resolve_elf_symbol_address(elf, "result"), 0x80002040)
            self.assertIsNone(resolve_elf_symbol_address(elf, "missing"))

    def test_diag_env_uses_hex_tohost_symbol(self):
        with TemporaryDirectory() as tmp:
            elf = Path(tmp) / "case.elf"
            elf.write_bytes(_elf64_with_symbols({"tohost": 0x80002080, "result": 0x80002040}))

            self.assertEqual(
                xiangshan_diag_env_for_image(elf),
                {
                    "PMFUZZ_TOHOST_ADDR": "0x80002080",
                    "PMFUZZ_RESULT_SLOT_ADDR": "0x80002060",
                },
            )

    def test_patch_emu_cpp_text_is_idempotent(self):
        original = """#include "emu.h"\n#include "ram.h"\nextern remote_bitbang_t *jtag;\nvoid Emulator::display_stats() {\n  for (int i = 0; i < NUM_CORES; i++) {\n    switch (trapCode) {\n      case STATE_GOODTRAP:\n        eprintf(ANSI_COLOR_GREEN "HIT GOOD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc);\n        break;\n      case STATE_BADTRAP: eprintf(ANSI_COLOR_RED "HIT BAD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc); break;\n      default: break;\n    }\n    difftest[i]->display_stats();\n  }\n}\n"""

        patched = patch_emu_cpp_text(original)

        self.assertIn(PATCH_MARKER, patched)
        self.assertIn("PMFUZZ_RESULT_SLOT_ADDR", patched)
        self.assertEqual(patch_emu_cpp_text(patched), patched)

    def test_patch_reads_structured_payload_after_stat_dump(self):
        original = """#include "emu.h"\n#include "ram.h"\nextern remote_bitbang_t *jtag;\nvoid Emulator::display_stats() {\n  for (int i = 0; i < NUM_CORES; i++) {\n    switch (trapCode) {\n      case STATE_GOODTRAP:\n        eprintf(ANSI_COLOR_GREEN "HIT GOOD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc);\n        break;\n      case STATE_BADTRAP: eprintf(ANSI_COLOR_RED "HIT BAD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc); break;\n      default: break;\n    }\n    difftest[i]->display_stats();\n  }\n  if (trapCode != STATE_ABORT) {\n    trigger_stat_dump();\n  }\n}\n"""

        patched = patch_emu_cpp_text(original)

        self.assertGreater(
            patched.rfind("pmfuzz_print_tohost_diag_if_configured();"),
            patched.index("trigger_stat_dump();"),
        )

    def test_patch_tree_updates_compiled_emu_source_first(self):
        original = """#include "emu.h"\n#include "ram.h"\nextern remote_bitbang_t *jtag;\nvoid Emulator::display_stats() {\n  for (int i = 0; i < NUM_CORES; i++) {\n    switch (trapCode) {\n      case STATE_GOODTRAP:\n        eprintf(ANSI_COLOR_GREEN "HIT GOOD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc);\n        break;\n      case STATE_BADTRAP: eprintf(ANSI_COLOR_RED "HIT BAD TRAP at pc = 0x%" PRIx64 "\\n" ANSI_COLOR_RESET, pc); break;\n      default: break;\n    }\n    difftest[i]->display_stats();\n  }\n}\n"""

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiled = root / "difftest/src/test/csrc/emu/emu.cpp"
            generated = root / "out/xiangshan/resources.dest/difftest-src/src/test/csrc/emu/emu.cpp"
            compiled.parent.mkdir(parents=True)
            generated.parent.mkdir(parents=True)
            compiled.write_text(original, encoding="utf-8")
            generated.write_text(original, encoding="utf-8")

            patched_paths = patch_xiangshan_emu_tree(root)

            self.assertEqual(
                patched_paths,
                [compiled, generated],
            )
            self.assertIn(PATCH_MARKER, compiled.read_text(encoding="utf-8"))
            self.assertIn(PATCH_MARKER, generated.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
