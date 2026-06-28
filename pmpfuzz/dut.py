from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .diagnostics import classify_log_failure, decode_tohost_payload, failed_tohost_from_log


DEFAULT_CHIPYARD_DIR = Path("/home/dubhe/wjs/boom_host_deploy/cascade-chipyard")
DEFAULT_CLEAN_CHIPYARD_DIR = Path("/home/dubhe/wjs/pmp-duts/chipyard-1.14.0")
DEFAULT_VERILATOR_BIN_DIR = Path("/home/dubhe/wjs/toolchains/eda/bin")
DEFAULT_RISCV = Path("/home/dubhe/wjs/boom_host_deploy/opt-riscv")
DEFAULT_JAVA_HOME = Path("/home/dubhe/.sdkman/candidates/java/11.0.30-tem")
DEFAULT_ROCKET_VERILATOR = Path("/home/dubhe/wjs/pmp-fuzz-stage1/scripts/verilator_rocket_wrapper.sh")
DEFAULT_CVA6_VERILATOR_BIN_DIR = Path(
    "/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/tools/verilator-5.032/bin"
)
DEFAULT_CVA6_VERILATOR = Path("/home/dubhe/wjs/pmp-fuzz-stage1/scripts/verilator_cva6_wrapper.sh")
XIANGSHAN_GOODTRAP_EMU = Path(
    "/home/dubhe/wjs/pmp-duts/xiangshan-clean/build/verilator-compile/emu"
)
XIANGSHAN_NATIVE_EMU = Path(
    "/home/dubhe/wjs/pmp-duts/xiangshan-clean/build/native-tlminimal/verilator-compile/emu"
)
XIANGSHAN_NATIVE_DEBUG_EMU = Path(
    "/home/dubhe/wjs/pmp-duts/xiangshan-clean/build/native-tlminimal-debug/verilator-compile/emu"
)
XIANGSHAN_NATIVE_FAST_EMU = Path(
    "/home/dubhe/wjs/pmp-duts/xiangshan-clean/build/native-tlminimal-fast/verilator-compile/emu"
)
LEGACY_XIANGSHAN_EMU = Path(
    "/home/dubhe/wjs/cascade_xiangshan_adapt/XiangShan/build/native-tlminimal/verilator-compile/emu"
)
DEFAULT_XIANGSHAN_EMU = XIANGSHAN_GOODTRAP_EMU
DEFAULT_CASCADE_ROCKET = (
    DEFAULT_CHIPYARD_DIR
    / "cascade-rocket"
    / "build"
    / "run_vanilla_notrace_0.1"
    / "default-verilator"
    / "Vtop_tiny_soc"
)


def _posix_arg(path: Path) -> str:
    return path.as_posix()


def _subprocess_output_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def _run_command_capture(
    command: list[str],
    *,
    timeout_seconds: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, int | None, str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, _ = process.communicate(timeout=timeout_seconds)
        return False, process.returncode, stdout
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        try:
            stdout, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            stdout, _ = process.communicate()
        return True, None, _subprocess_output_text(exc.stdout) + _subprocess_output_text(stdout)


def _run_command_to_log(
    command: list[str],
    *,
    timeout_seconds: int,
    log_path: Path,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, int | None, str]:
    with log_path.open("w", encoding="utf-8", errors="replace") as handle:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=(os.name == "posix"),
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                process.wait()
            handle.write("\nTIMEOUT\n")
            handle.flush()
            return True, None, _read_log_text(log_path)
    return False, returncode, _read_log_text(log_path)


def _read_log_text(log_path: Path) -> str:
    if not log_path.exists():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
            return
        except ProcessLookupError:
            return
    process.terminate()


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    process.kill()


@dataclass(frozen=True)
class ParsedDutLog:
    status: str
    observed_code: int | None = None
    reason: str | None = None
    failure_class: str | None = None
    observed_mcause: int | None = None
    observed_mtval: int | None = None
    observed_tohost: int | None = None


@dataclass(frozen=True)
class DutRunResult:
    dut: str
    status: str
    elapsed_seconds: float
    returncode: int | None = None
    observed_code: int | None = None
    failure_class: str | None = None
    observed_mcause: int | None = None
    observed_mtval: int | None = None
    observed_tohost: int | None = None
    log: str | None = None
    reason: str | None = None


class SpikeDut:
    def __init__(self, *, spike: str, isa: str) -> None:
        self.name = "spike"
        self.spike = spike
        self.isa = isa

    def run(self, elf: Path, *, timeout_seconds: int, log_path: Path) -> DutRunResult:
        start = time.monotonic()
        timed_out, returncode, stdout = _run_command_to_log(
            [self.spike, f"--isa={self.isa}", str(elf)],
            timeout_seconds=timeout_seconds,
            log_path=log_path,
        )
        if timed_out:
            return DutRunResult(
                dut=self.name,
                status="timeout",
                elapsed_seconds=time.monotonic() - start,
                log=str(log_path),
                failure_class="timeout",
                reason="spike timeout",
            )
        parsed = parse_spike_log(stdout, returncode or 0)
        return DutRunResult(
            dut=self.name,
            status=parsed.status,
            elapsed_seconds=time.monotonic() - start,
            returncode=returncode,
            observed_code=parsed.observed_code,
            observed_tohost=parsed.observed_tohost,
            observed_mcause=parsed.observed_mcause,
            observed_mtval=parsed.observed_mtval,
            failure_class=parsed.failure_class,
            log=str(log_path),
            reason=parsed.reason,
        )


class ChipyardMakeDut:
    def __init__(
        self,
        *,
        dut_name: str,
        chipyard_dir: Path = DEFAULT_CHIPYARD_DIR,
        config: str,
        verilator_bin_dir: Path = DEFAULT_VERILATOR_BIN_DIR,
        riscv: Path = DEFAULT_RISCV,
        java_home: Path = DEFAULT_JAVA_HOME,
        make_vars: tuple[str, ...] = (),
        target: str = "run-binary-fast-hex",
        set_verilator_bin_env: bool = True,
    ) -> None:
        self.name = dut_name
        self.chipyard_dir = chipyard_dir
        self.config = config
        self.verilator_bin_dir = verilator_bin_dir
        self.riscv = riscv
        self.java_home = java_home
        self.make_vars = make_vars
        self.target = target
        self.set_verilator_bin_env = set_verilator_bin_env

    def command_for(self, elf: Path) -> list[str]:
        return ["make", f"CONFIG={self.config}", f"BINARY={_posix_arg(elf)}", *self.make_vars, self.target]

    def env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["RISCV"] = _posix_arg(self.riscv)
        env["JAVA_HOME"] = _posix_arg(self.java_home)
        if self.set_verilator_bin_env:
            env["VERILATOR_BIN"] = _posix_arg(self.verilator_bin_dir / "verilator")
        conda_bin = self.chipyard_dir / ".conda-env" / "bin"
        circt_bin = self.chipyard_dir / "tools" / "circt" / "bin"
        path_prefix = [
            self.java_home / "bin",
            self.riscv / "bin",
        ]
        if circt_bin.exists():
            path_prefix.append(circt_bin)
        if conda_bin.exists():
            path_prefix.append(conda_bin)
        path_prefix.append(self.verilator_bin_dir)
        env["PATH"] = ":".join(_posix_arg(path) for path in path_prefix) + f":{env.get('PATH', '')}"
        return env

    def run(self, elf: Path, *, timeout_seconds: int, log_path: Path) -> DutRunResult:
        start = time.monotonic()
        timed_out, returncode, stdout = _run_command_to_log(
            self.command_for(elf),
            cwd=self.chipyard_dir / "sims" / "verilator",
            env=self.env(),
            timeout_seconds=timeout_seconds,
            log_path=log_path,
        )
        if timed_out:
            return DutRunResult(
                dut=self.name,
                status="timeout",
                elapsed_seconds=time.monotonic() - start,
                log=str(log_path),
                failure_class="timeout",
                reason="chipyard make timeout",
            )
        parsed = parse_chipyard_log(stdout, returncode or 0)
        return DutRunResult(
            dut=self.name,
            status=parsed.status,
            elapsed_seconds=time.monotonic() - start,
            returncode=returncode,
            observed_code=parsed.observed_code,
            failure_class=parsed.failure_class,
            observed_mcause=parsed.observed_mcause,
            observed_mtval=parsed.observed_mtval,
            observed_tohost=parsed.observed_tohost,
            log=str(log_path),
            reason=parsed.reason,
        )


class CascadeRocketDut:
    def __init__(self, *, binary: Path = DEFAULT_CASCADE_ROCKET, simlen: int = 100000) -> None:
        self.name = "rocket-cascade"
        self.binary = binary
        self.simlen = simlen

    def command_and_env(self, elf: Path) -> tuple[list[str], dict[str, str]]:
        env = os.environ.copy()
        env["SIMLEN"] = str(self.simlen)
        env["SIMSRAMELF"] = _posix_arg(elf)
        env["SIMROMELF"] = _posix_arg(elf)
        return [_posix_arg(self.binary)], env

    def run(self, elf: Path, *, timeout_seconds: int, log_path: Path) -> DutRunResult:
        command, env = self.command_and_env(elf)
        start = time.monotonic()
        timed_out, returncode, stdout = _run_command_to_log(
            command,
            env=env,
            timeout_seconds=timeout_seconds,
            log_path=log_path,
        )
        if timed_out:
            return DutRunResult(
                dut=self.name,
                status="timeout",
                elapsed_seconds=time.monotonic() - start,
                log=str(log_path),
                failure_class="timeout",
                reason="cascade rocket timeout",
            )
        parsed = parse_cascade_log(stdout, returncode or 0)
        return DutRunResult(
            dut=self.name,
            status=parsed.status,
            elapsed_seconds=time.monotonic() - start,
            returncode=returncode,
            observed_code=parsed.observed_code,
            failure_class=parsed.failure_class,
            observed_mcause=parsed.observed_mcause,
            observed_mtval=parsed.observed_mtval,
            observed_tohost=parsed.observed_tohost,
            log=str(log_path),
            reason=parsed.reason,
        )


class XiangShanDut:
    def __init__(self, *, binary: Path = DEFAULT_XIANGSHAN_EMU, simlen: int = 100000) -> None:
        self.name = "xiangshan-clean"
        self.binary = resolve_xiangshan_binary(binary)
        self.simlen = simlen

    def command_for(self, image: Path) -> list[str]:
        return [
            _posix_arg(self.binary),
            "--no-diff",
            "-C",
            str(self.simlen),
            "-i",
            _posix_arg(image),
        ]

    def run(self, elf: Path, *, timeout_seconds: int, log_path: Path) -> DutRunResult:
        start = time.monotonic()
        timed_out, returncode, stdout = _run_command_to_log(
            self.command_for(elf),
            timeout_seconds=timeout_seconds,
            log_path=log_path,
        )
        if timed_out:
            return DutRunResult(
                dut=self.name,
                status="timeout",
                elapsed_seconds=time.monotonic() - start,
                log=str(log_path),
                failure_class="timeout",
                reason="xiangshan timeout",
            )
        parsed = parse_xiangshan_log(stdout, returncode or 0)
        return DutRunResult(
            dut=self.name,
            status=parsed.status,
            elapsed_seconds=time.monotonic() - start,
            returncode=returncode,
            observed_code=parsed.observed_code,
            failure_class=parsed.failure_class,
            observed_mcause=parsed.observed_mcause,
            observed_mtval=parsed.observed_mtval,
            observed_tohost=parsed.observed_tohost,
            log=str(log_path),
            reason=parsed.reason,
        )


def make_dut(
    *,
    dut: str,
    spike: str,
    isa: str,
    chipyard_dir: Path = DEFAULT_CHIPYARD_DIR,
    dut_bin: Path | None = None,
    simlen: int = 100000,
) -> SpikeDut | ChipyardMakeDut | CascadeRocketDut | XiangShanDut:
    if dut == "spike":
        return SpikeDut(spike=spike, isa=isa)
    if dut == "rocket":
        return ChipyardMakeDut(
            dut_name="rocket",
            chipyard_dir=chipyard_dir,
            config="RocketConfig",
            verilator_bin_dir=DEFAULT_CVA6_VERILATOR_BIN_DIR,
            make_vars=(
                f"VERILATOR={_posix_arg(DEFAULT_ROCKET_VERILATOR)}",
                "PLATFORM_OPTS=--timing",
                "EXTRA_SIM_CXXFLAGS=-std=c++17",
            ),
        )
    if dut == "rocket-clean":
        return ChipyardMakeDut(
            dut_name="rocket-clean",
            chipyard_dir=chipyard_dir,
            config="RocketConfig",
            verilator_bin_dir=chipyard_dir / ".conda-env" / "bin",
            make_vars=("VERILATOR_THREADS=1",),
            set_verilator_bin_env=False,
        )
    if dut == "boom-clean":
        return ChipyardMakeDut(
            dut_name="boom-clean",
            chipyard_dir=chipyard_dir,
            config="SmallBoomV3Config",
            verilator_bin_dir=chipyard_dir / ".conda-env" / "bin",
            make_vars=("VERILATOR_THREADS=1",),
            set_verilator_bin_env=False,
        )
    if dut in {"cva6", "cva6-clean"}:
        return ChipyardMakeDut(
            dut_name=dut,
            chipyard_dir=chipyard_dir,
            config="CVA6Config",
            verilator_bin_dir=chipyard_dir / ".conda-env" / "bin",
            make_vars=("VERILATOR_THREADS=1",),
            set_verilator_bin_env=False,
        )
    if dut == "rocket-cascade":
        return CascadeRocketDut(binary=dut_bin or DEFAULT_CASCADE_ROCKET, simlen=simlen)
    if dut == "xiangshan-clean":
        return XiangShanDut(binary=dut_bin or DEFAULT_XIANGSHAN_EMU, simlen=simlen)
    raise ValueError(f"unsupported DUT: {dut}")


def resolve_xiangshan_binary(binary: Path) -> Path:
    return _resolve_xiangshan_binary(binary)


def xiangshan_emu_build_config(binary: Path) -> Path | None:
    candidates = [binary.parent / "VSimTop.mk"]
    try:
        resolved = binary.resolve()
    except OSError:
        resolved = binary
    if resolved != binary:
        candidates.append(resolved.parent / "VSimTop.mk")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def xiangshan_emu_supports_goodtrap(binary: Path) -> bool | None:
    config = xiangshan_emu_build_config(binary)
    if config is None:
        return None
    text = config.read_text(encoding="utf-8", errors="replace")
    return "CONFIG_NO_DIFFTEST" not in text


def _resolve_xiangshan_binary(binary: Path) -> Path:
    if binary != DEFAULT_XIANGSHAN_EMU:
        return binary
    candidates = (
        XIANGSHAN_GOODTRAP_EMU,
        XIANGSHAN_NATIVE_EMU,
        XIANGSHAN_NATIVE_DEBUG_EMU,
        XIANGSHAN_NATIVE_FAST_EMU,
        LEGACY_XIANGSHAN_EMU,
    )
    existing = [candidate for candidate in candidates if candidate.exists()]
    for candidate in existing:
        if xiangshan_emu_supports_goodtrap(candidate) is True:
            return candidate
    if existing:
        return existing[0]
    if binary.exists():
        return binary
    return binary


def parse_cascade_log(text: str, returncode: int) -> ParsedDutLog:
    match = re.search(r"Dump of reg x\d+:\s+0x([0-9a-fA-F]+)", text)
    observed_code = int(match.group(1), 16) if match else None
    if returncode != 0:
        return ParsedDutLog("infra_failure", observed_code, f"cascade simulator returned {returncode}")
    if "Found a stop request" not in text:
        return ParsedDutLog("infra_failure", observed_code, "cascade simulator did not observe stop request")
    if observed_code is None:
        return ParsedDutLog("infra_failure", None, "cascade simulator did not dump a result code")
    if observed_code == 1:
        return ParsedDutLog("pass", observed_code)
    return ParsedDutLog("fail", observed_code, f"cascade result code {observed_code}")


def parse_spike_log(text: str, returncode: int) -> ParsedDutLog:
    code = failed_tohost_from_log(text)
    if code is not None:
        decoded = decode_tohost_payload(code)
        return ParsedDutLog(
            "fail",
            code,
            "spike reported failed tohost",
            failure_class=classify_log_failure(text, returncode, decoded),
            observed_mcause=decoded.observed_mcause if decoded else None,
            observed_mtval=decoded.observed_mtval if decoded else None,
            observed_tohost=code,
        )
    if returncode != 0:
        return ParsedDutLog(
            "fail",
            None,
            "spike returned non-zero",
            failure_class=classify_log_failure(text, returncode),
        )
    return ParsedDutLog("pass")


def parse_chipyard_log(text: str, returncode: int) -> ParsedDutLog:
    code = failed_tohost_from_log(text)
    if code is not None:
        decoded = decode_tohost_payload(code)
        failure_class = classify_log_failure(text, returncode, decoded)
        return ParsedDutLog(
            "fail",
            code,
            "chipyard simulator reported failure",
            failure_class=failure_class,
            observed_mcause=decoded.observed_mcause if decoded else None,
            observed_mtval=decoded.observed_mtval if decoded else None,
            observed_tohost=code,
        )
    if returncode != 0:
        return ParsedDutLog(
            "infra_failure",
            None,
            f"chipyard simulator returned {returncode}",
            failure_class=classify_log_failure(text, returncode),
        )
    return ParsedDutLog("pass")


def parse_xiangshan_log(text: str, returncode: int) -> ParsedDutLog:
    code = failed_tohost_from_log(text)
    if code is not None:
        decoded = decode_tohost_payload(code)
        return ParsedDutLog(
            "fail",
            code,
            "xiangshan reported failed tohost",
            failure_class=classify_log_failure(text, returncode, decoded),
            observed_mcause=decoded.observed_mcause if decoded else None,
            observed_mtval=decoded.observed_mtval if decoded else None,
            observed_tohost=code,
        )
    if "HIT GOOD TRAP" in text or "good trap" in text.lower():
        return ParsedDutLog("pass")
    if "HIT BAD TRAP" in text or "bad trap" in text.lower():
        return ParsedDutLog(
            "fail",
            None,
            "xiangshan reported bad trap",
            failure_class="xiangshan_bad_trap",
        )
    if "EXCEEDING CYCLE/INSTR LIMIT" in text:
        return ParsedDutLog(
            "infra_failure",
            None,
            "xiangshan exceeded cycle limit before observing good/bad trap",
            failure_class="infra_unadapted",
        )
    if returncode != 0:
        return ParsedDutLog(
            "fail",
            None,
            f"xiangshan returned {returncode}",
            failure_class=classify_log_failure(text, returncode),
        )
    return ParsedDutLog(
        "infra_failure",
        None,
        "xiangshan finished without a recognizable pass/fail marker",
        failure_class="infra_unadapted",
    )
