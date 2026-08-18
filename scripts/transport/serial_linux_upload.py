import argparse
import base64
import hashlib
import os
import re
import sys
import time
from pathlib import Path

import serial


ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\a]*(?:\a|\x1b\\)")
LINUX_PROMPT_RE = re.compile(r"(?m)(^|\r|\n)(debian@[^\r\n]*[$#]\s*|root@[^\r\n]*#\s*)$")
LOGIN_PROMPT_RE = re.compile(r"(?m)(^|\r|\n)[^\r\n]*login:\s*$")
PASSWORD_PROMPT_RE = re.compile(r"(?m)(^|\r|\n)Password:\s*$")
UBOOT_PROMPT_RE = re.compile(r"(?m)(^|\r|\n)(=>\s*|[A-Za-z0-9_. -]+#\s*)$")


def strip_ansi(text: str) -> str:
    text = ANSI_CSI_RE.sub("", text)
    text = ANSI_OSC_RE.sub("", text)
    return text


def sh_single_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


class SerialLinuxSession:
    def __init__(
        self,
        *,
        port_name: str,
        baud: int,
        login_user: str,
        login_password: str,
        output_log: Path | None,
    ) -> None:
        self.port_name = port_name
        self.baud = baud
        self.login_user = login_user
        self.login_password = login_password
        self.output_log = output_log
        self.serial = serial.Serial(port_name, baudrate=baud, timeout=0.1, write_timeout=1.0)
        self.serial.dtr = True
        self.serial.rts = True
        self.raw_chunks: list[str] = []

    def close(self) -> None:
        try:
            self._save_log()
        finally:
            self.serial.close()

    def _save_log(self) -> None:
        if self.output_log is None:
            return
        self.output_log.parent.mkdir(parents=True, exist_ok=True)
        self.output_log.write_text("".join(self.raw_chunks), encoding="utf-8", errors="replace")

    def read_existing(self) -> str:
        chunk = self.serial.read(self.serial.in_waiting or 1).decode("utf-8", errors="replace")
        if chunk:
            self.raw_chunks.append(chunk)
        return chunk

    def drain(self, seconds: float = 0.3) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.read_existing()
            time.sleep(0.05)

    def clean_text(self) -> str:
        return strip_ansi("".join(self.raw_chunks))

    def write_line(self, line: str) -> None:
        self.serial.write((line + "\r").encode("utf-8"))
        self.serial.flush()

    def write_lines(self, lines: list[str]) -> None:
        payload = "\r".join(lines) + "\r"
        self.serial.write(payload.encode("ascii"))
        self.serial.flush()

    def wait_for(self, predicate, timeout_seconds: int, start_offset: int = 0) -> str:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self.read_existing()
            clean_text = self.clean_text()
            if predicate(clean_text[start_offset:]):
                return clean_text
            time.sleep(0.1)
        raise TimeoutError("serial wait timed out")

    def enter_shell(self, timeout_seconds: int = 90) -> None:
        deadline = time.monotonic() + timeout_seconds
        sent_user = False
        sent_password = False
        self.serial.write(b"\r")
        self.serial.flush()
        while time.monotonic() < deadline:
            self.read_existing()
            clean_text = self.clean_text()
            if UBOOT_PROMPT_RE.search(clean_text):
                raise RuntimeError("serial console is at U-Boot prompt, not Linux")
            if LINUX_PROMPT_RE.search(clean_text):
                return
            if not sent_user and LOGIN_PROMPT_RE.search(clean_text):
                self.write_line(self.login_user)
                sent_user = True
                time.sleep(0.5)
                continue
            if sent_user and not sent_password and PASSWORD_PROMPT_RE.search(clean_text):
                self.write_line(self.login_password)
                sent_password = True
                time.sleep(1.0)
                continue
            time.sleep(0.1)
        raise TimeoutError("could not reach a Linux shell over serial")

    def run_wrapped_command(self, command: str, timeout_seconds: int = 120) -> tuple[int, str]:
        marker = f"CODEX_SERIAL_{int(time.time())}_{os.getpid()}_{len(self.raw_chunks)}"
        begin_marker = f"__BEGIN__{marker}__"
        end_marker = f"__END__{marker}__"
        wrapped_command = (
            f"printf '{begin_marker}\\n'; "
            f"{command}; "
            f"rc=$?; "
            f"printf '\\n{end_marker} rc=%s\\n' \"$rc\""
        )
        self.drain()
        start_offset = len(self.clean_text())
        self.write_line(wrapped_command)
        def wrapped_command_complete(text: str) -> bool:
            begin_index = text.rfind(begin_marker)
            if begin_index == -1:
                return False
            return text.find(f"{end_marker} rc=", begin_index + len(begin_marker)) != -1

        clean_text = self.wait_for(
            wrapped_command_complete,
            timeout_seconds,
            start_offset=start_offset,
        )
        segment = clean_text[start_offset:]
        begin_index = segment.rfind(begin_marker)
        end_index = segment.find(end_marker, begin_index + len(begin_marker))
        if begin_index == -1 or end_index == -1 or end_index < begin_index:
            raise RuntimeError("wrapped serial command markers not found")
        payload = segment[begin_index + len(begin_marker) : end_index].lstrip("\r\n").rstrip()
        rc_match = re.search(rf"{re.escape(end_marker)} rc=(\d+)", segment[end_index:])
        if not rc_match:
            raise RuntimeError("wrapped serial command return code not found")
        return int(rc_match.group(1)), payload

    def ensure_sudo(self, timeout_seconds: int = 30) -> None:
        marker = "__CODEX_SUDO_OK__"
        command = (
            'stty -echo; sudo -k; sudo -S -p "" -v; rc=$?; '
            'stty echo; printf "\\n' + marker + '=%s\\n" "$rc"'
        )
        self.drain()
        start_offset = len(self.clean_text())
        self.write_line(command)
        time.sleep(0.3)
        self.write_line(self.login_password)
        self.wait_for(lambda text: f"{marker}=0" in text, timeout_seconds, start_offset=start_offset)

    def upload_base64_file(
        self,
        *,
        local_path: Path,
        remote_tmp_path: str,
        remote_dest_path: str,
        chunk_lines: int,
        timeout_seconds: int,
    ) -> str:
        local_bytes = Path(local_path).read_bytes()
        local_sha256 = hashlib.sha256(local_bytes).hexdigest()
        b64_lines = base64.encodebytes(local_bytes).decode("ascii").splitlines()
        remote_b64 = f"{remote_tmp_path}.b64"

        init_rc, init_output = self.run_wrapped_command(
            f"rm -f {sh_single_quote(remote_tmp_path)} {sh_single_quote(remote_b64)}; "
            f": > {sh_single_quote(remote_b64)}; "
            f"echo __UPLOAD_INIT__",
            timeout_seconds=timeout_seconds,
        )
        if init_rc != 0 or "__UPLOAD_INIT__" not in init_output:
            raise RuntimeError(f"upload init failed: {init_output}")

        total_chunks = (len(b64_lines) + chunk_lines - 1) // chunk_lines
        for index in range(total_chunks):
            chunk = b64_lines[index * chunk_lines : (index + 1) * chunk_lines]
            self.drain()
            start_offset = len(self.clean_text())
            self.write_lines(
                [
                    f"cat >> {remote_b64} <<'EOF'",
                    *chunk,
                    "EOF",
                ]
            )
            self.wait_for(
                lambda text: LINUX_PROMPT_RE.search(text) is not None,
                timeout_seconds,
                start_offset=start_offset,
            )
            print(f"upload_chunk={index + 1}/{total_chunks}")

        decode_rc, decode_output = self.run_wrapped_command(
            f"base64 -d {sh_single_quote(remote_b64)} > {sh_single_quote(remote_tmp_path)} && "
            f"chmod 0644 {sh_single_quote(remote_tmp_path)} && "
            f"sha256sum {sh_single_quote(remote_tmp_path)}",
            timeout_seconds=timeout_seconds,
        )
        if decode_rc != 0:
            raise RuntimeError(f"remote base64 decode failed: {decode_output}")
        if local_sha256 not in decode_output:
            raise RuntimeError(
                f"remote tmp sha256 mismatch: expected {local_sha256}, got {decode_output}"
            )

        if remote_tmp_path == remote_dest_path:
            install_output = decode_output
        else:
            self.ensure_sudo(timeout_seconds=timeout_seconds)
            install_rc, install_output = self.run_wrapped_command(
                f"sudo install -m 0644 {sh_single_quote(remote_tmp_path)} {sh_single_quote(remote_dest_path)} && "
                f"sync && sha256sum {sh_single_quote(remote_dest_path)}",
                timeout_seconds=timeout_seconds,
            )
            if install_rc != 0:
                raise RuntimeError(f"remote install failed: {install_output}")
        if local_sha256 not in install_output:
            raise RuntimeError(
                f"remote destination sha256 mismatch: expected {local_sha256}, got {install_output}"
            )
        return local_sha256


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload a local file to a Linux board over a serial console.")
    parser.add_argument("--port", default=os.environ.get("PMPFUZZ_BOARD_SERIAL_PORT", ""))
    parser.add_argument("--baud", type=int, default=int(os.environ.get("PMPFUZZ_BOARD_SERIAL_BAUD", "115200")))
    parser.add_argument("--login-user", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_USER", ""))
    parser.add_argument("--login-password", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_PASSWORD", ""))
    parser.add_argument("--chunk-lines", type=int, default=128)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--output-log", type=Path, default=None)
    parser.add_argument("--remote-tmp-path", required=True)
    parser.add_argument("--remote-dest-path", required=True)
    parser.add_argument("local_path", type=Path)
    args = parser.parse_args()

    session = SerialLinuxSession(
        port_name=args.port,
        baud=args.baud,
        login_user=args.login_user,
        login_password=args.login_password,
        output_log=args.output_log,
    )
    try:
        session.enter_shell(timeout_seconds=args.timeout_seconds)
        sha256 = session.upload_base64_file(
            local_path=args.local_path,
            remote_tmp_path=args.remote_tmp_path,
            remote_dest_path=args.remote_dest_path,
            chunk_lines=args.chunk_lines,
            timeout_seconds=args.timeout_seconds,
        )
        print(f"remote_dest={args.remote_dest_path}")
        print(f"sha256={sha256}")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
