import argparse
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


def serial_write_line(port: serial.Serial, line: str) -> None:
    port.write((line + "\r").encode("utf-8"))
    port.flush()


def wait_for_command_output(
    *,
    port_name: str,
    baud: int,
    login_user: str,
    login_password: str,
    command: str,
    timeout_seconds: int,
    output_log: Path | None,
) -> int:
    marker = f"CODEX_SERIAL_{int(time.time())}_{os.getpid()}"
    begin_marker = f"__BEGIN__{marker}__"
    end_marker = f"__END__{marker}__"
    wrapped_command = (
        f"printf '{begin_marker}\\n'; "
        f"{command}; "
        f"rc=$?; "
        f"printf '\\n{end_marker} rc=%s\\n' \"$rc\""
    )

    serial_port = serial.Serial(port_name, baudrate=baud, timeout=0.1, write_timeout=1.0)
    serial_port.dtr = True
    serial_port.rts = True
    raw_chunks: list[str] = []
    sent_user = False
    sent_password = False
    sent_command = False
    command_start_offset = 0
    deadline = time.monotonic() + timeout_seconds
    serial_port.write(b"\r")
    serial_port.flush()

    try:
        while time.monotonic() < deadline:
            chunk = serial_port.read(serial_port.in_waiting or 1).decode("utf-8", errors="replace")
            if chunk:
                raw_chunks.append(chunk)
            raw_text = "".join(raw_chunks)
            clean_text = strip_ansi(raw_text)

            if UBOOT_PROMPT_RE.search(clean_text):
                sys.stderr.write("serial console is at U-Boot prompt, not Linux shell\n")
                return 2

            if not sent_user and LOGIN_PROMPT_RE.search(clean_text):
                serial_write_line(serial_port, login_user)
                sent_user = True
                time.sleep(0.5)
                continue

            if sent_user and not sent_password and PASSWORD_PROMPT_RE.search(clean_text):
                serial_write_line(serial_port, login_password)
                sent_password = True
                time.sleep(1.0)
                continue

            if LINUX_PROMPT_RE.search(clean_text):
                if not sent_command:
                    command_start_offset = len(clean_text)
                    serial_write_line(serial_port, wrapped_command)
                    sent_command = True
                    time.sleep(0.3)
                    continue
                segment = clean_text[command_start_offset:]
                begin_index = segment.rfind(begin_marker)
                if begin_index != -1 and segment.find(f"{end_marker} rc=", begin_index + len(begin_marker)) != -1:
                    break

            time.sleep(0.1)

        raw_text = "".join(raw_chunks)
        clean_text = strip_ansi(raw_text)
        if output_log is not None:
            output_log.parent.mkdir(parents=True, exist_ok=True)
            output_log.write_text(raw_text, encoding="utf-8", errors="replace")

        segment = clean_text[command_start_offset:]
        begin_index = segment.rfind(begin_marker)
        end_index = segment.find(end_marker, begin_index + len(begin_marker))
        if begin_index == -1 or end_index == -1 or end_index < begin_index:
            sys.stderr.write(clean_text[-4000:])
            sys.stderr.write("\nserial command did not complete before timeout\n")
            return 3

        payload = segment[begin_index + len(begin_marker) : end_index]
        payload = payload.lstrip("\r\n").rstrip()
        if payload:
            sys.stdout.write(payload + "\n")

        rc_match = re.search(rf"{re.escape(end_marker)} rc=(\d+)", segment[end_index:])
        if not rc_match:
            sys.stderr.write("missing command return code marker\n")
            return 4
        return int(rc_match.group(1))
    finally:
        serial_port.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute one Linux shell command over a serial console.")
    parser.add_argument("--port", default=os.environ.get("PMPFUZZ_BOARD_SERIAL_PORT", ""))
    parser.add_argument("--baud", type=int, default=int(os.environ.get("PMPFUZZ_BOARD_SERIAL_BAUD", "115200")))
    parser.add_argument("--login-user", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_USER", ""))
    parser.add_argument("--login-password", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_PASSWORD", ""))
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--output-log", type=Path, default=None)
    parser.add_argument("command")
    args = parser.parse_args()
    return wait_for_command_output(
        port_name=args.port,
        baud=args.baud,
        login_user=args.login_user,
        login_password=args.login_password,
        command=args.command,
        timeout_seconds=args.timeout_seconds,
        output_log=args.output_log,
    )


if __name__ == "__main__":
    raise SystemExit(main())
