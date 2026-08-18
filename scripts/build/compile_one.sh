#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 INPUT.S OUTPUT.elf" >&2
  exit 2
fi

GCC="${RISCV_GCC:-/usr/local/bin/riscv64-unknown-elf-gcc}"

"$GCC" \
  -mno-relax \
  -nostdlib \
  -nostartfiles \
  -Wl,-N \
  -Wl,--no-relax \
  -Ttext=0x80000000 \
  -o "$2" \
  "$1"
