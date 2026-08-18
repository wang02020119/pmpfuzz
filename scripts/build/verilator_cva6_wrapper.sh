#!/usr/bin/env bash
set -euo pipefail

VERILATOR_BIN="${VERILATOR_BIN:-verilator}"
mdir=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-Mdir" ]]; then
    mdir="$arg"
    break
  fi
  previous="$arg"
done

"$VERILATOR_BIN" \
  --cc \
  --exe \
  --timing \
  -Wno-BLKANDNBLK \
  "$@"

if [[ -n "$mdir" && -f "$mdir/VTestHarness__pch.h" ]]; then
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.fast"
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.slow"
fi
