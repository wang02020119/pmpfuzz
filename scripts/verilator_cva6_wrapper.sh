#!/usr/bin/env bash
set -euo pipefail

mdir=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-Mdir" ]]; then
    mdir="$arg"
    break
  fi
  previous="$arg"
done

/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/tools/verilator-5.032/bin/verilator \
  --cc \
  --exe \
  --timing \
  -Wno-BLKANDNBLK \
  "$@"

if [[ -n "$mdir" && -f "$mdir/VTestHarness__pch.h" ]]; then
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.fast"
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.slow"
fi
