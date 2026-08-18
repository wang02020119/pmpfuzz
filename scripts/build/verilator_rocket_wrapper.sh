#!/usr/bin/env bash
set -euo pipefail

VERILATOR_BIN="${VERILATOR_BIN:-verilator}"

has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

mdir=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-Mdir" ]]; then
    mdir="$arg"
    break
  fi
  previous="$arg"
done

extra=()
has_arg "--cc" "$@" || extra+=("--cc")
has_arg "--exe" "$@" || extra+=("--exe")
if ! has_arg "--timing" "$@" && ! has_arg "--no-timing" "$@"; then
  extra+=("--timing")
fi

"$VERILATOR_BIN" "${extra[@]}" "$@"

if [[ -n "$mdir" && -f "$mdir/VTestHarness__pch.h" ]]; then
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.fast"
  ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.slow"
fi
