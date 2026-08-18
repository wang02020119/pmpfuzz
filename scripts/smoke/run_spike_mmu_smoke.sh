#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SPIKE="${SPIKE:-spike}"
OUT="${OUT:-out_mmu_smoke}"

cd "$ROOT"
rm -rf "$OUT"
python3 -m pmpfuzz.runner \
  --profile "${PROFILE:-mixed-smepmp-mmu}" \
  --count "${COUNT:-24}" \
  --seed "${SEED:-20260628}" \
  --jobs "${JOBS:-1}" \
  --time-budget "${TIME_BUDGET:-10m}" \
  --per-case-timeout "${TIMEOUT:-10}" \
  --spike "$SPIKE" \
  --out "$OUT"
