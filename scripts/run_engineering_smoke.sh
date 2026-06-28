#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/runs/engineering_smoke_$(date +%Y%m%d_%H%M%S)}"

cd "$ROOT"

python3 -m unittest discover -s tests
python3 -m pmpfuzz env-check

python3 -m pmpfuzz run \
  --dut spike \
  --profile legacy-data \
  --count 30 \
  --no-smepmp \
  --out "$OUT/spike_legacy_data"

python3 -m pmpfuzz run \
  --dut spike \
  --profile pmp-boundary \
  --count 30 \
  --no-smepmp \
  --out "$OUT/spike_pmp_boundary"

python3 -m pmpfuzz run \
  --dut rocket-clean \
  --profile sv39-final-pmp \
  --count 30 \
  --no-smepmp \
  --per-case-timeout 60 \
  --out "$OUT/rocket_sv39_final"

python3 -m pmpfuzz run \
  --dut rocket-clean \
  --profile sv39-perm-matrix \
  --count 18 \
  --no-smepmp \
  --per-case-timeout 60 \
  --out "$OUT/rocket_sv39_perm_matrix"

python3 -m pmpfuzz run \
  --dut boom-clean \
  --profile boom-ptw-pmp-regression \
  --count 6 \
  --indices 0,1,2,3 \
  --no-smepmp \
  --per-case-timeout 60 \
  --out "$OUT/boom_ptw_regression" || true

python3 -m pmpfuzz triage --run-dir "$OUT/boom_ptw_regression"
python3 -m pmpfuzz coverage --run-dir "$OUT/boom_ptw_regression"
python3 -m pmpfuzz report --run-dir "$OUT/boom_ptw_regression"

python3 -m pmpfuzz repro \
  --case "$OUT/boom_ptw_regression/cases/scenario_0000" \
  --dut spike,rocket-clean,boom-clean \
  --no-smepmp \
  --per-case-timeout 60 \
  --out "$OUT/boom_ptw_repro" || true

python3 -m pmpfuzz triage --run-dir "$OUT/boom_ptw_repro"
python3 -m pmpfuzz coverage --run-dir "$OUT/boom_ptw_repro"
python3 -m pmpfuzz report --run-dir "$OUT/boom_ptw_repro"

echo "engineering-smoke-out=$OUT"
