#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/runs/chain_closure_smoke_$(date +%Y%m%d_%H%M%S)}"

cd "$ROOT"

python3 -m unittest discover -s tests
python3 -m pmpfuzz env-check

run_one() {
  local dut="$1"
  local profile="$2"
  local count="$3"
  local out="$OUT/${dut}_${profile}"

  set +e
  python3 -m pmpfuzz run \
    --dut "$dut" \
    --profile "$profile" \
    --count "$count" \
    --no-smepmp \
    --per-case-timeout 60 \
    --out "$out"
  local rc=$?
  set -e

  python3 -m pmpfuzz triage --run-dir "$out"
  python3 -m pmpfuzz coverage --run-dir "$out"
  python3 -m pmpfuzz report --run-dir "$out"
  echo "chain-closure-run dut=$dut profile=$profile rc=$rc out=$out"
}

run_one spike pmp-side-effect 24

for dut in rocket-clean boom-clean; do
  run_one "$dut" pmp-side-effect 12
  run_one "$dut" tlb-stale-pte 12
  run_one "$dut" tlb-stale-pmp 12
  run_one "$dut" ptw-stale-pmp 8
done

echo "chain-closure-smoke-out=$OUT"
