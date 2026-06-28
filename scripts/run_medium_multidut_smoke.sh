#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-runs/medium_multidut_$(date +%Y%m%d_%H%M%S)}"
SEED_RUN="$OUT/seed"
mkdir -p "$OUT"

echo "[preflight] disk"
df -h "$ROOT" || true
echo "[preflight] memory"
free -h || true

echo "[preflight] env-check"
python3 -m pmpfuzz env-check

echo "[preflight] probe-dut"
python3 -m pmpfuzz probe-dut \
  --dut spike,rocket-clean,boom-clean,cva6-clean,xiangshan-clean \
  --out "$OUT/probe_multidut" || true

echo "[seed] generate semantic seed run"
python3 -m pmpfuzz gen \
  --profiles pmp-boundary,sv39-perm-matrix,pmp-side-effect \
  --count 4 \
  --no-smepmp \
  --out "$SEED_RUN"

run_one_dut() {
  local dut="$1"
  local cases="$2"
  local timeout="$3"
  local simlen="$4"
  local run_dir="$OUT/$dut"
  local schedule_dir="$run_dir/schedule"

  mkdir -p "$run_dir"
  echo "[schedule] $dut cases=$cases"
  python3 -m pmpfuzz schedule \
    --from-runs "$SEED_RUN" \
    --target core-stateful \
    --coverage-mode pairwise \
    --max-cases "$cases" \
    --seed 20260628 \
    --out "$schedule_dir"

  echo "[run] $dut"
  set +e
  python3 -m pmpfuzz run \
    --dut "$dut" \
    --schedule "$schedule_dir/schedule.json" \
    --count "$cases" \
    --jobs 1 \
    --no-smepmp \
    --per-case-timeout "$timeout" \
    --simlen "$simlen" \
    --time-budget 90m \
    --out "$run_dir"
  local rc=$?
  set -e

  echo "[post] $dut triage/coverage/report"
  python3 -m pmpfuzz triage --run-dir "$run_dir" || true
  python3 -m pmpfuzz coverage --run-dir "$run_dir" || true
  python3 -m pmpfuzz report --run-dir "$run_dir" || true
  echo "[done] $dut rc=$rc"
  return 0
}

set -e
run_one_dut spike 256 30 100000
run_one_dut rocket-clean 128 220 100000
run_one_dut boom-clean 128 260 100000
run_one_dut cva6-clean 96 260 100000
run_one_dut xiangshan-clean 64 160 200000

echo "[complete] medium multi-DUT run at $OUT"
