#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-runs/xiangshan_targeted_$(date +%Y%m%d_%H%M%S)}"
PROFILES="xiangshan-fetch-pmp-boundary,xiangshan-itlb-stale-pmp,xiangshan-ptw-pmp-depth,xiangshan-side-effect"
TOTAL_BUDGET="${TOTAL_BUDGET:-2h}"
SPIKE_COUNT="${SPIKE_COUNT:-24}"
ROCKET_COUNT="${ROCKET_COUNT:-24}"
XIANGSHAN_COUNT="${XIANGSHAN_COUNT:-48}"
SEED="${SEED:-20260630}"

mkdir -p "$OUT"

echo "[preflight] disk"
df -h "$ROOT" || true
echo "[preflight] memory"
free -h || true

echo "[preflight] env-check"
python3 -m pmpfuzz env-check || true

echo "[preflight] probe-dut"
python3 -m pmpfuzz probe-dut \
  --dut spike,rocket-clean,xiangshan-clean \
  --out "$OUT/probe" || true

run_one() {
  local dut="$1"
  local count="$2"
  local timeout_s="$3"
  local simlen="$4"
  local budget="$5"
  local run_dir="$OUT/$dut"

  mkdir -p "$run_dir"
  echo "[run] $dut count=$count budget=$budget"
  set +e
  python3 -m pmpfuzz run \
    --dut "$dut" \
    --profiles "$PROFILES" \
    --count "$count" \
    --jobs 1 \
    --no-smepmp \
    --per-case-timeout "$timeout_s" \
    --simlen "$simlen" \
    --time-budget "$budget" \
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

run_all() {
  set -e
  run_one spike "$SPIKE_COUNT" 45 120000 "10m"
  run_one rocket-clean "$ROCKET_COUNT" 220 160000 "25m"
  run_one xiangshan-clean "$XIANGSHAN_COUNT" 260 360000 "90m"
}

export ROOT OUT PROFILES SPIKE_COUNT ROCKET_COUNT XIANGSHAN_COUNT SEED
export -f run_one run_all

echo "[budget] total=$TOTAL_BUDGET"
set +e
timeout "$TOTAL_BUDGET" bash -c 'run_all'
rc=$?
set -e
if [ "$rc" -eq 124 ]; then
  echo "[timeout] XiangShan targeted campaign exceeded $TOTAL_BUDGET"
fi

echo "[complete] XiangShan targeted campaign at $OUT rc=$rc"
exit "$rc"
