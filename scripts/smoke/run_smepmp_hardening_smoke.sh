#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

OUT="${OUT:-runs/smepmp_hardening_smoke}"
PROFILES="smepmp-mmwp-mmode-default-deny,smepmp-mml-shared-code,smepmp-mml-shared-data,smepmp-locked-entry,smepmp-rlb-setup"
JOBS="${JOBS:-1}"
TIME_BUDGET="${TIME_BUDGET:-20m}"
PER_CASE_TIMEOUT="${PER_CASE_TIMEOUT:-60}"

mkdir -p "${OUT}"

python3 -m unittest discover -s tests

python3 -m pmpfuzz probe-dut \
  --dut spike,rocket-clean,boom-clean,xiangshan-clean \
  --probe-smepmp \
  --out "${OUT}/probe"

run_one() {
  local dut="$1"
  local count="$2"
  local run_dir="${OUT}/${dut}"

  python3 -m pmpfuzz run \
    --dut "${dut}" \
    --profiles "${PROFILES}" \
    --count "${count}" \
    --jobs "${JOBS}" \
    --time-budget "${TIME_BUDGET}" \
    --per-case-timeout "${PER_CASE_TIMEOUT}" \
    --out "${run_dir}" || true

  python3 -m pmpfuzz triage --run-dir "${run_dir}" || true
  python3 -m pmpfuzz coverage --run-dir "${run_dir}" || true
  python3 -m pmpfuzz report --run-dir "${run_dir}" || true
}

run_one spike 64
run_one rocket-clean 32
run_one boom-clean 32
run_one xiangshan-clean 24
