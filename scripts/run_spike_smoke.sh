#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SPIKE="${SPIKE:-$HOME/wjs/boom_host_deploy/opt-riscv/bin/spike}"

cd "$ROOT"
rm -rf out
python3 -m pmpfuzz.cli --count "${COUNT:-8}" --seed "${SEED:-3}" --no-smepmp --out out

passed=0
for asm in out/scenario_*.S; do
  elf="${asm%.S}.elf"
  sh scripts/compile_one.sh "$asm" "$elf"
  timeout "${TIMEOUT:-5}" "$SPIKE" --isa=rv64gc "$elf"
  passed=$((passed + 1))
done

echo "spike-smoke-pass: $passed scenarios"
