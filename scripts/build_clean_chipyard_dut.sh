#!/usr/bin/env bash
set -euo pipefail

CHIPYARD_DIR="${CHIPYARD_DIR:-/home/dubhe/wjs/pmp-duts/chipyard-1.14.0}"
CONFIG="${CONFIG:-RocketConfig}"
JOBS="${JOBS:-1}"
TIMEOUT="${TIMEOUT:-6h}"
RISCV="${RISCV:-/home/dubhe/wjs/boom_host_deploy/opt-riscv}"
JAVA_HOME="${JAVA_HOME:-/home/dubhe/.sdkman/candidates/java/11.0.30-tem}"
VERILATOR_BIN_DIR="${VERILATOR_BIN_DIR:-}"
ULIMIT_V_KB="${ULIMIT_V_KB:-94371840}"
DRY_RUN="${DRY_RUN:-0}"
TARGET="${TARGET:-}"

if [ ! -d "$CHIPYARD_DIR/sims/verilator" ]; then
  echo "missing Chipyard verilator directory: $CHIPYARD_DIR/sims/verilator" >&2
  exit 2
fi

if [ ! -d "$CHIPYARD_DIR/.conda-env" ]; then
  echo "missing Chipyard conda environment; run scripts/setup_clean_chipyard_env.sh first" >&2
  exit 2
fi

export RISCV
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$RISCV/bin:$CHIPYARD_DIR/tools/circt/bin:$CHIPYARD_DIR/.conda-env/bin${VERILATOR_BIN_DIR:+:$VERILATOR_BIN_DIR}:$PATH"

cd "$CHIPYARD_DIR/sims/verilator"

make_args=(
  "CONFIG=$CONFIG"
  "VERILATOR_THREADS=1"
)

if [ -n "$TARGET" ]; then
  make_args+=("$TARGET")
fi

if [ "$DRY_RUN" = "1" ]; then
  exec make -n "${make_args[@]}"
fi

if [ -n "$ULIMIT_V_KB" ]; then
  ulimit -Sv "$ULIMIT_V_KB"
fi

exec timeout --kill-after=60s "$TIMEOUT" nice -n 10 ionice -c2 -n7 make -j"$JOBS" "${make_args[@]}"
