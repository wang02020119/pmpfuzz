#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHIPYARD_DIR="${CHIPYARD_DIR:-/home/dubhe/wjs/boom_host_deploy/cascade-chipyard}"
RISCV="${RISCV:-/home/dubhe/wjs/boom_host_deploy/opt-riscv}"
JAVA_HOME="${JAVA_HOME:-/home/dubhe/.sdkman/candidates/java/11.0.30-tem}"
DEFAULT_VERILATOR_BIN_DIR="${DEFAULT_VERILATOR_BIN_DIR:-/home/dubhe/wjs/toolchains/eda/bin}"
ROCKET_VERILATOR="${ROCKET_VERILATOR:-$ROOT_DIR/scripts/verilator_rocket_wrapper.sh}"
CVA6_VERILATOR_BIN_DIR="${CVA6_VERILATOR_BIN_DIR:-/home/dubhe/wjs/cascade_cpu_fuzzing/mount/cascade_xiangshan_adapt/tools/verilator-5.032/bin}"
ROCKET_VERILATOR_BIN="${ROCKET_VERILATOR_BIN:-$CVA6_VERILATOR_BIN_DIR/verilator}"
CVA6_VERILATOR="${CVA6_VERILATOR:-$ROOT_DIR/scripts/verilator_cva6_wrapper.sh}"
JOBS="${JOBS:-4}"
TARGET="${1:-all}"

export RISCV
export JAVA_HOME

build_rocket() {
  export VERILATOR_BIN="$ROCKET_VERILATOR_BIN"
  export PATH="$JAVA_HOME/bin:$RISCV/bin:$CVA6_VERILATOR_BIN_DIR:$PATH"
  cd "$CHIPYARD_DIR/sims/verilator"
  local sim="$CHIPYARD_DIR/sims/verilator/simulator-chipyard-RocketConfig"
  local mdir="$CHIPYARD_DIR/sims/verilator/generated-src/chipyard.TestHarness.RocketConfig/chipyard.TestHarness.RocketConfig"
  if [[ ! -x "$sim" ]]; then
    rm -rf "$mdir"
  fi
  make CONFIG=RocketConfig VERILATOR="$ROCKET_VERILATOR" PLATFORM_OPTS=--timing EXTRA_SIM_CXXFLAGS=-std=c++17 -j"$JOBS"
}

ensure_cva6_pch_aliases() {
  local mdir="$CHIPYARD_DIR/sims/verilator/generated-src/chipyard.TestHarness.CVA6Config/chipyard.TestHarness.CVA6Config"
  if [[ -f "$mdir/VTestHarness__pch.h" ]]; then
    ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.fast"
    ln -sf VTestHarness__pch.h "$mdir/VTestHarness__pch.h.slow"
  fi
}

build_cva6() {
  export PATH="$JAVA_HOME/bin:$RISCV/bin:$CVA6_VERILATOR_BIN_DIR:$PATH"
  cd "$CHIPYARD_DIR/sims/verilator"
  local sim="$CHIPYARD_DIR/sims/verilator/simulator-chipyard-CVA6Config"
  local mdir="$CHIPYARD_DIR/sims/verilator/generated-src/chipyard.TestHarness.CVA6Config/chipyard.TestHarness.CVA6Config"
  if [[ ! -x "$sim" ]]; then
    rm -rf "$mdir"
  fi
  ensure_cva6_pch_aliases
  make CONFIG=CVA6Config VERILATOR="$CVA6_VERILATOR" EXTRA_SIM_CXXFLAGS=-std=c++17 -j"$JOBS"
}

case "$TARGET" in
  rocket)
    build_rocket
    ;;
  cva6)
    build_cva6
    ;;
  all)
    build_rocket
    build_cva6
    ;;
  *)
    echo "usage: $0 [rocket|cva6|all]" >&2
    exit 2
    ;;
esac
