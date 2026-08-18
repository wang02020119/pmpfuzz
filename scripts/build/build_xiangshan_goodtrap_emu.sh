#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PMPFUZZ_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKSPACE_DIR="${PMPFUZZ_WORKSPACE:-$HOME/pmpfuzz-workspace}"
XIANGSHAN_DIR="${XIANGSHAN_DIR:-$WORKSPACE_DIR/xiangshan}"
DEFAULT_XIANGSHAN_VANILLA_ROOT="$WORKSPACE_DIR/xiangshan"
JAVA_HOME="${JAVA_HOME:-$HOME/.sdkman/candidates/java/current}"
MILL_DIR="${MILL_DIR:-$WORKSPACE_DIR/bin}"
EDA_BIN="${EDA_BIN:-$WORKSPACE_DIR/toolchains/eda/bin}"
LOG_DIR="${LOG_DIR:-$WORKSPACE_DIR/runs/xiangshan_build}"
MAKE_THREADS="${MAKE_THREADS:-1}"
CHISEL_THREADS="${CHISEL_THREADS:-1}"
OPT_FAST="${OPT_FAST:--O0}"

export JAVA_HOME
export NOOP_HOME="$XIANGSHAN_DIR"
export PATH="$JAVA_HOME/bin:$MILL_DIR:$EDA_BIN:$PATH"

mkdir -p "$LOG_DIR"
cd "$XIANGSHAN_DIR"

echo "[preflight] XiangShan tree: $XIANGSHAN_DIR"
echo "[preflight] NOOP_HOME: $NOOP_HOME"
test -d "$XIANGSHAN_DIR/.git"
test -x "$MILL_DIR/mill"
test -x "$EDA_BIN/verilator"
test -x /usr/bin/g++

echo "[submodules] syncing vanilla XiangShan submodules"
git submodule sync --recursive
git submodule update --init --recursive --jobs 8

echo "[rtl] generating difftest-enabled MinimalConfig Verilator C++"
/usr/bin/python3 scripts/xiangshan.py \
  --build \
  --config MinimalConfig \
  --make-threads "$MAKE_THREADS" \
  --threads "$CHISEL_THREADS" \
  --disable-fork \
  > "$LOG_DIR/build.log" 2>&1 || {
    if grep -q "the argument '--data' cannot be used multiple times" "$LOG_DIR/build.log"; then
      echo "[rtl] XiangShan wrapper hit host time/arg parser issue after C++ generation; continuing with direct final compile"
    elif grep -q "\[c++\] Compiling C++ files" "$LOG_DIR/build.log"; then
      echo "[rtl] XiangShan wrapper reached final C++ phase; continuing with direct final compile"
    else
      tail -80 "$LOG_DIR/build.log"
      exit 1
    fi
  }

if [ ! -f "$XIANGSHAN_DIR/build/verilator-compile/VSimTop.mk" ]; then
  echo "[error] expected generated VSimTop.mk under $XIANGSHAN_DIR/build/verilator-compile"
  exit 1
fi

if [ "$XIANGSHAN_DIR" != "$DEFAULT_XIANGSHAN_VANILLA_ROOT" ]; then
  if grep -R -n -F "$DEFAULT_XIANGSHAN_VANILLA_ROOT" \
    "$XIANGSHAN_DIR/build/verilator-compile" \
    "$XIANGSHAN_DIR/build/generated-src" \
    > "$LOG_DIR/isolation_path_leak.log"; then
    echo "[error] isolated XiangShan build still references shared vanilla root"
    echo "[error] see $LOG_DIR/isolation_path_leak.log"
    exit 1
  fi
fi

echo "[patch] enabling PMFUZZ_DIAG tohost dump in generated XiangShan emu"
PYTHONPATH="$PMPFUZZ_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
  /usr/bin/python3 -m pmpfuzz.xiangshan_emu_diag --xiangshan-dir "$XIANGSHAN_DIR"

echo "[compile] building emu with system g++ to avoid EDA conda sysroot header gaps"
find "$XIANGSHAN_DIR/build/verilator-compile" -maxdepth 1 -type f \
  \( -name '*.o' -o -name '*.a' -o -name '*.d' -o -name '*.gch' -o -name 'emu' \) \
  -delete

make -C "$XIANGSHAN_DIR/build/verilator-compile" \
  -f VSimTop.mk \
  VM_PARALLEL_BUILDS=1 \
  OPT_SLOW="-O0" \
  OPT_FAST="$OPT_FAST" \
  CXX=/usr/bin/g++ \
  LINK=/usr/bin/g++ \
  -j"$MAKE_THREADS" \
  > "$LOG_DIR/direct_inner_make_gpp.log" 2>&1

if grep -q "CONFIG_NO_DIFFTEST" "$XIANGSHAN_DIR/build/verilator-compile/VSimTop.mk"; then
  echo "[error] built emu has CONFIG_NO_DIFFTEST; xstrap good-trap will not be observable"
  exit 1
fi

test -x "$XIANGSHAN_DIR/build/verilator-compile/emu"
echo "[done] XiangShan good-trap emu: $XIANGSHAN_DIR/build/verilator-compile/emu"
