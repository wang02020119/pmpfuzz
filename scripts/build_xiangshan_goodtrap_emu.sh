#!/usr/bin/env bash
set -euo pipefail

XIANGSHAN_DIR="${XIANGSHAN_DIR:-/home/dubhe/wjs/xiangshan_vanilla}"
JAVA_HOME="${JAVA_HOME:-/home/dubhe/.sdkman/candidates/java/11.0.30-tem}"
MILL_DIR="${MILL_DIR:-/home/dubhe/wjs/bin}"
EDA_BIN="${EDA_BIN:-/home/dubhe/wjs/toolchains/eda/bin}"
LOG_DIR="${LOG_DIR:-/home/dubhe/wjs/pmp-fuzz-stage1/runs/xiangshan_vanilla_build}"
MAKE_THREADS="${MAKE_THREADS:-1}"
CHISEL_THREADS="${CHISEL_THREADS:-1}"
OPT_FAST="${OPT_FAST:--O2}"

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$MILL_DIR:$EDA_BIN:$PATH"

mkdir -p "$LOG_DIR"
cd "$XIANGSHAN_DIR"

echo "[preflight] XiangShan tree: $XIANGSHAN_DIR"
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
