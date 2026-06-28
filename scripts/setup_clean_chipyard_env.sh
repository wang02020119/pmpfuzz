#!/usr/bin/env bash
set -euo pipefail

CHIPYARD_DIR="${CHIPYARD_DIR:-/home/dubhe/wjs/pmp-duts/chipyard-1.14.0}"
MINIFORGE_DIR="${MINIFORGE_DIR:-/home/dubhe/wjs/pmp-duts/miniforge3}"
INSTALLER="${INSTALLER:-/home/dubhe/wjs/pmp-duts/Miniforge3-Linux-x86_64.sh}"
LOCKFILE="${LOCKFILE:-$CHIPYARD_DIR/conda-reqs/conda-lock-reqs/conda-requirements-riscv-tools-linux-64-lean.conda-lock.yml}"
CIRCT_DIR="${CIRCT_DIR:-$CHIPYARD_DIR/tools/circt}"
GITHUB_TOKEN="${GITHUB_TOKEN:-null}"

if [ ! -d "$CHIPYARD_DIR/.git" ]; then
  echo "missing Chipyard checkout: $CHIPYARD_DIR" >&2
  exit 2
fi

CONDA_ENV_READY=0
if [ -d "$CHIPYARD_DIR/.conda-env" ]; then
  echo "Chipyard conda environment already exists: $CHIPYARD_DIR/.conda-env"
  CONDA_ENV_READY=1
fi

if [ "$CONDA_ENV_READY" = "0" ] && ! command -v conda >/dev/null 2>&1; then
  if [ ! -x "$MINIFORGE_DIR/bin/conda" ]; then
    mkdir -p "$(dirname "$INSTALLER")"
    if [ ! -s "$INSTALLER" ]; then
      url="https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh"
      if command -v curl >/dev/null 2>&1; then
        curl -L --fail --retry 3 -o "$INSTALLER" "$url"
      elif command -v wget >/dev/null 2>&1; then
        wget -O "$INSTALLER" "$url"
      else
        echo "neither curl nor wget is available for downloading Miniforge" >&2
        exit 2
      fi
    fi
    bash "$INSTALLER" -b -p "$MINIFORGE_DIR"
  fi
  export PATH="$MINIFORGE_DIR/bin:$PATH"
fi

cd "$CHIPYARD_DIR"

if [ "$CONDA_ENV_READY" = "0" ]; then
  if [ ! -f "$LOCKFILE" ]; then
    echo "missing Chipyard lean conda lockfile: $LOCKFILE" >&2
    exit 2
  fi

  if [ ! -x "$CHIPYARD_DIR/.conda-lock-env/bin/conda-lock" ]; then
    rm -rf "$CHIPYARD_DIR/.conda-lock-env"
    conda create -y -p "$CHIPYARD_DIR/.conda-lock-env" -c conda-forge conda-lock=2.5.7
  fi

  "$CHIPYARD_DIR/.conda-lock-env/bin/conda-lock" install \
    --conda "$(command -v conda)" \
    -p "$CHIPYARD_DIR/.conda-env" \
    "$LOCKFILE"
fi

export PATH="$CHIPYARD_DIR/.conda-env/bin:$PATH"
if [ ! -x "$CIRCT_DIR/bin/firtool" ]; then
  git submodule update --init "$CHIPYARD_DIR/tools/install-circt"
  "$CHIPYARD_DIR/tools/install-circt/bin/download-release-or-nightly-circt.sh" \
    -f circt-full-static-linux-x64.tar.gz \
    -i "$CIRCT_DIR" \
    -v version-file \
    -x "$CHIPYARD_DIR/conda-reqs/circt.json" \
    -g "$GITHUB_TOKEN"
fi

echo "Chipyard lean conda environment is ready: $CHIPYARD_DIR/.conda-env"
