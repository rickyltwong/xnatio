#!/usr/bin/env bash
set -euo pipefail

# xnatio build script
# - Default: docker build with Ubuntu 20.04 builder producing a onefile binary
# - Local: optional local PyInstaller build if environment is ready

BUILD_MODE="docker"

usage() {
  cat <<EOF
xnatio build script

Usage: $0 [--docker] [--local] [--help]

Options:
  --docker   Use Docker Ubuntu 20.04 builder (default)
  --local    Build locally using PyInstaller
  --help     Show this help

Outputs the binary to ./dist/xnatio
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) BUILD_MODE="docker"; shift;;
    --local)  BUILD_MODE="local"; shift;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

mkdir -p dist

if [[ "$BUILD_MODE" == "local" ]]; then
  echo "[local] Building with local PyInstaller"
  if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "pyinstaller not found; installing"
    python3 -m pip install --user pyinstaller || pip install --user pyinstaller
  fi
  # Prevent pathlib backport issues
  python3 -m pip uninstall -y pathlib || true
  # Generate entry if missing
  if [[ ! -f pyinstaller_entry.py ]]; then
    printf '#!/usr/bin/env python3\nfrom xnatio.cli import run_cli\nif __name__ == "__main__":\n    raise SystemExit(run_cli())\n' > pyinstaller_entry.py
  fi
  pyinstaller --clean -y -n xnatio --onefile --distpath dist pyinstaller_entry.py
  echo "Binary: dist/xnatio"
  exit 0
fi

# Docker builder path
echo "[docker] Building Ubuntu 20.04 builder image"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not available" >&2
  exit 1
fi

docker build -f Dockerfile.ubuntu20.builder -t xnatio:ubuntu20-builder .

echo "[docker] Running PyInstaller in builder"
docker run --rm \
  -e HOME=/tmp \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd)/dist:/dist" \
  xnatio:ubuntu20-builder \
  bash -lc "cd /app && pyinstaller --clean -y -n xnatio --onefile --distpath /dist --workpath /tmp/build --specpath /tmp/spec pyinstaller_entry.py && ls -la /dist && file /dist/xnatio || true"

echo "Binary: dist/xnatio" 