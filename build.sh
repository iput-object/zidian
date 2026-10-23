#!/usr/bin/env bash
# Build the zidian binary.
#
#   ./build.sh          -> dist/zidian       native standalone ELF (no Python needed)
#   ./build.sh --pyz    -> dist/zidian.pyz   portable single file (needs python3)
#
# The native build bootstraps a private venv + PyInstaller under build/ the first
# time; it needs a C toolchain and network access for that one install. The .pyz
# needs only the stdlib and is always buildable offline.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
mkdir -p dist build

build_pyz() {
    echo ">> building dist/zidian.pyz (zipapp, stdlib-only)"
    "$PY" -m zipapp src --main "zidian.cli:main" \
        --python "/usr/bin/env python3" --output dist/zidian.pyz --compress
    chmod +x dist/zidian.pyz
    echo "   -> dist/zidian.pyz ($(du -h dist/zidian.pyz | cut -f1))"
    "$PY" dist/zidian.pyz --help >/dev/null && echo "   OK: dist/zidian.pyz runs"
}

build_native() {
    local venv="build/venv"
    if [ ! -x "$venv/bin/pyinstaller" ]; then
        echo ">> bootstrapping build venv + PyInstaller (one-time)"
        "$PY" -m venv "$venv"
        "$venv/bin/python" -m pip install --quiet --upgrade pip
        "$venv/bin/pip" install --quiet pyinstaller
    fi
    echo ">> building dist/zidian (PyInstaller native ELF)"
    "$venv/bin/pyinstaller" --onefile --name zidian --clean --noconfirm \
        --paths src --collect-submodules zidian \
        --distpath dist --workpath build/pyi --specpath build main.py \
        > build/pyinstaller.log 2>&1
    echo "   -> dist/zidian ($(du -h dist/zidian | cut -f1))"
    env -i dist/zidian --help >/dev/null && echo "   OK: dist/zidian runs standalone"
}

case "${1:-}" in
    --pyz) build_pyz ;;
    "")    build_native ;;
    *)     echo "usage: $0 [--pyz]"; exit 2 ;;
esac
