#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "python3 was not found." >&2
    echo "On NixOS run: nix shell nixpkgs#python3 -c './package.sh'" >&2
    exit 1
fi

exec "$PYTHON_BIN" tools/package.py
