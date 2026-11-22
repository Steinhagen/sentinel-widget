#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 was not found." >&2
    echo "On NixOS run: nix shell nixpkgs#python3 -c './package.sh'" >&2
    exit 1
fi

exec python3 tools/package.py
