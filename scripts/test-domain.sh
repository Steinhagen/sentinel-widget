#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

if ! command -v node >/dev/null 2>&1; then
    echo "node was not found. Use 'nix develop' or install Node 18+." >&2
    exit 1
fi

mapfile -t tests < <(node_test_files "$ROOT")
if [ "${#tests[@]}" -eq 0 ]; then
    echo "No domain tests yet."
    exit 0
fi

echo "== node --test =="
node --test "${tests[@]}"
