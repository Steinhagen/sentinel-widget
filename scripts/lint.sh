#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

QMLINT="$(find_tool qmllint || true)"
if [ -z "$QMLINT" ]; then
    echo "qmllint was not found. Use 'nix develop' or put Qt's qmllint on PATH." >&2
    exit 1
fi

echo "== qmllint =="
while IFS= read -r file; do
    "$QMLINT" "$file"
done < <(find "$ROOT/contents" -name '*.qml' -type f | sort)

if command -v node >/dev/null 2>&1; then
    echo "== node --check =="
    while IFS= read -r file; do
        node --check "$file"
    done < <(find "$ROOT/contents" -name '*.mjs' -type f 2>/dev/null | sort)
fi

if command -v python3 >/dev/null 2>&1; then
    echo "== compile package tool =="
    python3 -m py_compile "$ROOT/tools/package.py"
    rm -rf "$ROOT/tools/__pycache__"
fi
