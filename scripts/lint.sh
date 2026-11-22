#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

QMLINT="$(find_tool qmllint || true)"
if [ -z "$QMLINT" ]; then
    echo "qmllint was not found. Use 'nix develop' or put Qt's qmllint on PATH." >&2
    exit 1
fi

setup_qml_environment "$QMLINT"

import_args=()
if [ -n "${QML2_IMPORT_PATH:-}" ]; then
    IFS=':' read -r -a import_dirs <<< "$QML2_IMPORT_PATH"
    for dir in "${import_dirs[@]}"; do
        if [ -d "$dir" ]; then
            import_args+=("-I" "$dir")
        fi
    done
fi

echo "== qmllint =="
while IFS= read -r file; do
    "$QMLINT" "${import_args[@]}" "$file"
done < <(find "$ROOT/contents" -name '*.qml' -type f | sort)

if command -v node >/dev/null 2>&1; then
    echo "== node --check =="
    while IFS= read -r file; do
        node --check "$file"
    done < <(find "$ROOT/contents" -name '*.mjs' -type f 2>/dev/null | sort)
    while IFS= read -r file; do
        node --check "$file"
    done < <(find "$ROOT/tools" -name '*.mjs' -type f 2>/dev/null | sort)
fi

if command -v python3 >/dev/null 2>&1; then
    echo "== compile package tool =="
    python3 -m py_compile "$ROOT/tools/package.py"
    rm -rf "$ROOT/tools/__pycache__"
fi
