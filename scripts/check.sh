#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

"$ROOT/scripts/lint.sh"
"$ROOT/scripts/test-domain.sh"
"$ROOT/scripts/test-qml.sh"

echo "== package =="
PYTHON="${PYTHON:-python3}" "$ROOT/package.sh"

if command -v jq >/dev/null 2>&1; then
    version="$(jq -r '.KPlugin.Version' "$ROOT/metadata.json")"
    archive="$ROOT/dist/sentinel-$version.plasmoid"
else
    archive="$(find "$ROOT/dist" -maxdepth 1 -name '*.plasmoid' -type f -printf '%T@ %p\n' \
        | sort -n | tail -n 1 | cut -d' ' -f2-)"
fi

if [ -z "$archive" ] || [ ! -f "$archive" ]; then
    echo "package.sh did not produce the expected .plasmoid archive" >&2
    exit 1
fi

"${PYTHON:-python3}" - "$archive" <<'PY'
import sys, zipfile
path = sys.argv[1]
with zipfile.ZipFile(path) as archive:
    names = archive.namelist()
    assert "metadata.json" in names, names
    assert all(n == "metadata.json" or n.startswith("contents/") for n in names), names
    assert not any(n.startswith("tests/") or n.startswith("docs/") for n in names), names
print(f"archive ok: {path}")
PY
