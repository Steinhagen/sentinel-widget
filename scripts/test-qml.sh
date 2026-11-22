#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

QMLTESTRUNNER="${QMLTESTRUNNER:-$(find_tool qmltestrunner || true)}"
if [ -z "$QMLTESTRUNNER" ]; then
    echo "qmltestrunner was not found. Use 'nix develop' or set QMLTESTRUNNER." >&2
    exit 1
fi
setup_qml_environment "$QMLTESTRUNNER"

if ! find "$ROOT/tests/qml" -name 'tst_*.qml' -type f | grep -q .; then
    echo "No QML tests yet."
    exit 0
fi

echo "== qmltestrunner =="
"$QMLTESTRUNNER" -input "$ROOT/tests/qml"
