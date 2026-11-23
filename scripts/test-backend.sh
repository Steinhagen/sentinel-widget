#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"
PYTHON="${PYTHON:-python3}"

echo "== backend tests =="
"$PYTHON" -m unittest discover -s "$ROOT/tests/backend" -p 'test_*.py'
