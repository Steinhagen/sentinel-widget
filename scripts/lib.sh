#!/usr/bin/env bash
# Shared helpers for the Sentinel development scripts.

set -euo pipefail

sentinel_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

find_tool() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    if [ -d /nix/store ]; then
        find /nix/store -maxdepth 4 -type f -name "$name" 2>/dev/null \
            | sort -V | tail -n 1
    fi
}

setup_qml_environment() {
    local qmltestrunner="$1"
    local qt_qml_dir=""
    if [ -n "$qmltestrunner" ]; then
        qt_qml_dir="$(cd "$(dirname "$qmltestrunner")/.." && pwd)/lib/qt-6/qml"
    fi

    local paths=()
    [ -n "$qt_qml_dir" ] && [ -d "$qt_qml_dir" ] && paths+=("$qt_qml_dir")
    # A Qt Quick Test runner needs QtTest; the system Plasma QML modules live
    # here on NixOS.
    if [ -d /run/current-system/sw/lib/qt-6/qml ]; then
        paths+=("/run/current-system/sw/lib/qt-6/qml")
    fi
    if [ -n "${NIXPKGS_QT6_QML_IMPORT_PATH:-}" ]; then
        paths+=("$NIXPKGS_QT6_QML_IMPORT_PATH")
    fi
    if [ -n "${QML2_IMPORT_PATH:-}" ]; then
        paths+=("$QML2_IMPORT_PATH")
    fi

    local joined=""
    local path=""
    for path in "${paths[@]}"; do
        if [ -n "$joined" ]; then
            joined="$joined:$path"
        else
            joined="$path"
        fi
    done
    if [ -n "$joined" ]; then
        export QML2_IMPORT_PATH="$joined"
    fi
    export QML_XHR_ALLOW_FILE_READ=1
    export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
}

node_test_files() {
    local root="$1"
    find "$root/tests/domain" -maxdepth 1 -name '*.test.mjs' -type f 2>/dev/null \
        | sort
}
