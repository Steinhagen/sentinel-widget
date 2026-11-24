#!/usr/bin/env bash
# Install the custom severity shield icons into the per-user hicolor theme.
# kpackagetool6 installs the applet but not icon-theme assets; run this once
# after installing/updating the applet from source.
set -euo pipefail

cd "$(dirname "$0")/.."

data="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
dest="$data/scalable/status"

install -d "$dest"
install -m 644 contents/icons/sentinel-severity-*.svg "$dest"/

cache_tool="$(command -v gtk-update-icon-cache || true)"
if [ -z "$cache_tool" ]; then
    cache_tool="$(find /nix/store -maxdepth 4 -type f \
        -name gtk-update-icon-cache 2>/dev/null | head -n 1 || true)"
fi
if [ -n "$cache_tool" ]; then
    "$cache_tool" -f -t "$data" >/dev/null 2>&1 || true
fi

if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 >/dev/null 2>&1 || true
fi

echo "Installed severity shields into $dest"
