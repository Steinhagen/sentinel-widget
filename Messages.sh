#!/bin/sh
# Extract translatable strings from the applet. Run from the repository root.
set -eu

podir="${podir:-$PWD/po}"
XGETTEXT="${XGETTEXT:-xgettext}"
mkdir -p "$podir"

files=$(find contents -type f \( -name '*.qml' -o -name '*.js' -o -name '*.mjs' \) | sort)
if [ -z "$files" ]; then
    echo "No source files found." >&2
    exit 1
fi

# QML uses the same i18n/i18nc/i18np calls as KDE C++; the C++ parser plus
# explicit keywords is the conventional extraction path for Plasma applets.
$XGETTEXT --from-code=UTF-8 --add-comments=TRANSLATORS: \
    --language=C++ \
    --keyword=i18n:1 \
    --keyword=i18nc:1c,2 \
    --keyword=i18np:1,2 \
    --output="$podir/sentinel.pot" \
    $files

echo "Wrote $podir/sentinel.pot"
