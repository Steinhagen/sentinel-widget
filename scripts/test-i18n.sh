#!/usr/bin/env bash
# Verify the gettext catalogs: complete, well-formed and compiled into the
# package at the path Plasma expects.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(sentinel_root)"

if ! command -v msgfmt >/dev/null 2>&1; then
    echo "msgfmt was not found. Use 'nix develop' or add gettext to PATH." >&2
    exit 1
fi

app_id="$(sed -n 's/.*"Id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/metadata.json" | head -n 1)"
if [ -z "$app_id" ]; then
    echo "could not read the applet Id from metadata.json" >&2
    exit 1
fi
domain="plasma_applet_$app_id"

shopt -s nullglob
catalogs=("$ROOT"/translate/*.po)
shopt -u nullglob
if [ "${#catalogs[@]}" -eq 0 ]; then
    echo "No .po catalogs in translate/." >&2
    exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "== translation catalogs =="
for po in "${catalogs[@]}"; do
    lang="$(basename "$po" .po)"
    stats="$(LC_ALL=C msgfmt --check --statistics -o /dev/null "$po" 2>&1)"
    echo "  $lang: ${stats:-0 translated messages}"
    if grep -Eq 'untranslated|fuzzy' <<<"$stats"; then
        echo "  $lang: the catalog is incomplete; fill in every msgstr and drop fuzzy flags." >&2
        exit 1
    fi

    msgfmt --check -o "$tmpdir/$lang.mo" "$po"
    installed="$ROOT/contents/locale/$lang/LC_MESSAGES/$domain.mo"
    if [ ! -f "$installed" ]; then
        echo "  $lang: missing $installed; run ./translate/build.sh" >&2
        exit 1
    fi
    if ! cmp -s "$tmpdir/$lang.mo" "$installed"; then
        echo "  $lang: $installed is stale; run ./translate/build.sh" >&2
        exit 1
    fi

    if ! grep -q "\"Description\\[$lang\\]\"" "$ROOT/metadata.json"; then
        echo "metadata.json is missing Description[$lang]" >&2
        exit 1
    fi
done

echo "translation checks passed"
