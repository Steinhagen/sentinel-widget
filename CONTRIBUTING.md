# Contributing to Sentinel

Sentinel is a Plasma 6 applet and a thin frontend for the **Sentinel** service.
The architecture and migration plan are in [docs/architecture.md](architecture.md);
the backend contract is in [docs/status-schema.md](status-schema.md).

## Setup

```sh
git clone git@github.com:Steinhagen/sentinel-widget.git
cd sentinel-widget
nix develop          # optional, but recommended on NixOS
```

Install into a temporary packageroot for testing:

```sh
kpackagetool6 --type Plasma/Applet --install . \
  --packageroot "$PWD/build/plasmoids"
```

Or install for the current user:

```sh
kpackagetool6 --type Plasma/Applet --upgrade .
```

## Before opening a pull request

```sh
./scripts/check.sh
```

This runs:

- `qmllint` on `contents/ui`;
- `node --test` on `tests/domain`;
- `qmltestrunner` on `tests/qml` (offscreen);
- `./package.sh` and an archive check.

If a tool is not installed, use `nix develop` or set `QMLTESTRUNNER`,
`QML2_IMPORT_PATH` and `PATH` explicitly. See [docs/testing.md](testing.md).

## Rules of the codebase

- `contents/ui/domain/` is pure ECMAScript: no QML, Qt, `i18n`, timers or I/O.
- `contents/ui/services/` is the only place that executes commands or reads
  configuration/files.
- `contents/ui/state/` owns data and selection state; it does not paint.
- `contents/ui/components/` receives properties and emits signals. It must not
  read the applet root, `Plasmoid` or execute commands.
- `contents/ui/main.qml` is the composition root: applet metadata and wiring.
- Add `pragma ComponentBehavior: Bound` and `required property` to components
  with delegates.
- Keep user-facing copy in `Labels.qml`; do not build sentences by
  concatenating translated fragments.
- Preserve the behavior documented in `docs/architecture.md` §2.2.

## Commit style

One concern per commit, using a short imperative subject:

```
refactor(domain): extract fix classification
test(domain): cover every fix state
fix(state): refresh rows when tracker annotations change
```

Do not mix formatting-only changes with behavior changes. For visual changes,
include before/after screenshots or a short manual QA note.

## Translations

User-facing strings use `i18n`, `i18nc` or `i18np` in QML. Run
`./Messages.sh` when adding strings (it writes `po/sentinel.pot`), and test a
pseudo-locale for elision and layout. Do not add translated strings to
`.mjs` files.

## Reporting issues

Include the Plasma version, the `status.json` schema version, whether the
tracker token is configured, and the relevant lines from the scan log. Redact
the token.
