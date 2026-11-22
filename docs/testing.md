# Testing Sentinel

The test suite has two runners:

- **Node** (`node --test`) for the pure `.mjs` domain modules.
- **qmltestrunner** for QML services and state, with fake services.

Both run without Plasma, a display server, `/var/lib/vulnscan`, systemd or the
network.

## Commands

Current suite: 57 Node domain tests and 33 qmltestrunner service/state tests.

```sh
# one command for everything available
./scripts/check.sh

# domain only
./scripts/test-domain.sh

# QML services/state/components only
./scripts/test-qml.sh

# lint only
./scripts/lint.sh
```

`check.sh` runs lint, domain tests, QML tests and the package build. It skips a
stage only when that stage has no files yet; CI treats a missing tool as an
error.

## Tooling

The expected tools are `node` (18+), `qmllint`, `qmltestrunner`, `qmlformat`,
`kpackagetool6`, `jq` and `python3`. On NixOS use the dev shell:

```sh
nix develop
./scripts/check.sh
```

Outside the dev shell, point the scripts at explicit binaries:

```sh
QMLTESTRUNNER=/path/to/qmltestrunner \
QML2_IMPORT_PATH=/path/to/qt/qml:/path/to/plasma/qml \
  ./scripts/test-qml.sh
```

The scripts derive the Qt QML directory from the `qmltestrunner` binary when
possible and append `/run/current-system/sw/lib/qt-6/qml` on NixOS.

## Domain tests

`tests/domain/*.test.mjs` import the same `.mjs` files the applet ships. Use
Node's built-in runner and `node:assert/strict`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { classify } from "../../contents/ui/domain/fix.mjs";

test("fixed on the system channel", () => {
    const fix = classify(finding, "nixos-unstable");
    assert.equal(fix.bucket, "fixed");
});
```

Fixtures live in `tests/fixtures`. Node reads them with `fs`; QML tests read
them with `XMLHttpRequest` and `QML_XHR_ALLOW_FILE_READ=1`, or use a `.mjs`
fixture module when the env flag is inconvenient.

## QML tests

`tests/qml/*.qml` use Qt Quick Test. A test case can instantiate a service or
state object with fakes:

```qml
TestCase {
    name: "FindingsViewModel"
    function test_filters() {
        const vm = Qt.createQmlObject("...", testCase);
        // set vm.searchText, compare vm.rows
    }
}
```

Use `FakeRunner.qml` to script command responses, `FakeClock.qml` to control
time, and an in-memory `FakeStatusSource.qml` to feed status text. Never read
`/var/lib/vulnscan`, call `systemctl`, open a URL or sleep in a test.

QML tests that import Kirigami or Plasma components need the Plasma QML import
path. Run them against the Qt/Plasma minor version the applet targets.

## Fixtures

`tests/fixtures/status-v7.json` is a sanitized subset of a real scan covering:

- `fix_state`: fixed, in-staging, in-master, in-release, issue-open and missing;
- legacy `master_status`: unaffected, affected, unknown, unmatched;
- tracker: found false, pending, published, rejected and absent;
- origins: none, one, several, repeated nodes and multiple chains;
- severity: 0, null, medium, high and critical.

`tests/fixtures/status-legacy.json` covers `top`, a missing
`severity_counts`, and a legacy timestamp. `status-corrupt.json` covers invalid
JSON. `tracker-progress.json` covers a running package phase.

To refresh the fixture, capture a real `status.json` and run the sanitizing
script in `tools/` (or use `jq`). Strip `store_paths` if you want a smaller
fixture, and keep only the findings needed to cover the states above. Never
commit a tracker token.

## What to test when changing code

| Change | Tests to add or update |
| --- | --- |
| New status field | `status.test.mjs`, fixture, schema doc |
| Fix/tracker rule | `fix.test.mjs` or `tracker.test.mjs`; one test per state |
| Filter/sort/group | `filters.test.mjs` / `table.test.mjs` |
| Command/service | QML test with `FakeRunner`; exit code and timeout |
| Scan lifecycle | QML test for start, adopt, finish, timeout, failure |
| UI component | QML test for labels, signals and empty states; manual screenshot |
| Performance | 2,000-row synthetic fixture and a CI benchmark threshold |

## Manual release checklist

- Fresh install with no status file; first scan; running scan.
- Restart plasmashell during a scan; the Scanning state is recovered.
- Tracker progress is live; an open tooltip survives a poll.
- Search, severity/fix filters, sort, package/origin drill-down and grouping.
- Context menu: tracker, fix, copy, search, report, log.
- Settings: badge count/dot/none; token field.
- Light and dark themes; 36 grid-unit width; high DPI; compact popup.
- RTL and a long-translation pseudo-locale.
- Two applet instances keep independent state.
- Missing, corrupt and permission-denied status files show distinct messages.
- Package build and `kpackagetool6 --install` into a temporary packageroot.
