# Sentinel architecture

**Status:** implemented. This document is kept as the design record and migration log.

**Scope:** keep the current applet behavior and the `vulnscan` backend contract,
but replace the single 3,625-line `contents/ui/main.qml` with layers that can be
tested, reviewed and extended independently.

**Recommendation in one sentence:** turn `main.qml` into a composition root,
move every rule into pure ECMAScript modules, put every side effect behind a
small service, expose two per-instance state objects, and make the UI a set of
presentational components. Migrate in small, shippable steps; do not rewrite
in one pass.

---

## 1. Why the current shape hurts

> Historical starting point: the sections below record the 3,625-line monolith
> and the refactor that replaced it. Post-refactor metrics are in Appendix A.

`contents/ui/main.qml` is not just large. It mixes concerns that change for
different reasons:

| Concern | Examples in the current file |
| --- | --- |
| Applet shell | `Plasmoid.title`, `Plasmoid.icon`, `badgeText`, tooltip, contextual actions |
| Configuration | `badgeMode`, tracker token, column widths |
| I/O | `cat`, `systemctl`, `curl`, clipboard, `openUrlExternally` |
| Polling and lifecycle | eight `Timer` elements, scan adoption after a plasmashell restart, timeout |
| Schema adaptation | `vulnerabilities` vs `top`, three timestamp formats, missing counts |
| Domain rules | severity bands, fix-state precedence, tracker state, origin chains |
| Aggregation | severity counts, fix buckets, tracker buckets, affected packages |
| Formatting and i18n | 245 `i18n`/`i18nc`/`i18np` calls, long help text, tooltips |
| Table state | search, nine filter fields, severity band, sort, grouping, scroll restoration |
| Layout and theme | 1,428 lines of UI, 18 derived colors |
| Workarounds | hover freeze, deferred status, list-level tooltip, zero-interval timers |

The practical consequences are:

- **Every change touches the same file.** A layout tweak, a tracker rule and a
  polling change all collide in one 152 KB file.
- **The risky rules are untested.** Fix-state precedence and tracker
  classification decide what the user sees, yet there is no test, fixture or
  CI job for them.
- **The compiler cannot help.** QML's dynamic scope hides errors that a typed
  module would reject. `qmllint` currently reports 752 unqualified accesses,
  24 missing properties and 6 unresolved types (Qt 6.12 tooling).
- **Dead code accumulates.** 26 top-level members are unreferenced, one is
  write-only, and the whole column-width persistence path has no observable
  effect.
- **Defects survive review.** See the concrete examples in Appendix B: a
  duplicate `var pending` corrupts the tracker summary, and `root.compactLayout`
  is read from the wrong object.
- **Performance work is guesswork.** The widget parses a 1.86 MB status file on
  the GUI thread every 60 s, and every 3 s while the tracker runs. On the
  current real fixture that is a 34 ms `JSON.parse` per read; grouped mode also
  performs an O(n²) count in the section delegate.

The app works. The problem is that its structure gives no safe place to change
it, and no way to prove that a change did not break an existing state.

---

## 2. Goals, contract and non-goals

### 2.1 Goals

1. **Behavior preservation.** The dashboard, toolbar, filters, grouping,
   tooltips, context menu, scan lifecycle, badge, settings and backend contract
   stay the same.
2. **Testability.** Every rule that can produce a wrong label, count or row is
   a pure function with fixtures and tests.
3. **Local reasoning.** A change to fix logic touches `domain/fix.mjs` and its
   tests; a change to the header touches `components/HeaderBar.qml`; neither
   requires reading 3,600 lines.
4. **Explicit contracts.** Components receive properties and emit signals. No
   component reaches into the applet root, and no UI code executes commands.
5. **Safe evolution.** A new backend field, a new fix state, a new tracker phase
   or a new card has one obvious place to land.
6. **A real safety net.** Lint, unit tests, QML tests, packaging and an install
   smoke test run in CI on every change.

### 2.2 What must not change

Treat this as the behavioral contract for the migration:

- `metadata.json` id/name and KPackage layout.
- `/var/lib/vulnscan/status.json`, `report.csv` and `last.log` paths.
- `systemctl start --no-block vulnscan.service` and
  `systemctl is-active vulnscan.service`.
- Status-file fallbacks: `vulnerabilities`/`top`, optional
  `severity_counts`, `packages_affected`, `scanned_at_epoch`,
  `scanned_at_iso`, legacy `scanned_at`.
- Fix-state vocabulary and precedence (`fixed`, `staging`, `master`, release,
  `issue`, `no fix`, `unknown`, `n/a`).
- Tracker states, on-demand tracker check behavior and rate-limit messages.
- Polling intervals: 60 s idle, 10 s while scanning, 3 s while the tracker is
  busy, 3 s service check while scanning, 150 min scan timeout, 30 s clock.
- Hover behavior: an open row tooltip must not be destroyed by a poll.
- Scroll behavior: a refresh preserves position; a filter/sort/search/new scan
  jumps to the top.
- `badgeMode` values `count`, `dot`, `none`.
- Light/dark theming through Kirigami.
- The `.plasmoid` archive and `kpackagetool6` installation.

### 2.3 Non-goals for this refactor

- Rewriting the scanner backend.
- A visual redesign.
- New features (history, notifications, per-column resizing, etc.).
- A C++ QML plugin. QML plus `.mjs` is enough for the current scale. Revisit
  only if incremental models or >5,000 findings make it necessary.
- Changing the config schema beyond removing the dead column-width key.
- TypeScript or a bundler. JSDoc plus tests is enough; avoid a build step that
  KPackage does not need.

### 2.4 Constraints

- Plasma 6 / Qt 6 QML. The applet is loaded by KPackage; files under
  `contents/` are shipped as-is.
- Multiple applet instances (desktop and panel) must have independent state.
  This rules out QML singletons for state.
- `i18n()` and `Kirigami.Theme` are QML-context facilities, not available in
  pure JS modules.
- The scanner backend is a separate project; the widget must remain tolerant of
  older and newer status files.
- The tracker token is stored in the applet configuration and consumed by the
  root service; it must never be passed on a command line or logged.

---

## 3. Target architecture

### 3.1 Dependency rule

```
UI components ──▶ state (view models) ──▶ domain (pure rules)
       │                    │
       │                    └───────────▶ services (I/O) ──▶ OS / files / network
       └──▶ theme / labels (no I/O, no domain decisions)
```

Allowed dependencies:

- `components/` may import Qt Quick, Plasma components, `SentinelTheme`,
  `Labels`, and plain data properties. It must not import `Plasmoid`, execute
  commands, read files or classify findings.
- `state/` may import `domain/` and service interfaces. It must not import
  Qt Quick Controls or paint anything.
- `services/` may use `Plasma5Support`, `Qt`, `Plasmoid.configuration` and
  OS commands. They return data/errors; they do not decide what the UI means.
- `domain/` has no external imports. Domain modules may import each other, but
  no QML, Qt, i18n, timers or file I/O.
- `main.qml` is the only composition root. It instantiates services, state and
  views, and wires signals.

### 3.2 Layers

| Layer | Responsibility | Knows about | Must not know about |
| --- | --- | --- | --- |
| `domain/` | Parse, normalize, classify, filter, sort, group, diff, format numbers/time tokens | Plain JS objects | QML, Qt, i18n, files, commands, colors |
| `services/` | Read the status file, start/query the service, call the tracker, read settings, clipboard, URLs, clock | OS, `Plasma5Support`, `Plasmoid.configuration` | UI, list state, fix precedence |
| `state/` | Own report, tracker, scan phase, errors, filters, sort, grouping, derived rows and counts | Domain + services | Layout, colors, `ListView`, `ToolTip` |
| `components/` | Render properties, emit user intents, local hover/focus/menu state | Qt Quick, Plasma, theme, labels | Files, commands, `Plasmoid`, domain rules |
| `main.qml` | Applet metadata, wiring, full/compact representation | Everything | Business rules |

### 3.3 Proposed tree

```
contents/
  config/
    main.xml                     # badgeMode, tracker token
    config.qml
  ui/
    main.qml                     # composition root, target ~150 lines
    configGeneral.qml
    domain/
      status.mjs                 # parse/normalize/validate/fingerprint
      severity.mjs               # score -> band, formatting of numbers
      fix.mjs                    # fix state classification + branch rows
      tracker.mjs                # tracker state, filters, progress model
      origins.mjs                # origin names/chains/group key
      filters.mjs                # FilterState, predicates, counts
      table.mjs                  # row building, sorting, grouping, flattening
      time.mjs                   # scan age, relative-time tokens
      urls.mjs                   # tracker/search URLs, safe URL checks
      types.mjs                  # JSDoc typedefs and shared enums
    services/
      CommandRunner.qml          # one place that executes shell commands
      StatusFileSource.qml       # read status.json, return text/error
      ScanService.qml            # systemctl start/is-active
      TrackerClient.qml          # on-demand curl check
      AppSettings.qml            # badgeMode/token from Plasmoid.configuration
      Clock.qml                  # one ticking clock, injectable interval
      ClipboardService.qml
      UrlService.qml             # scheme-checked openUrlExternally
    state/
      ScanStore.qml              # report, tracker, phase, errors, fingerprints
      FindingsViewModel.qml      # filters, sort, group, rows, counts
    components/
      SentinelPopup.qml          # full representation layout
      HeaderBar.qml
      ScanProgress.qml
      SummaryCards.qml
      RiskCard.qml
      SeverityCard.qml
      FixesCard.qml
      FindingsToolbar.qml
      FindingsList.qml
      FindingRow.qml
      GroupHeader.qml
      RowContextMenu.qml
      EmptyState.qml
      TrackerHint.qml
      Labels.qml                 # all user-facing copy, in QML context
      SentinelTheme.qml          # derived colors, per instance
tests/
  domain/
    status.test.mjs
    severity.test.mjs
    fix.test.mjs
    tracker.test.mjs
    origins.test.mjs
    filters.test.mjs
    table.test.mjs
    time.test.mjs
  qml/
    tst_scan_store.qml
    tst_findings_view_model.qml
    tst_command_runner.qml
    tst_finding_row.qml
    tst_findings_list.qml
  fixtures/
    status-v7.json             # sanitized, 12-20 representative findings
    status-legacy.json         # `top`, no severity counts, old timestamp
    status-corrupt.json
    tracker-progress.json
  helpers/
    fixtures.mjs
    FakeRunner.qml
    FakeClock.qml
scripts/
  check.sh                     # lint + tests + package
  test-domain.sh
  test-qml.sh
flake.nix                      # dev shell + checks (recommended)
docs/
  architecture.md              # this file
  status-schema.md             # backend contract, versioned
  testing.md                   # how to run and extend the suite
```

The exact file count is not the point. The point is that each file has one
reason to change, and dependencies point in one direction.

### 3.4 Runtime data flow

```
           user intent (scan, filter, sort, open, copy)
                              │
                              ▼
┌────────────────────────── components/ ──────────────────────────┐
│ HeaderBar  SummaryCards  FindingsToolbar  FindingsList  RowMenu  │
└───────────────▲───────────────────────────────┬─────────────────┘
                │ properties / rows              │ signals
┌───────────────┴───────────────────────────────▼─────────────────┐
│ FindingsViewModel                                             │
│  filters, sort, group, visible/total counts, rows              │
└───────────────▲───────────────────────────────┬─────────────────┘
                │ domain/table.mjs               │ domain/*.mjs
┌───────────────┴───────────────────────────────▼─────────────────┐
│ ScanStore                                                     │
│  report, tracker, phase, errors, fingerprints, hold policy     │
└───────────────▲───────────────────────────────┬─────────────────┘
                │ domain/status.mjs               │ service calls
┌───────────────┴───────────────────────────────▼─────────────────┐
│ services/                                                     │
│ StatusFileSource  ScanService  TrackerClient  Settings  Clock   │
└───────────────────────────────────────────────────────────────┘
                │
     status.json / systemctl / curl / KConfig / clipboard
```

There is no path from a component back to a file or a command. There is no path
from a domain module to a timer or a color.

### 3.5 State ownership

| State | Owner | Lifetime |
| --- | --- | --- |
| Parse errors, report, tracker, fingerprints | `ScanStore` | applet instance |
| Scan phase, service active, pre-scan stamp, deferred update | `ScanStore` | applet instance |
| Search, severity/fix/tracker filters, package/origin filters, sort, group | `FindingsViewModel` | applet instance |
| Derived rows and counts | `FindingsViewModel` | recomputed from report |
| Theme colors | `SentinelTheme` | applet instance |
| Hovered row, tooltip anchor, context menu, scroll position | `FindingsList` / `FindingRow` | view |
| Badge mode, tracker token | `AppSettings` | applet instance, backed by KConfig |
| Applet title/icon/badge/tooltip/actions | `main.qml` | applet instance |

`ScanStore`, `FindingsViewModel`, `SentinelTheme` and `Labels` are `QtObject`
instances. Do **not** make them QML singletons: two Sentinel applets on the
same desktop must not share filters or report state.

---

## 4. Module decomposition

### 4.1 Domain (`*.mjs`, no QML imports)

| Module | Responsibility | Key exports |
| --- | --- | --- |
| `types.mjs` | JSDoc typedefs, frozen enums | `SeverityBand`, `FixStage`, `FixBucket`, `TrackerState` |
| `status.mjs` | Parse and normalize `status.json`; tolerate legacy shapes; compute fingerprints | `parseStatusText`, `normalizeReport`, `normalizeFinding`, `normalizeTracker`, `fingerprint` |
| `severity.mjs` | CVSS score checks and bands; one-decimal formatting | `hasScore`, `bandOf`, `formatScore` |
| `fix.mjs` | The whole fix precedence table, branch rows, master fallback, fix URL, next-step token | `classify`, `masterStatus`, `branchRows`, `fixUrl`, `isUnstableChannel` |
| `tracker.mjs` | Tracker state for a finding, filters, URL, progress model, summary counts | `stateOf`, `matches`, `urlFor`, `progressOf`, `countsOf` |
| `origins.mjs` | Origin names, normalized chains, primary origin, group key | `namesOf`, `primaryOf`, `chainOf`, `groupKeyOf` |
| `filters.mjs` | `FilterState`, search haystack, predicates, active flag, band counts | `empty`, `isActive`, `haystack`, `matches`, `counts` |
| `table.mjs` | Build precomputed view rows, sort, flatten groups | `buildRows`, `sortRows`, `flattenGroups`, `valueOf` |
| `time.mjs` | Scan age and relative-time tokens (`unit`, `value`) | `scanAge`, `relativeToken` |
| `urls.mjs` | Tracker/search URLs, safe scheme check | `trackerPage`, `trackerApi`, `nixpkgsSearch`, `isSafeExternalUrl` |

Rules:

- No `i18n`, `Qt`, `Kirigami` or `Plasmoid`; no ambient clock (`Date.now()`) —
  pass `now` in as an argument; no `Timer`, `XMLHttpRequest` or `console`
  (except a debug seam if needed).
- Use conservative ES2017 syntax. Avoid optional chaining and nullish coalescing
  until the minimum Qt/Plasma version is explicitly pinned and tested. The
  current code style already uses `var`; moving to `const`/`let` is fine, but
  keep the syntax accepted by Qt 6's JS engine.
- Functions take explicit inputs, including `systemChannel` and `now`, so tests
  do not depend on machine state or the clock.
- Return plain data and tokens, never translated strings or colors.

### 4.2 Services (all side effects)

| Service | API | Notes |
| --- | --- | --- |
| `CommandRunner.qml` | `run(command, token)`, `signal response(token, exitCode, stdout, stderr)`, `signal timeout(token)` | One `Plasma5Support.DataSource`; maps source names to tokens/callbacks; serializes or queues; owns timeouts. Replaces prefix routing in `onNewData`. |
| `StatusFileSource.qml` | `read()`, `signal loaded(text, errorCode)`, optional `mtime` | Reads `status.json`; returns raw text plus `missing`/`permission`/`other`. No parsing. |
| `ScanService.qml` | `start()`, `queryActive()`, signals | Exact `systemctl` commands; typed errors. |
| `TrackerClient.qml` | `check(cve)`, signals `found`/`missing`/`rateLimited`/`failed` | Validates CVE with the same regex; uses `curl`; no token on the command line. |
| `AppSettings.qml` | `badgeMode`, `trackerToken`, `signal changed` | Only place that reads `Plasmoid.configuration`. |
| `Clock.qml` | `now`, configurable tick interval | Replaces the 30 s clock timer; tests set `now` directly. |
| `ClipboardService.qml` | `copy(text)` | Owns the hidden `TextEdit` helper. |
| `UrlService.qml` | `open(url)` | Rejects non-`https` schemes for external vulnerability/tracker URLs. |

Services should not know about fix states or list rows. A service answers "here
is text/exit code" or "the command failed"; the store decides what that means.

### 4.3 State

#### `ScanStore.qml`

Owns the data and the scan lifecycle.

```qml
QtObject {
    id: store

    required property StatusFileSource source
    required property ScanService scanService
    required property Clock clock

    property var report: null              // normalized ScanReport
    property var tracker: null             // normalized TrackerProgress
    property string phase: "idle"         // idle|starting|scanning|finishing|failed
    property bool serviceActive: false
    property string loadError: ""          // LoadError code
    property string reportFingerprint: ""
    property string trackerFingerprint: ""

    // The list sets this while a tooltip is open.
    property bool holdUpdates: false
    property var deferredReport: null

    readonly property bool hasReport: report !== null
    readonly property string systemChannel: report && report.tracker
        ? (report.tracker.systemChannel || "") : ""

    function refresh() { source.read(); }
    function startScan() { ... }
    function finishScan() { ... }
    function onStatusLoaded(text, errorCode) { ... }
    function applyDeferred() { ... }
}
```

Responsibilities:

- Parse via `domain/status.mjs`; never `JSON.parse` inline.
- Keep `report` and `tracker` separate conceptually, even if they come from one
  file today.
- Compare fingerprints, not hand-written field lists.
- Apply the hover policy: if a new report changes displayed rows while
  `holdUpdates` is true, store `deferredReport`; apply on leave.
- Own scan phase transitions and the 150 min timeout.
- Expose typed error codes; no user-facing strings.

#### `FindingsViewModel.qml`

Owns everything about the table selection and derived rows.

```qml
QtObject {
    id: vm

    required property ScanStore store

    property string searchText: ""
    property string severityBand: ""
    property string fixState: ""
    property string trackerState: ""
    property string packageFilter: ""
    property string originFilter: ""
    property string sortKey: "severity"
    property bool sortDescending: true
    property string groupBy: "none"
    property bool groupsExpanded: true

    readonly property var rows: ...
    readonly property var counts: ...
    readonly property int visibleCount: ...
    readonly property int totalCount: ...
    readonly property bool anyFilterActive: ...

    signal rowsReset(bool preserveScroll)

    function clearFilters() { ... }
    function showPackage(name) { ... }
    function showOrigin(name) { ... }
    function toggleSort(key) { ... }
}
```

Responsibilities:

- Build view rows once per report/filter/sort/group change via
  `domain/table.mjs`. Each row carries `severityBand`, `fix` classification,
  `origin` info, `trackerState` and a lowercase search haystack.
- Return a flat list, including group headers, so the view has one model and no
  O(n²) section count.
- Emit `rowsReset(preserveScroll)`: a report refresh preserves the current
  position, while a filter/sort/search/new scan jumps to the top. `FindingsList`
  performs the save/restore; the view model never touches `contentY`.
- Do not import `ListView`, `ToolTip`, `Kirigami` or `Plasmoid`.

### 4.4 UI components

| Component | Inputs | Outputs |
| --- | --- | --- |
| `SentinelPopup` | store, vm, settings, theme, labels | scan/settings intents |
| `HeaderBar` | posture, summary, icon, last scan, scan phase, progress, warning | `scanRequested`, `settingsRequested` |
| `ScanProgress` | `phase`, `tracker`, totals/done | none |
| `SummaryCards` | counts, bands, selected filters, theme | `severitySelected`, `fixStateSelected` |
| `RiskCard` | max severity, findings, packages, CVEs | none |
| `SeverityCard` | bands, selected band, theme | `selected(band)` |
| `FixesCard` | fix bands, total, selected state, theme | `selected(state)` |
| `FindingsToolbar` | search text, filters, counts, group mode, expanded state | `searchChanged`, `clearFilters`, `groupBySelected`, `toggleGroupsExpandedRequested` |
| `FindingsList` | rows, grouped mode, theme, labels | `openFinding`, `filterPackage`, `filterOrigin`, `openFix`, `openTracker`, `copy`, `menuRequested` |
| `FindingRow` | `required property var rowData`, theme, labels | row intents |
| `GroupHeader` | group title/kind, count | none |
| `RowContextMenu` | row, labels | row intents |
| `EmptyState` | icon, title, explanation | none |
| `TrackerHint` | text, visible | none |
| `Labels` | none (stateless functions) | translated strings |
| `SentinelTheme` | none | derived colors |

UI rules:

- Add `pragma ComponentBehavior: Bound` to every file with delegates, and use
  `required property` for inputs. This removes the dynamic-scope warnings and
  makes accidental outer-ID access a compile error.
- No `root.*` inside a component. Pass `theme`, `labels` and data explicitly.
- No `Qt.openUrlExternally`, `systemctl`, `cat`, `curl` or config access in a
  component; emit a signal.
- Keep long help text and all user-facing copy in `Labels.qml`, not in domain
  modules.
- One list-level tooltip keyed by row id (and later, an incremental model) is
  preferable to per-delegate tooltips that die when the model resets. Until
  incremental updates land, `ScanStore.holdUpdates` remains the explicit
  policy.
- `FindingsList` owns `contentY`, `positionViewAtBeginning()` and restoration.
  Remove the `scrollToTopRequest`/`restoreListRequest` counters and the two
  zero-interval timers from the composition root.

### 4.5 Composition root

Target shape (names illustrative):

```qml
PlasmoidItem {
    id: applet

    AppSettings { id: settings }
    CommandRunner { id: runner }
    StatusFileSource { id: statusSource; runner: runner; path: applet.statusFile }
    ScanService { id: scanService; runner: runner }
    Clock { id: clock }
    ScanStore { id: store; source: statusSource; scanService: scanService; clock: clock }
    FindingsViewModel { id: vm; store: store }
    SentinelTheme { id: theme }
    Labels { id: labels }

    fullRepresentation: SentinelPopup {
        store: store
        vm: vm
        settings: settings
        theme: theme
        labels: labels
        onScanRequested: store.startScan()
        onSettingsRequested: {
            const action = Plasmoid.internalAction("configure");
            if (action) {
                action.trigger();
            }
        }
    }

    // Plasmoid.title/icon/badge/tooltip/contextualActions only.
}
```

Target: 120-180 lines. If `main.qml` still contains a `switch`, a filter loop or
a command string, the extraction is not finished.

---

## 5. Current-to-new mapping

This is the concrete extraction map. Work top-to-bottom: pure rules first, UI
last.

| Current concern | Current location | New home |
| --- | --- | --- |
| Status defaults, `top` fallback, counts fallback, timestamp parsing | 21-63, 256-312, 1842-1952 | `domain/status.mjs`, `domain/time.mjs` |
| Theme colors | 66-98, 503-514 | `components/SentinelTheme.qml` |
| Posture labels, state icon/summary/detail, empty state | 100-107, 516-607 | `domain/severity.mjs` + `Labels.qml` + `EmptyState.qml` |
| Severity bands/counts | 132-155 | `domain/severity.mjs`, `domain/filters.mjs` |
| Fix filter bands and counts | 157-190 | `domain/fix.mjs`, `domain/filters.mjs` |
| Tracker filter bands and counts | 192-254 | `domain/tracker.mjs`, `domain/filters.mjs` |
| Last scan relative/exact/tooltip | 256-312 | `domain/time.mjs` + `Labels.qml` + `HeaderBar.qml` |
| Tracker summary/progress text and totals | 314-501 | `domain/tracker.mjs` + `Labels.qml` + `HeaderBar/ScanProgress` |
| Table state (search, filters, sort, group) | 609-633 | `state/FindingsViewModel.qml` |
| Column defaults/minimums/pixels/persistence | 635-699, 1673-1732 | Delete. `main.xml` `columnWidths` is dead; remove after a release. |
| Filter/search/sort pipeline | 701-861, 1741-1830 | `domain/filters.mjs`, `domain/table.mjs` |
| Severity/fix/tracker/origin classification | 863-1671 | `domain/severity.mjs`, `domain/fix.mjs`, `domain/tracker.mjs`, `domain/origins.mjs` |
| Status diff and merge policy | 1846-1952 | `domain/status.mjs` fingerprints + `state/ScanStore.qml` |
| Applet title/icon/badge/tooltip/actions | 1954-2012 | `main.qml` |
| `Plasma5Support.DataSource` and command routing | 2014-2138 | `services/CommandRunner.qml`, `StatusFileSource`, `ScanService`, `TrackerClient` |
| Timers and scan lifecycle | 2140-2189 | `state/ScanStore.qml`, `services/Clock.qml` |
| Header UI | 2299-2549 | `components/HeaderBar.qml`, `ScanProgress.qml` |
| Summary cards | 2567-2909 | `components/SummaryCards.qml`, `RiskCard`, `SeverityCard`, `FixesCard` |
| Search/filters/group toolbar | 2911-3088 | `components/FindingsToolbar.qml` |
| Findings list, header, delegate, menus | 3090-3594 | `components/FindingsList.qml`, `FindingRow.qml`, `GroupHeader.qml`, `RowContextMenu.qml` |
| Empty state / tracker hint | 3596-3620 | `components/EmptyState.qml`, `TrackerHint.qml` |

---

## 6. Key design decisions

### 6.1 Use pure `.mjs` modules for the domain

**Decision:** put all rules in `contents/ui/domain/*.mjs`, imported by QML as
`import "domain/fix.mjs" as Fix`.

**Why:**

- Qt supports ECMAScript modules in QML when the extension is `.mjs`; this was
  validated in this checkout with `qmltestrunner` 6.12.
- The same files run under Node 24 with `node --test`, giving fast tests
  without a display server, Plasma session or QML runtime.
- No QML globals means no accidental `root`, `Plasmoid`, `i18n` or `Timer`
  dependency.
- It avoids a C++ plugin and keeps KPackage packaging unchanged.

**Trade-off:** QML's JS engine is not a full Node runtime. Keep to conservative
ES2017 syntax, and run the QML tests against the production Qt/Plasma version,
not only Node.

### 6.2 Per-instance `QtObject` state, never QML singletons

Plasma allows multiple instances of the same applet (desktop and panel). A QML
singleton store would share report, filters and scan phase across them, which
is wrong.

- Pure domain functions are stateless and can be shared.
- `ScanStore`, `FindingsViewModel`, `SentinelTheme`, `Labels` are instantiated
  once per `PlasmoidItem`.
- Services are per instance too. If polling duplication ever matters, add a
  shared cache service explicitly; do not make the store global.

### 6.3 Domain returns tokens; QML owns words

The domain must not call `i18n`. It returns enums and data:

```js
{ stage: "in-master", bucket: "progress", branch: "nixos-unstable" }
```

`Labels.qml` maps those tokens to `i18n("master")`, `i18np(...)`, etc. This
keeps the rules testable and keeps translation extraction in QML. Move the long
fix/confidence help text and tooltip sentences into `Labels.qml`; they are copy,
not logic.

**Avoid string concatenation for sentences.** The current tracker progress code
concatenates translated fragments such as `i18n("Checking ...")` and
`i18n(" (%1 failed)", n)`. Use one complete sentence with placeholders, and
`i18np` for counts, so translators can reorder the sentence.

### 6.4 Normalize once, then fingerprint

`domain/status.mjs` produces a stable `ScanReport`:

- backend names map to camelCase where it helps the UI;
- missing fields get safe defaults;
- legacy `top`/`scanned_at` fallbacks happen here;
- each finding gets a `severityBand`, `fix`, `origin` and `trackerState` only
  when the view row is built, not in the raw normalizer;
- unknown fields are preserved (forward compatibility).

Compute two fingerprints:

- **findings fingerprint**: FNV-1a over a canonical serialization of every
  field that can change a row or a tooltip (including `fix_branches`,
  `origins.chains`, `origins.store_paths`, scanner order, tracker fields).
- **tracker fingerprint**: FNV-1a over tracker progress fields and
  `updated_at`.

Then `ScanStore` replaces rows only when the findings fingerprint changes, and
updates progress only when the tracker fingerprint changes. This replaces the
hand-maintained `sameTracker`/`sameVulnerabilities` lists, which already miss
`fix_branches`, `origins.chains`, `origins.store_paths` and several tracker
fields. Those omissions can leave a tooltip stale after the backend updates it.

Do not retain the full raw file just for comparison; keep the fingerprint and
drop the 1.8 MB string after parsing.

### 6.5 One flat list, including group headers

`ListView.section` plus `originGroupCount(section)` is convenient, but the
section header calls a function that scans the entire filtered list. With 69
origins and 932 rows that is an O(n²) path; it also makes the model and its
counts harder to test.

**Decision:** `domain/table.mjs` returns one flat array:

```js
[
  { rowType: "group", key: "haskell-language-server-2.13.0.0", count: 12 },
  { rowType: "finding", finding: {...}, fix: {...}, origin: {...} },
  ...
]
```

`FindingsList` uses a `Loader`/`DelegateChooser` on `rowType`, or one delegate
that swaps a `ColumnLayout`. Group counts are computed in one pass. Sorting
within groups and group ordering (max severity, count, name) live in
`domain/table.mjs` and have tests.

### 6.6 One command runner, typed callbacks

The current `onNewData` routes responses by string prefixes:

```js
if (sourceName.indexOf("systemctl is-active") === 0) { ... }
if (sourceName.indexOf("curl ") === 0 && trackerMatch) { ... }
if (sourceName.indexOf("cat ") === 0) { ... }
else if (root.scanning && exitCode !== 0) { ... }
```

This is brittle under concurrent requests, conflates unrelated commands, and
makes error handling depend on command text. `CommandRunner` should:

- own the single `Plasma5Support.DataSource`;
- map each command/source to a token and a callback list;
- deliver `exitCode`, `stdout`, `stderr` to exactly the right caller;
- timeout and cancel a stuck request;
- never let a store see a raw `sourceName`.

`StatusFileSource` then returns text/error; `ScanService` returns service
state; `TrackerClient` returns a tracker result. Each can be tested with a
`FakeRunner` that records commands and emits scripted responses.

### 6.7 Hover, tooltip, scroll and model updates

These are real UX requirements, not incidental hacks:

- A poll must not destroy the delegate under an open Fix tooltip.
- A status refresh must not reset the scroll position.
- A filter/sort/search/new scan must jump to the top.
- A tracker check must update the row that is being inspected.

The current implementation solves this with `listHovered`,
`deferredStatus`, `restoreListY`, request counters and zero-interval timers.
Keep the behavior, but make the ownership explicit:

- `FindingsList` signals `holdUpdates(true/false)` to `ScanStore`.
- `ScanStore` queues a deferred report and applies it when the hold ends.
- `FindingsList` saves `contentY` before a rows reset and restores it after
  when `preserveScroll` is true.
- A single list-level tooltip is anchored by the hovered row id and pointer
  position; it does not belong to a delegate that can be destroyed.
- Later, if hover churn or 2,000+ rows becomes a problem, switch the array
  model to a `ListModel` synchronized in place. That removes resets entirely.
  Do this only after tests and profiling justify it.

### 6.8 Delete the column-width subsystem

The old column-width subsystem was removed during the refactor: the
`columnWidths` KConfig entry, defaults, persistence, aliases and drag-handle
hooks are gone. The current table uses fixed widths in `listHeaderColumns`.

Remove the code, keep the KConfig key present for one release if downgrade
compatibility matters, then remove it. Do not reimplement resizing until there
is a tested `TableColumns` module and a UI requirement.

### 6.9 Testing stack

Use two runners, each where it is strongest:

- **Domain:** Node's built-in test runner (`node --test`) on `.mjs`. Fast,
  no display, coverage, standard assertions.
- **QML state/services/components:** `qmltestrunner` with
  `QT_QPA_PLATFORM=offscreen` and the Plasma QML import path.
- **Fixtures:** sanitized JSON captured from real scans; load with `fs` in Node
  and with `XMLHttpRequest` in QML (`QML_XHR_ALLOW_FILE_READ=1`), or use `.mjs`
  fixture modules if avoiding the env flag.
- **Fakes:** `FakeRunner`, `FakeClock`, fake status source, fake settings. No
  test reads `/var/lib/vulnscan`, runs `systemctl`, opens a URL or sleeps.

This was validated locally: qmltestrunner 6.12 loaded `.mjs` modules, imported
Kirigami/Plasma components, and loaded a local JSON fixture with
`QML_XHR_ALLOW_FILE_READ=1`; Node 24 ran the same `.mjs` module. CI must pin a
Qt/Plasma version matching the supported runtime.

### 6.10 Packaging stays KPackage-first

- Keep `package.sh` and `tools/package.py`; they already archive
  `metadata.json` + `contents/`.
- Keep `default.nix`; adjust it only if the layout changes.
- Optionally add CMake/ECM with `plasma_install_package` later for KDE CI
  conventions and `ctest`. Do not block the refactor on it.
- Ensure tests, docs and fixtures never go into the `.plasmoid`: they live
  outside `contents/`.
- Make `metadata.json` the single version source; generate or check the Nix
  version against it in CI.

---

## 7. Contracts

### 7.1 `ScanReport`

```js
/**
 * @typedef {Object} ScanReport
 * @property {number} schemaVersion
 * @property {string} state           // secure|vulnerable|warn|unknown
 * @property {number} findings
 * @property {number} maxSeverity
 * @property {number} packagesAffected
 * @property {{critical:number, high:number, medium:number, low:number, unknown:number}} severityCounts
 * @property {number|null} scannedAtMs
 * @property {string} error
 * @property {Finding[]} vulnerabilities
 * @property {TrackerProgress|null} tracker
 * @property {string} fingerprint
 * @property {string} trackerFingerprint
 */
```

### 7.2 Finding view row

```js
/**
 * @typedef {Object} FindingView
 * @property {"finding"} rowType
 * @property {string} id
 * @property {string} package
 * @property {string} version
 * @property {number} severity
 * @property {SeverityBand} severityBand
 * @property {string} severityText       // "9.9" or "—"
 * @property {string} url
 * @property {string[]} scanners
 * @property {string} confidence
 * @property {string} patchState
 * @property {OriginInfo} origin
 * @property {TrackerState} trackerState
 * @property {FixClassification} fix
 * @property {string} searchText         // lowercase haystack
 */
```

`FixClassification`:

```js
/**
 * @typedef {Object} FixClassification
 * @property {string} state            // fixed|in-staging|in-master|in-release|issue-open|""
 * @property {"fixed"|"progress"|"none"|"unknown"|"n/a"|""} bucket
 * @property {string} branch
 * @property {string} version
 * @property {{name:string, version:string, kind:string, state:string, url:string}[]} rows
 * @property {{status:string, version:string, source:string, range:string}} master
 * @property {string} url
 * @property {string} nextStep         // token, e.g. channel-bump|backport|staging-merge|none
 */
```

### 7.3 Filter state

Current table state is nine string filters plus search, severity band, sort and
group. Only some are reachable from the UI. The target state is:

```js
{
  text: "",
  severity: "",      // severity band
  fixState: "",      // fixed|progress|none|unknown|n/a
  trackerState: "",  // linked|pending|missing|unchecked
  package: "",       // set by clicking a package row
  origin: ""         // set by clicking an origin/chain
}
```

`cve`, `version`, `via` and `master` per-column filters have no UI and no
setter that can be reached; drop them unless they are intentionally kept for a
future column-filter feature. If kept, define them in the same `FilterState`
and unit-test them.

### 7.4 Scan phase and errors

```text
ScanPhase = "idle" | "starting" | "scanning" | "finishing" | "failed"
LoadError = "" | "missing" | "permission" | "invalid-json" | "unsupported-schema" | "unknown"
ScanError = "" | "start-failed" | "timeout" | "service-missing" | "unknown"
```

The UI maps codes to sentences in `Labels.qml`. `ScanStore` never stores a
translated message. This makes errors testable and prevents accidental
information loss such as the current behavior where a malformed `status.json`
only logs `console.warn` and the popup still says "Not scanned yet".

### 7.5 Backend schema

Add `docs/status-schema.md` (or a JSON Schema) with the v7 fields actually used:

- top level: `schema_version`, `state`, `findings`, `max_severity`,
  `packages_affected`, `severity_counts`, `scanned_at`, `scanned_at_iso`,
  `scanned_at_epoch`, `error`, `tracker`, `vulnerabilities`;
- per finding: `id`, `package`, `version`, `severity`, `url`, `scanners`,
  `confidence`, `patch_state`, `origins`, `tracker`;
- per tracker: `found`, `status`, `issue`, `issue_state`, `master_status`,
  `master_version`, `master_status_source`, `master_range`, `fix_state`,
  `fix_branch`, `fix_version`, `fix_branches`, `fix_url`, `github_issue_url`,
  `system_channel`, `system_known`, `suggestion_packages`,
  `affected_products`;
- progress: `available`, `complete`, `phase`, `updated_at`, all phase counters,
  `throttled`, `auth_failed`.

Validation strategy:

- fixtures validate the adapter;
- a schema test asserts required/optional fields;
- if `schema_version` is newer than supported, still render known fields and
  show a "newer backend" warning instead of failing;
- unknown fields are preserved, never rejected.

---

## 8. Code sketches

The sketches omit small helpers (`result`, `buildViewRow`, `matches`,
`sortRows`) and error branches for brevity. They show the intended boundaries,
not final implementations.

### 8.1 `domain/fix.mjs`

```js
export const Stage = Object.freeze({
    FIXED: "fixed",
    STAGING: "in-staging",
    MASTER: "in-master",
    RELEASE: "in-release",
    ISSUE: "issue-open"
});

export const Bucket = Object.freeze({
    FIXED: "fixed",
    PROGRESS: "progress",
    NONE: "none",
    UNKNOWN: "unknown",
    NA: "n/a"
});

export function branchRows(finding) {
    const tracker = finding && finding.tracker;
    return tracker && tracker.fix_branches ? tracker.fix_branches : [];
}

export function classify(finding, systemChannel) {
    const tracker = finding && finding.tracker ? finding.tracker : null;
    const state = tracker && tracker.fix_state ? tracker.fix_state : "";
    const rows = branchRows(finding);

    if (state === "fixed") {
        return result(Stage.FIXED, Bucket.FIXED, rows, systemChannel);
    }
    if (state === "in-staging") {
        return result(Stage.STAGING, Bucket.PROGRESS, rows, systemChannel);
    }
    if (state === "in-master") {
        return result(Stage.MASTER, Bucket.PROGRESS, rows, systemChannel);
    }
    if (state === "in-release") {
        return result(Stage.RELEASE, Bucket.PROGRESS, rows, systemChannel);
    }
    if (state === "issue-open") {
        return result(Stage.ISSUE, Bucket.PROGRESS, rows, systemChannel);
    }

    // Legacy status files only carry the master verdict.
    const master = masterStatus(finding);
    if (rows.length === 0 && master === "unaffected") {
        return result(Stage.FIXED, Bucket.FIXED, rows, systemChannel);
    }
    if (master === "affected") {
        return result("", Bucket.NONE, rows, systemChannel);
    }
    if (master === "unknown") {
        return result("", Bucket.UNKNOWN, rows, systemChannel);
    }
    if (master === "unmatched") {
        return result("", Bucket.NA, rows, systemChannel);
    }
    return result("", "", rows, systemChannel);
}
```

This module should mirror the current precedence exactly. The point of the
extraction is not to change the rules; it is to put them where tests can lock
them down. Add a test per state, per legacy fallback and per branch kind before
deleting the old implementation.

### 8.2 `domain/table.mjs`

```js
export function buildRows(findings, options) {
    const matched = [];
    for (let i = 0; i < findings.length; ++i) {
        const row = buildViewRow(findings[i], options.systemChannel);
        if (matches(row, options.filters)) {
            matched.push(row);
        }
    }
    sortRows(matched, options.sortKey, options.descending);
    return options.groupBy === "none"
        ? matched
        : flattenGroups(matched, options.groupBy, options.groupsExpanded);
}

function flattenGroups(rows) {
    const groups = new Map();
    for (const row of rows) {
        const key = row.origin.groupKey;
        let group = groups.get(key);
        if (!group) {
            group = { key: key, count: 0, maxSeverity: -1, rows: [] };
            groups.set(key, group);
        }
        group.count += 1;
        group.rows.push(row);
        if (row.severity > group.maxSeverity) {
            group.maxSeverity = row.severity;
        }
    }
    const ordered = Array.from(groups.values()).sort(compareGroups);
    const result = [];
    for (const group of ordered) {
        result.push({ rowType: "group", key: group.key, count: group.count });
        for (const row of group.rows) {
            result.push(row);
        }
    }
    return result;
}
```

### 8.3 `services/CommandRunner.qml` (shape)

```qml
QtObject {
    id: runner

    property int timeoutMs: 10000
    signal response(string token, int exitCode, string stdout, string stderr)
    signal failed(string token, string reason)

    function run(command, token) {
        // Map source -> token; start a timeout; connect the DataSource.
    }

    function cancel(token) { ... }
}
```

Implementation notes:

- A single `Plasma5Support.DataSource` with `connectedSources: []`.
- A JS object `pendingBySource` mapping the source string to `{ token,
  callbacks, timer }`.
- On `onNewData(sourceName, data)`: resolve the pending entry, disconnect only
  when no callbacks remain, invoke the callback with `data["exit code"]`,
  `data["stdout"]`, `data["stderr"]`.
- If the same command is requested twice before it returns, either queue the
  second request or attach both callbacks to the same in-flight entry. Do not
  disconnect after the first caller, which is a latent bug in the current
  prefix routing.
- Never route by parsing `sourceName` in a store.

### 8.4 `state/ScanStore.qml` (shape)

```qml
import "../domain/status.mjs" as Status

QtObject {
    id: store

    required property StatusFileSource source
    required property ScanService scanService
    required property Clock clock

    property var report: null
    property var tracker: null
    property string phase: "idle"
    property bool serviceActive: false
    property string loadError: ""
    property string reportFingerprint: ""
    property string trackerFingerprint: ""
    property bool holdUpdates: false
    property var deferredReport: null

    readonly property bool hasReport: report !== null

    function refresh() { source.read(); }

    function onStatusLoaded(text, errorCode) {
        if (errorCode) {
            loadError = errorCode;
            return;
        }
        const parsed = Status.parseStatusText(text);
        if (!parsed.ok) {
            loadError = parsed.error;
            return;
        }
        const next = parsed.report;
        if (next.trackerFingerprint !== trackerFingerprint) {
            tracker = next.tracker;
            trackerFingerprint = next.trackerFingerprint;
        }
        loadError = "";
        if (next.fingerprint === reportFingerprint) {
            return;
        }
        if (holdUpdates && hasReport) {
            deferredReport = next;
            return;
        }
        commit(next);
    }

    function commit(next) {
        report = next;
        reportFingerprint = next.fingerprint;
        loadError = "";
    }

    function applyDeferred() {
        const pending = deferredReport;
        deferredReport = null;
        if (pending) {
            commit(pending);
        }
    }
}
```

The scan timers and phase transition logic live in the same object initially.
If it grows past ~250 lines, split a `ScanController` that owns only timers and
phase; do not split prematurely.

### 8.5 `components/FindingRow.qml` (interface)

```qml
ItemDelegate {
    id: row

    required property var rowData
    required property var theme
    required property var labels

    signal openRequested()
    signal packageFilterRequested(string packageName)
    signal originFilterRequested(string originName)
    signal fixRequested(string url)
    signal trackerRequested(string cve)
    signal contextMenuRequested(point position)

    // Bind only to rowData/theme/labels. No root.*, no root.fixText(...).
}
```

The row receives precomputed `rowData.fix`, `rowData.origin`,
`rowData.trackerState`, `rowData.severityText` and `rowData.searchText`.
Formatting methods in `Labels` turn tokens into text. This removes repeated
classification calls from delegate bindings and makes row rendering testable
with a plain object.

### 8.6 Domain test (Node)

```js
import test from "node:test";
import assert from "node:assert/strict";
import { classify, Bucket } from "../../contents/ui/domain/fix.mjs";
import { reportV7 } from "../helpers/fixtures.mjs";

test("a fix on the system channel is bucket=fixed", () => {
    const finding = reportV7.vulnerabilities.find((v) => v.id === "CVE-2026-111497");
    const fix = classify(finding, "nixos-unstable");
    assert.equal(fix.state, "fixed");
    assert.equal(fix.bucket, Bucket.FIXED);
    assert.equal(fix.branch, "nixos-unstable");
});
```

### 8.7 QML test (grouping)

```qml
import QtQuick
import QtTest
import "../contents/ui/domain/table.mjs" as Table

TestCase {
    name: "TableGrouping"

    function test_group_header_precedes_its_rows() {
        const rows = Table.buildRows([/* two same-origin fixtures */], {
            systemChannel: "nixos-unstable",
            filters: {},
            sortKey: "severity",
            descending: true,
            groupBy: "origin"
        });
        compare(rows[0].rowType, "group");
        compare(rows[0].count, 2);
        compare(rows[1].rowType, "finding");
        compare(rows[2].rowType, "finding");
    }
}
```

---

## 9. Testing strategy

### 9.1 Test pyramid

| Level | Tool | What it covers | Approx. share |
| --- | --- | --- | --- |
| Domain unit | Node `node:test` | schema, severity, fix, tracker, origins, filters, table, time, URLs | 65-70% |
| Service/state | qmltestrunner + fakes | command routing, status source, scan phases, store merge/defer, view-model rows | 25% |
| UI component | qmltestrunner | row labels/tooltips, cards counts, empty state, toolbar signals | 5-10% |
| Manual/integration | shell + Plasma | real install, plasmashell restart, light/dark, panel, RTL, screenshots | release gate |

Do not chase 100% line coverage on QML layout. Cover the rules and the
transitions; verify the pixels manually or with screenshots.

### 9.2 Fixtures to write first

Create these from a sanitized real `status.json` (keep package names, drop
store paths if desired; no secrets are present, but keep the file small):

1. **`status-v7.json`** — 12-20 findings covering:
   - `fix_state`: `fixed`, `in-staging`, `in-master`, `in-release`,
     `issue-open`, missing;
   - legacy `master_status` only: `unaffected`, `affected`, `unknown`,
     `unmatched`;
   - tracker: `found: false`, `found: true` with `pending`, `published`,
     `rejected`; no `tracker` at all;
   - origins: no origins, one, several, duplicate nodes, version-suffixed last
     node, multiple `chains`;
   - severity: `0`, null, `3.9`, `4.0`, `6.9`, `7.0`, `8.9`, `9.0`, `9.9`;
   - confidence/scanners variants.
2. **`status-legacy.json`** — `top` instead of `vulnerabilities`, no
   `severity_counts`, `scanned_at` string, no tracker.
3. **`status-corrupt.json`** — truncated JSON.
4. **`tracker-progress.json`** — phases `pending`, `waiting`, `packages`,
   `cves`, `issues`, `probes`, done, `auth_failed`, `throttled`, `complete:
   false`.
5. **`status-large.json`** — generated 2,000-row synthetic fixture for the
   performance budget; not committed if it is large, generate in CI.

Sanitize with a small script (`tools/make-fixtures.py` or Node) so the fixture
can be refreshed when the backend changes. Keep the raw unmodified file out of
the repository.

### 9.3 Test matrix

| Area | Cases |
| --- | --- |
| Schema | v7, legacy, corrupt, missing file, permission error, future schema version, missing optional fields, string vs numeric severity |
| Timestamps | epoch, ISO with offset, legacy `%Y-%m-%d %H:%M %Z`, missing, invalid |
| Severity | boundaries 0/4/7/9, null, non-numeric, formatting to one decimal |
| Fix | every `fix_state`, every branch `kind`/`state`, fixed on another channel, system channel empty/unstable/stable, `system_known:false`, legacy master fallback, no rows, `issue-open`, URL fallback |
| Tracker | found/missing/unknown/none, on-demand checked map, each filter, each progress phase, totals/done, auth/throttle/failure, stale progress |
| Origins | empty, single, multiple, duplicate chain nodes, version suffix, chain equals package, >1 chains, group key, count |
| Filters | search each field, trim/case, combined, severity+fix+tracker, package/origin, active flag, counts |
| Sort | numeric/text, nulls, ties, ascending/descending, every exposed key, toggling |
| Group | order by max severity/count/name, item order, counts, unknown origin, no mutation, 0/1/many |
| Diff | unchanged, findings change, tracker-only change, `fix_branches` change, `origins.chains` change, reordered keys |
| Time | just now, 59 s, 60 s, 1 h, 1 d, future clock, no timestamp |
| Settings | count/dot/none/invalid, token, column-width key ignored after removal |
| Services | response routing, concurrent identical commands, timeout, cancel, exit codes, missing file, tracker 200/404/429/5xx |
| Lifecycle | idle → starting → scanning → finishing, adopt active service after restart, timeout, start failure, tracker busy, hold/defer/apply |
| UI | row text/tooltips/accessibility, cards counts, empty states, toolbar signals, compact threshold, light/dark, RTL |

### 9.4 Lint

- `qmllint` on all QML files. Record the current baseline; require new/changed
  files to be clean. The 752 `unqualified` warnings should fall sharply after
  `pragma ComponentBehavior: Bound` and explicit properties; the remaining
  `i18n`, `Plasmoid`, `Qt` context-property warnings can be documented or
  configured.
- `qmlformat` formatting check via a small wrapper that diffs formatted output
  against the sources (`qmlformat` has no `--check` flag).
- `node --check` on `.mjs` files; optionally `tsc --noEmit --allowJs --checkJs`
  with JSDoc for the domain only. This adds a type-checking pass without a
  runtime build step.
- `shellcheck` on scripts; `python -m py_compile` on `tools/package.py`.
- Fail CI on new warnings, not on the existing baseline. Ratchet the baseline
  down each phase.

### 9.5 CI

Recommended jobs:

1. **lint** — `qmllint`, `qmlformat` format check, `node --check`, shellcheck.
2. **test-domain** — `node --test tests/domain` with coverage threshold (90%
   branches for `domain/`).
3. **test-qml** — `QT_QPA_PLATFORM=offscreen qmltestrunner -input tests/qml`
   with the Plasma QML import path; `QML_XHR_ALLOW_FILE_READ=1` for fixtures.
4. **package** — `./package.sh`; assert the archive contains only
   `metadata.json` and `contents/`, and that no `tests/` or `docs/` files leak.
5. **install-smoke** — `kpackagetool6 --type Plasma/Applet --install .
   --packageroot "$PWD/build/plasmoids"` and `--show` the installed package.
6. **manual/release** — a checklist for visual, panel, light/dark, RTL and
   plasmashell-restart checks; run before tagging.

Use a Nix dev shell (`flake.nix`) so the Qt/Plasma versions match the target,
rather than relying on whatever `qmltestrunner` happens to be on the host. If
the repository stays NixOS-first, `nix flake check` is the natural CI entry
point. Add a GitHub Actions workflow that installs Nix and runs
`scripts/check.sh`.

### 9.6 Performance budget

Measured on the current real fixture (1.86 MB, 932 findings, Node 24,
indicative):

| Operation | Current | Target |
| --- | --- | --- |
| Read + parse on every poll | 34 ms, every 60 s / 3 s | skip read+parse when mtime is unchanged; <100 ms at 2,000 findings |
| Search haystack rebuild | 4.5 ms for 932 | precomputed per row; filter <16 ms |
| Sort | 0.7 ms | <16 ms at 2,000 |
| Group header counts | 24 ms O(n²) | <16 ms O(n) |
| Row delegate classification | repeated per binding | once per row build |
| Idle polling I/O | 1.86 MB/min | `stat` first; `cat` only on change |

Add a synthetic 2,000-row benchmark test in CI with generous thresholds; fail
only on a clear regression, not on noisy runner timing. Never optimize by
moving logic into a delegate or by caching translated strings globally.

---

## 10. Migration plan

Each phase is a series of small pull requests, each shippable. Keep the applet
runnable after every merge. Use the "strangler fig" pattern: add the new module,
make the old code delegate to it, test, then delete the old code.

| Phase | Effort | Risk | User-visible change |
| --- | --- | --- | --- |
| 0. Safety net | S-M | low | two bug fixes only |
| 1. Pure domain | M | low | none |
| 2. Services/lifecycle | M | medium | none |
| 3. State/view models | M | medium | none |
| 4. UI components | L | medium-high (visual) | none intended |
| 5. Cleanup/hardening | M | low | error states, accessibility |
| 6. Future work | ongoing | varies | new features |

### Phase 0 — Safety net (completed)

**Deliverables**

- `docs/architecture.md` (this document), `docs/status-schema.md`,
  `docs/testing.md`, `CONTRIBUTING.md`.
- `tests/fixtures/` with the sanitized v7 and legacy fixtures.
- `scripts/check.sh`, `scripts/test-domain.sh`, `scripts/test-qml.sh`.
- A `flake.nix` dev shell with Qt/Plasma QML tooling and Node.
- CI workflow; qmllint baseline artifact.
- Fix the two unambiguous defects (duplicate `pending`, wrong `compactLayout`
  reference) with regression tests in separate commits, so the suite is green
  before extraction begins.

**Exit criteria**

- `./scripts/check.sh` runs locally and in CI.
- The package builds and installs into a temporary packageroot.
- The current warning count is recorded, and new warnings fail CI.
- Only the two bug fixes above are user-visible; no layout or feature change.

### Phase 1 — Extract the pure domain (completed)

**Steps**

1. Add `domain/status.mjs`, `severity.mjs`, `fix.mjs`, `tracker.mjs`,
   `origins.mjs`, `filters.mjs`, `table.mjs`, `time.mjs`, `urls.mjs`.
2. Move functions verbatim, replacing `root.x` with explicit parameters.
3. Keep thin forwarding functions in `main.qml`:
   ```qml
   function fixBucket(item) {
       return Fix.classify(item, root.systemChannel).bucket;
   }
   ```
   The UI keeps calling the same names, so visual behavior cannot change in
   this phase.
4. Add domain tests per module and per state. Use the real fixture and a
   legacy fixture.
5. Delete the old implementations only after the forwarding wrappers are green.

**Exit criteria**

- `main.qml` is ~1,000 lines shorter.
- Domain tests cover every fix state, tracker state, filter, sort key and group
  rule.
- Manual smoke test shows no visual change.
- No `i18n`, QML or I/O in `domain/`.

### Phase 2 — Extract services and the scan lifecycle (completed)

**Steps**

1. Add `CommandRunner`, `StatusFileSource`, `ScanService`, `TrackerClient`,
   `AppSettings`, `Clock`, `ClipboardService`, `UrlService`.
2. Replace the `Plasma5Support.DataSource` block and prefix routing in
   `main.qml` with calls to those services.
3. Add `ScanStore` with phase, service adoption, timeout, hold/defer and
   fingerprints. Keep forwarding properties/functions for the UI.
4. Add fake-runner tests for routing, concurrency, timeout, exit codes and
   every scan transition.
5. Remove `statusRaw` retention; compare fingerprints.

**Exit criteria**

- No command string is constructed outside `services/`.
- No `sourceName.indexOf(...)` routing remains.
- The scan lifecycle is testable without systemd or real files.
- Manual smoke test includes: start scan, shell restart mid-scan, tracker
  progress, timeout, start failure.

### Phase 3 — Extract state and view models (completed)

**Steps**

1. Add `FindingsViewModel` with `FilterState`, sort, group, rows and counts.
2. Move table state and derived properties from `main.qml` to the view model.
3. Bind the UI to `store`/`vm` properties; remove the forwarding functions.
4. Add view-model tests with fake stores.
5. Keep the current array/list behavior; do not switch to `ListModel` yet.

**Exit criteria**

- `main.qml` is under ~600 lines and contains no filter/sort/group loop.
- Changing a filter causes exactly one row rebuild and one
  `rowsReset(preserveScroll=false)`.
- Counts and visible count agree with the domain tests.
- Manual smoke test on search, filters, package/origin drill-down and grouping.

### Phase 4 — Extract UI components (completed)

**Steps**

1. Add `SentinelTheme`, `Labels`, `EmptyState`, `TrackerHint`,
   `GroupHeader`, `RowContextMenu`, `FindingRow`.
2. Add `HeaderBar`, `ScanProgress`, `SummaryCards` and the three cards.
3. Add `FindingsToolbar`, `FindingsList`, `SentinelPopup`.
4. Add `pragma ComponentBehavior: Bound` and `required property` to every
   component; remove `root.*` accesses.
5. Switch grouping to flat rows; delete `ListView.section` and
   `originGroupCount`.
6. Centralize tooltips and let `FindingsList` own scroll/hover state.
7. Take before/after screenshots for light/dark, compact, grouped and filtered
   states.

**Exit criteria**

- `main.qml` is 120-180 lines and contains only applet metadata and wiring.
- No component imports `Plasmoid` or constructs a command.
- No `root.` inside a component.
- Visual parity verified; no intended visual differences (the two Phase 0
  fixes are already in).
- Component tests cover row rendering, card counts, empty states and signals.

### Phase 5 — Cleanup and hardening (completed)

**Steps**

1. Delete the dead column-width subsystem and the `columnWidths` key.
2. Delete the 26 unreferenced members and `filterRowVisible`.
3. Fix the remaining known defects and add regression tests:
   - stale diff fields (`fix_branches`, `origins.chains`, tracker URLs);
   - swallowed load errors.
   - keep the Phase 0 regression tests for the tracker summary and compact
     layout green through the refactor.
4. Add error states to the UI: missing, permission, corrupt, unsupported
   schema, start failure, timeout.
5. Add keyboard navigation and accessibility roles/names; test focus order.
6. Add `Messages.sh`, `po/`, pseudo-locale and RTL checks.
7. Add mtime-based read skipping and, if the backend can change, a separate
   tracker status file. Add the 2,000-row benchmark.
8. Update README/CHANGELOG; document the new architecture and test commands.

**Exit criteria**

- No known dead code.
- qmllint has no new warnings; domain coverage >=90% branches.
- 2,000-row parse/filter/sort/group within budget.
- Error states are visible and actionable.
- Light/dark, high-DPI, compact, RTL and pseudo-locale checks pass.

### Phase 6 — Future work (partially implemented)

- JSON Schema for `status.json` and contract tests against the backend.
- Split findings and tracker progress into separate files (different update
  frequencies) and read only what changed.
- Incremental `ListModel` or a C++ `QAbstractItemModel` if row count or hover
  churn justifies it.
- Persist sort/group/filter preferences in KConfig, with a versioned schema.
- Optional CMake/ECM packaging and a KDE CI image.
- Additional backends behind a `ScanBackend` interface, if the widget ever
  supports non-NixOS systems.
- History/trends, notifications and richer tracker detail (backend work).

### Definition of done

| Check | Target |
| --- | --- |
| `main.qml` | 120-180 lines; applet metadata and wiring only |
| Domain tests | every fix/tracker/filter/sort/group rule; >=90% branches |
| Component coupling | no `root.*`, `Plasmoid`, I/O or config in components |
| Dead code | no unreferenced members, no dead KConfig keys |
| Lint | no new qmllint warnings; changed QML clean |
| CI | lint, domain tests, QML tests, package, install smoke all green |
| Performance | 2,000 findings within the budget in 9.6 |
| Accessibility | keyboard path for search, rows, menus; roles/names present |
| Translations | all copy extractable; pseudo-locale and RTL checked |
| Manual QA | light/dark, compact, panel, multi-instance, restart, error states |

---

## 11. Risks and anti-patterns

| Risk | Mitigation |
| --- | --- |
| Visual regressions during UI extraction | Extract leaf components first; screenshot before/after; keep the old layout until parity is checked. |
| Behavior drift in fix logic | Move rules verbatim, add tests per state before deleting the old code, and never "improve" a rule during extraction. |
| QML JS engine differences | Keep domain to conservative ES2017; test with the production Qt/Plasma version; do not rely on Node-only APIs. |
| Test flakiness | No sleeps; inject `Clock`; fake services; deterministic fixtures; generous perf thresholds. |
| Over-abstraction | Cap the domain at the modules listed here; no generic framework, no C++ plugin, no state library. |
| Multiple applet instances | Per-instance `QtObject` state; no QML singleton stores. |
| Translations regress | Move copy in one commit; use full sentences and `i18np`; pseudo-locale check. |
| Hover/tooltip regressions | Keep the explicit hold/defer policy, centralize tooltips, manual QA with live tracker updates. |
| Packaging leaks tests | `package.sh` archives only `metadata.json` + `contents/`; CI asserts archive contents. |
| CI tool mismatch | Pin Qt/Plasma in a Nix dev shell; run the QML tests against the same minor version as the target. |
| Security | No token on command lines or logs; validate CVE against the existing regex; allow only `https` external URLs; keep commands in services. |

### What not to do

- Do not use a QML singleton for `ScanStore` or `FindingsViewModel`.
- Do not rewrite the applet in one branch; there is no test suite to catch the
  regressions.
- Do not put `i18n`, `Kirigami`, `Plasmoid` or `Timer` in domain modules.
- Do not make components read `root` or the applet's configuration.
- Do not add C++/CMake solely to get tests; `.mjs` + qmltestrunner is enough.
- Do not test against `/var/lib/vulnscan`, systemd or the network.
- Do not copy every finding object for grouping; build rows once and precompute
  counts.
- Do not reintroduce column resizing without a tested `TableColumns` module.
- Do not optimize the list model before profiling; correctness and tests first.

---

## Appendix A — Metrics

### Starting point (pre-refactor)

Measured before the refactor:

- `contents/ui/main.qml`: 3,625 lines, 152 KB.
- 201 top-level properties/functions; 82 functions.
- 2,196 lines before `fullRepresentation`; 1,428 lines of UI.
- 245 i18n calls (233 `i18n`, 2 `i18nc`, 10 `i18np`).
- 9 string filter fields plus search, severity band, sort and group.
- 8 `Timer` elements (6 runtime timers and 2 zero-interval scroll timers),
  plus animations and tooltips.
- 18 derived theme colors.
- 26 unreferenced top-level members; 1 write-only member; the entire
  column-width persistence path has no observable effect.
- qmllint (Qt 6.12): 752 `unqualified`, 24 `missing-property`, 6
  `unresolved-type`.
- No tests, fixtures, lint config, CI or translation catalog.
- Real fixture: 1.86 MB, 932 findings, 69 origin groups.
  - `JSON.parse`: ~34 ms.
  - search haystack build: ~4.5 ms.
  - sort: ~0.7 ms.
  - simulated section count: ~24 ms (O(n²)).
  - These are Node 24 numbers, indicative rather than QML-engine exact.


### Post-refactor

- `contents/ui/main.qml`: 130 lines, composition root only.
- 10 domain modules, 8 services, 2 state objects and 16 components.
- 57 Node domain tests, 33 qmltestrunner service/state tests.
- qmllint (Qt 6.12): 175 warnings, down from 752 unqualified accesses,
  24 missing properties and 6 unresolved types; the remaining warnings are
  mostly context properties (`Plasmoid`, `i18n`, `Qt`) and `Loader.item`
  dynamic properties.
- Idle polling reads `status.json` only when `stat -c '%y:%s'` changes.
- Grouping is a single O(n) pass; filtering and sorting use precomputed rows.
- The column-width config key and all unreferenced legacy members are gone.
- The known tracker summary, compact-layout, stale-fingerprint and polling-gate
  defects are fixed and covered by the new tests.


## Appendix B — Concrete defects found and fixed

These were found during the audit; the fixes and their regression tests are in
the refactor commits.

1. **Duplicate `var pending`** in `trackerSummaryText` (lines 459 and 462).
   The second declaration (fix progress) overwrites the tracker pending count,
   so "N pending review" uses the fix-pending count. On the current fixture
   the tracker reports 409 pending, while the fix-progress count is 21. Add a
   test that asserts both counts independently.
2. **`root.compactLayout`** (line 2303) is defined on `fullRoot` (line 2297),
   not on the applet root. The header inset reads `undefined` in compact mode.
   Use `fullRoot.compactLayout` and cover the compact threshold in a manual or
   component test.
3. **Stale diff fields.** `sameTracker` ignores `fix_branches`,
   `matched_package`, `system_known`, `fix_url`, `master_url`,
   `suggestion_packages` and `affected_products`; `sameVulnerabilities` ignores
   `origins.chains` and `origins.store_paths`. A tracker update can therefore
   be dropped by `mergeStatus`, leaving tooltips stale. Fingerprints over the
   display-relevant fields fix this class of bug.
4. **Silent load failures.** A failed `cat` is ignored entirely, and a malformed
   JSON only logs `console.warn`; the popup keeps showing the old state (or "Not
   scanned yet"). Add `LoadError` states and user-visible messages.
5. **Raw file retention.** `statusRaw` keeps a second 1.8 MB string. Keep only
   the fingerprint.
6. **Prefix-based command routing.** `onNewData` dispatches by
   `sourceName.indexOf(...)`; concurrent or duplicate commands can lose
   callbacks, and error handling depends on command text. Use `CommandRunner`
   callbacks.
7. **Dead column resizing.** The dead code and config entry were removed during the refactor.
8. **Write-only `filterRowVisible`.** It is set by `showPackage`/`showOrigin`
   and never read. Remove it or use it.
9. **In-place tracker map + revision counter.** `trackerChecked[cve] = true`
   followed by `trackerRevision += 1` is a binding workaround. Use an immutable
   map/revision object so the dependency is explicit.
10. **String-concatenated translated sentences.** Tracker progress builds
    sentences from translated fragments; use complete messages and plural
    forms.
11. **Tracker polling is gated on the scan service.** The fast timer requires
    `trackerBusy && scanServiceActive`, but the tracker is started as a
    separate service in `ExecStartPost`; after the oneshot scan exits,
    `scanServiceActive` is false. The live tracker window can therefore fall
    back to 60 s. Gate the fast poll on tracker state and freshness instead,
    and test the service/tracker state combinations.

## Appendix C — Recommended first PRs

1. `docs: add architecture, schema and testing proposals`
2. `test: add sanitized v7/legacy fixtures and domain test harness`
3. `refactor(domain): extract severity and time rules with tests`
4. `refactor(domain): extract origins and tracker classification with tests`
5. `refactor(domain): extract fix classification with a test per state`
6. `refactor(domain): extract filters, sorting and grouping`
7. `refactor(io): add CommandRunner, StatusFileSource and ScanService`
8. `refactor(state): add ScanStore with fingerprints and scan phase`
9. `refactor(state): add FindingsViewModel and bind the toolbar/list`
10. `refactor(ui): extract theme, labels, cards, toolbar and list`
11. `fix: stale diff fields and load-error states`
12. `chore: remove dead column-width and filter code; add CI/translation checks`

Keep each PR reviewable: move code, do not change it; add tests in the same PR;
include a manual QA note and, for UI PRs, before/after screenshots.

---

## References

- Qt QML JavaScript / ECMAScript modules:
  <https://doc.qt.io/qt-6/qtqml-javascript-imports.html>
- Qt Quick Test (`qmltestrunner`):
  <https://doc.qt.io/qt-6/qtquicktest-index.html>
- KDE Plasma widget development:
  <https://develop.kde.org/docs/plasma/widget/>
- KConfigXT configuration:
  <https://develop.kde.org/docs/features/configuration/kconfig_xt/>

