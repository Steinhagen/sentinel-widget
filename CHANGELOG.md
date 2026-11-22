# Changelog

All notable changes to Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a complete Romanian translation (`translate/ro.po`), compiled to
  `contents/locale/ro/LC_MESSAGES/plasma_applet_io.github.steinhagen.sentinel.mo`
  and loaded through Ki18n like any other Plasma applet.
- Added `translate/merge.sh` and `translate/build.sh` for refreshing the gettext
  template and rebuilding the catalogs, plus `scripts/test-i18n.sh` to fail CI on
  untranslated, fuzzy or stale catalogs.
- Added a Romanian widget description in `metadata.json`.
- Added `tools/triage.mjs`, a post-scan pass that re-derives each finding's
  identity from the CVE record and classifies it as `confirmed`, `unverified` or
  `suppressed`; documented in `docs/triage.md`.
- Added `tests/tools/triage.test.mjs` to the `node --test` suite.
- Added a **REVIEW** chip to unverified findings. Its tooltip names the CVE's
  vendor and product, and the toolbar count now shows hidden entries as
  `(+ N false positives)`.
- Added **Ignore this finding (false positive)** to the row context menu and
  an ignored-findings section in the settings page with **Restore all**. The
  list lives in the applet configuration and applies even when triage verdicts
  are disabled.
- Added `--ignore` to `tools/triage.mjs` and a
  `/var/lib/sentinel/triage-ignore.json` dismissal list for product-name
  collisions no rule can resolve; a tracker-confirmed verdict still wins.
- Added a **Triage verdicts** setting (enabled by default) that hides findings
  classified as false positives, plus the hidden count in the toolbar. Verdicts
  come from `/var/lib/sentinel/triage.json` or from a `verdict` field on the
  finding.

### Changed

- The findings list, summary cards, counts and panel badge now honor triage
  verdicts; `unverified` findings stay visible.

- Replaced the unused `Messages.sh` / `po/` stubs with the working `translate/`
  gettext setup.
- Pluralized the package and CVE counters on the summary cards with `i18np`.
- Localized the tracker issue state shown next to a security issue.

## [0.2.0] - 2026-11-22

### Added

- Added a compact, click-to-sort header for CVSS, CVE, Package and Fix, with an
  arrow showing the active sort direction.
- Added a grouped findings view with Priority, Package and Origin section
  headers. Each finding keeps the two-line row layout.
- Added a current-state **Group by** menu button, individually collapsible
  group headers, a global expand/collapse control, and a sortable group column
  bar.
- Added an advanced **Filter** popover for CVE, package and origin, with
  severity and fix-state controls shown when the summary cards are hidden.
- Added removable chips below the toolbar for every active search, CVE,
  package, origin, severity and fix-state filter, including filters set by
  clicking a package or origin in a row.
- Added explicit load-error, scan-error and newer-schema states.
- Added 60 Node domain tests, 26 QML test functions, sanitized v7/legacy
  fixtures, a 2,000-row performance budget and CI checks.

### Changed

- Refactored the applet into layered `domain` (pure `.mjs`), `services`,
  `state` and `components` modules. `main.qml` is now a ~130-line composition
  root instead of a 3,625-line monolith.
- Replaced the wide column table with a two-line findings list carrying the
  CVSS score, CVE, package and version, fix status, and the full
  dependency-origin chain.
- Renamed the backend contract to Sentinel: `/var/lib/sentinel`,
  `sentinel.service`, `system/sentinel.nix`, `system/sentinel-status.py` and
  the `sentinelTrackerToken` setting.
- Reworked the **READY TO FIX** card to mirror the Severity card with a stacked
  fix-state bar and clickable Fixed/Pending/No fix/Unknown/n/a rows.
- Increased dashboard card height and spacing, enlarged card titles, and
  included n/a in the fix breakdown.
- Moved post-scan tracker progress into the header next to the scan timestamp;
  tracker warnings are now a small icon with a detailed tooltip.
- Merged scan and tracker progress into one header slot: the scanner animates
  the bar, tracker checks fill it, and the separate scanner spinner is gone.
- Aligned the header content, toolbar and findings table to the fixed card-row
  width, then centered the card row so the panel padding is symmetric.
- Gave every finding row a consistent minimum height and more vertical padding,
  including rows without an origin chain.
- Colour-coded fix pills (green fixed, amber pending/staging, red no fix, grey
  unknown/n/a) and sized them to the longest fix-state label.
- Skipped reading `status.json` when its mtime and size are unchanged.
- Restored the list/group icon and normal toolbar font size on the grouping
  menu, and styled it as a flat button with a chevron.

### Fixed

- Fixed the tracker pending count and the tracker polling gate.
- Fixed stale tracker fingerprints being retained across scans.
- Fixed the compact-layout inset.
- Fixed the search field losing focus after the first keystroke by disabling
  SearchField auto-accept for live filtering.
- Fixed the table overflowing the popup when the summary cards were hidden;
  it now keeps the card width in both layouts.
- Fixed **Review fixes** leaving an unclearable filter by using the explicit
  fix-state filter and resetting the legacy per-column field.
- Fixed the critical-exposure ring, whose arc is now proportional to the
  highest CVSS score instead of a fixed 78%.
- Fixed CVSS score centering and the severity-strip spacing in each row.
- Fixed the indeterminate scan sweep drawing outside its header track.
- Restored the Scanning state after a shell restart by checking
  `systemctl is-active`; stale tracker progress is hidden and an interrupted
  scan is flagged.
- Hid the summary cards when the popup is too short so they cannot overlap the
  findings list.

### Removed

- Removed the column header row, per-column filter row, severity chips, detector
  column and column resizing from the old table.
- Removed the dead column-width configuration and unused legacy members.
- Removed the **Top origin** card to narrow the dashboard; origins remain in
  finding rows and group-by-origin mode. Reduced the default/minimum width from
  50 to 36 grid units.
- Removed the duplicate **Review fixes** link from the critical-exposure card;
  the fixes card owns that action.
- Removed the report, scan-log and About buttons from the header; report and
  log remain in the context menu, and help moved to the summary tooltip.

## [0.1.0] - 2026-11-22

### Added

- First standalone release of **Sentinel**. Version numbering restarts at
  0.1.0 for this repository.
- Published the applet as **Sentinel**: `KPlugin.Id` is
  `io.github.steinhagen.sentinel` and `KPlugin.Name` is `Sentinel`.

### Changed

- Unified the scan timestamp into the single header label next to **Scan now**.
  Relative time is shown inline; the exact local time is in its tooltip.

### Removed

- Dropped the footer bar. Its report, scan-log and help actions moved into the
  header; its finding count was already duplicated in the search toolbar.
- Removed the duplicate timestamp from the summary line, footer and secure-state
  explanation.

## [1.8.0] - 2026-11-21

### Added

- Standalone source snapshot of the Sentinel / System Vulnerability Status
  Plasma applet.
- Four-card security dashboard: risk, severity, available fixes and top origin.
- Sortable and filterable findings table with severity chips, persistent column
  widths and an always-visible scrollbar.
- Automatic light/dark theming through `Kirigami.Theme`.
- Dependency-origin data and Nixpkgs security tracker integration.
