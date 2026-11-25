# Changelog

All notable changes to Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-26

### Added

- The scanner backend and its systemd units now ship in this repository:
  `nixosModules.default` installs the applet, the scan service and the tracker
  service, and `services.sentinel.enable` turns them on. The applet and the
  backend always come from the same revision.
- `tools/triage.mjs --embed` writes the triage verdicts into `status.json`, so
  the applet reads a single file; the tracker pass runs it automatically.
- Each finding row now shows the Nixpkgs source the system was built from
  (channel and revision, e.g. `nixos-unstable (2786a2a)`) under the CVE, and
  the dependency-origin chain moved under the package name. The source comes
  from a new top-level `source` object in `status.json`; a per-finding `source`
  overrides it.

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
- Added a triage icon column: amber **!** for unverified findings, green
  **✓** for confirmed ones, and red **⊘** for the suppressed false positives
  shown when the setting is off. The header is sortable; the tooltip names the
  CVE's vendor and product, and the toolbar count shows hidden entries as
  `(+ N false positives)`.
- Added an **Unverified findings** setting, enabled by default, that hides
  findings the triage pass could not confirm. When it and **Triage verdicts**
  are both on, the Triaj column is hidden; the toolbar count now reports all
  hidden rows as `(+ N hidden findings)`.
- Added an **OSV advisories** setting, enabled by default, that hides all
  findings whose id starts with `OSV-`. The toolbar count includes them as
  hidden findings.
- Added **Ignore this finding (false positive)** to the row context menu and
  an ignored-findings section in the settings page with **Restore all**. The
  list lives in the applet configuration and applies even when triage verdicts
  are disabled.
- Added `--ignore` to `tools/triage.mjs` and a
  `/var/lib/sentinel/triage-ignore.json` dismissal list for product-name
  collisions no rule can resolve; a tracker-confirmed identity still wins over
  a manual dismissal, but the installed version and channel fix still decide.
- Added a **Triage verdicts** setting (enabled by default) that hides findings
  classified as false positives, plus the hidden count in the toolbar. Verdicts
  come from `/var/lib/sentinel/triage.json` or from a `verdict` field on the
  finding.

### Changed

- The findings list, summary cards, counts and panel badge now honor triage
  verdicts; the new **Unverified findings** setting (on by default) hides
  `unverified` rows as well.
- The triage pass now checks language bindings against the C library version
  they link instead of the binding's package version. Hackage `zlib` 0.7.1.1 is
  compared with the linked zlib 1.3.2, so CVE-2023-45853 and similar C zlib CVEs
  are no longer confirmed against the Haskell binding.
- The triage pass now treats CMS module-name collisions separately: a Drupal
  `Diff` CVE against the Haskell `Diff` package is suppressed as
  `ecosystem-mismatch`; an unknown or PHP package stays `unverified`
  (`cms-module-cve`). `docs/triage.md` documents the rule tables, worked
  examples and verdict reasons.
- Tracker-published findings are now checked against the installed version and
  the tracker's channel fix. A fixed brotli 1.2.1 is suppressed as
  `tracker-fixed`; a gnutls 3.8.13 outside the CVE range is suppressed as
  `version-not-affected`. CVE 5.1 `packageName` entries are parsed as product
  names when vendor/product are absent.
- The tracker now selects versioned nixpkgs attributes by the longest matching
  version prefix (`ffmpeg` 8.1.3 → `ffmpeg_8`, `openssl` 1.1.1w →
  `openssl_1_1`, `libressl` 4.2.1 → `libressl_4_2`) instead of the bare
  package name. A legacy or vendored attribute stays **no fix** even when the
  default package is fixed; the fix tooltip names the matched tracker package.
- The exposure card now follows the actual CVSS band: a maximum of 8.8 shows
  **High exposure** in orange (the same band as the severity list), not
  **Critical exposure**; only 9.0+ uses the critical title and colour.
- The dependency-origin tooltip is now a structured card instead of a plain
  text block: origin chips, numbered trails with package/version chips, a
  highlighted vulnerable last step and a separate hint footer.

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
- Added a **CVE** grouping mode: findings with the same CVE (or OSV) id are
  shown under one header, with the usual expand/collapse and group sorting.
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

- Every package chip in an origin trail is clickable, not only the main
  origin chip; clicking a step filters by that package's version-less name.
  The origin search index now includes every raw and version-less chain node,
  so a trail chip matches all findings whose paths contain it instead of only
  findings whose origin name happens to match.
- The origin card no longer repeats the origin chips in the header; it shows
  an origins/trails summary instead, and the trails are flat rows separated by
  hairlines rather than nested cards.
- The origin hover card is more compact without losing the header icon or the
  richer step chips: the origin label and trail count share the header row,
  trail numbers are inline instead of a separate column, and the cards, chips
  and footer use tighter padding and a narrower width.
- The Fix pill now opens a structured card with a package/state header, a
  compact per-branch table, a one-line summary and tracker/fix actions. The
  old plain-text tooltip is gone, and it no longer repeats the dependency
  origin; the origin line has its own overlay. Tracker and channel are shown
  as separate labelled chips.
- The CVE and Package headers now carry sortable **Nixpkgs** and **Origin**
  sub-labels next to them, so the source and dependency-origin fields can be
  sorted without widening the table.
- Six custom SVG severity shields (`sentinel-severity-*`) in
  `contents/icons`, installed into the hicolor icon theme. The panel icon
  shows critical/high/medium/low/secure/unknown with distinct colours and
  symbols. The shields use a bolder silhouette and symbol; critical uses a
  deeper red for better white-symbol contrast.
- The header tile is tinted with the severity colour and shows the matching
  severity shield; the white brand shield on the blue tile remains an
  alternative.

### Fixed

- Ignored findings now have their own settings category. The page lists every
  CVE/package/version entry with a per-entry restore button, plus Restore all;
  old versionless entries show “all versions”.
- Restore a padded click target around the hide/restore eye so its hover and
  focus box no longer overlaps the icon. The triage column gets a matching
  left margin, keeping the two visual gaps around the badge equal.
- Tighten the gap around the Triage badge and the hide eye. The triage column
  keeps just enough width for its header, and the eye uses exactly its icon
  width, so the two gaps around the badge are equal.
- The Remediation column now comes before the Triage column, placing the
  triage badge next to the hide/restore eye. Both list headers and finding
  rows use the same order.
- The Triage column now stays visible in the normal findings view as well as
  the hidden view, so a restored finding keeps its verdict visible.
- The hidden-findings count opens a dedicated hidden view. It lists the
  findings hidden by triage, OSV or manual ignores, and the normal-eye action
  restores one to the main list (forced-visible override). Ignoring a restored
  row removes that override again.
- Ignoring a finding now records its version, so hiding one `ffmpeg 6.1.6`
  row no longer hides the 8.1.3 and 9.0.2 rows. A package bump makes the
  finding visible again for review. Old versionless ignores stay package-wide,
  and the settings page lists each entry with its version and a restore action.
- Each finding row now has a `view-hidden` quick action at its far right.
  It uses the same ignore path as the context menu and shows the existing
  false-positive tooltip; the list header reserves the same empty slot.
- The applet no longer shows the raw scan report while the tracker/triage pass
  is still running: a report is held back until its triage verdicts are
  embedded. The false "The last scan did not finish" warning is gone; tracker
  progress is shown instead, and a triage failure is reported explicitly.
- Branch verification now detects upstream fix hashes in the Nixpkgs package's
  `patches` list. A branch at the same version is `unaffected` when it carries
  the tracker's fix commit, so `alsa-lib` master is fixed by a backport while
  release-26.05 remains affected. Master and release branches are probed at
  their current heads instead of trusting the tracker's stale `src_position`.
- Branch rows in the fix card are now clickable and open the package file at
  the version line on the selected branch. Master/release rows use the
  tracker's source-position anchor; channels and staging rows use the line
  found by the branch probe.
- The fix card now shares the origin card's visual language: a header icon
  tile, package title and state pill, the same section hairline and an
  origin-style footer surface with the ↗ action marker.
- Branch status now follows the Nixpkgs fix flow: if master is affected and
  `nixos-unstable`/`staging`/`staging-next` have the same or an older version,
  they are affected too. A `nixos-XX.YY` channel follows its
  `release-XX.YY` branch. This replaces "unknown" rows for bison 3.8.2 with
  affected rows; a branch with a newer version stays unknown because a fix may
  be in progress there.
- The first summary card no longer shows the tracker's queried-CVE count
  (`tracker.cves`) as if it were the number of unique CVEs in the report. It
  counts distinct finding IDs among the visible findings; the tracker count
  stays a tracker-progress metric.
- Fix-range evaluation is now release-line aware. A CVE with separate
  affected ranges for several lines (for example OpenSSL `<4.1.1`,
  `<3.5.10`, `<4.0.4`) no longer marks a newer 3.6.x version as affected by
  comparing it against the 4.x ceiling. OpenSSL 3.6.5 is correctly seen as
  fixed by the `<3.5.10` range, so the release-26.05 branch row becomes
  `unaffected`.
- The panel shield now uses the custom four-level severity set: red for
  critical, orange for high, yellow for medium, green for low; secure is a
  green check and unknown is grey. Previously every vulnerable report used
  the red `security-low` shield.
- The header tile now uses a severity tint instead of the blue brand tile,
  avoiding the clash between the coloured shield and the blue background.
- Expanding or collapsing a group keeps the findings list at the same scroll
  position instead of jumping back to the top.
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
