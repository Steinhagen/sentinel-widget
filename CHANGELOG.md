# Changelog

## Unreleased

- Replace the wide column table with a two-line findings list: CVSS score,
  CVE, package + version, fix status, and the full dependency-origin chain.
  Removed the column header row, per-column filter row, severity chips, the
  detector column and column resizing.
- Add an optional **Group by origin** mode with origin section headers; rows
  use the same layout and keep the fix status in the last column.
- Make the group toggle icon-only and non-toggleable: the list icon in flat
  mode, the grouped/tree icon in origin mode, with the tooltip naming the
  action.
- Move severity and fix-state filtering into one compact **Filters** menu.
- Colour-code the fix pills: green for fixed, amber for pending/staging, red
  for no fix, grey for unknown/n/a.
- Give every fix pill the same width, sized to the longest fix-state label,
  and centre the text inside it.
- Give each row a consistent minimum height and more vertical padding, so
  rows without an origin chain remain comfortable and easy to click.
- Move post-scan tracker progress to a compact indicator next to the
  last-scan timestamp and remove the bottom progress row. Tracker warnings
  appear as a small icon with the detail in its tooltip.
- Remove the **Top origin** card to make the dashboard narrower; origins remain
  visible in the findings list and group-by-origin mode. Reduce the
  default/minimum width from 50 to 36 grid units.
- Remove the duplicate **Review fixes** link from the critical-exposure card;
  the fixes card owns that action. Keep all three cards at their natural
  widths and centre them so no card absorbs the spare width.
- Remove the report, scan-log and About buttons from the header. Report and log
  stay in the context menu; the About/help text moves to the summary tooltip.
  Shrink the risk card slightly to match the narrower panel.
- Fix “Review fixes” leaving an unclearable filter: it now uses the explicit
  fix-state filter, and Clear filters also resets the legacy per-column field.
- Centre the CVSS score in its column and add the 3 px severity strip to the
  row padding, so the score has equal space on both sides.
- Hide the summary cards when the popup is too short, so they cannot
  overlap the findings list.

## 0.1.0 — 2026-11-22

- First standalone release of **Sentinel**; the version numbering restarts at
  0.1.0 for this repository.
- Publish the applet as **Sentinel**: `KPlugin.Id` is now
  `io.github.steinhagen.sentinel` and `KPlugin.Name` is `Sentinel`.
- Unify the scan timestamp: the header label next to **Scan now** is the only
  place it is shown (relative time, exact local time in its tooltip). Removed
  the timestamp from the summary line, the footer bar and the secure-state
  explanation.
- Drop the footer bar. Its report, scan-log and help buttons moved into the
  header; its finding count was already duplicated in the search toolbar.

## 1.8.0 — 2026-11-21

- Standalone source snapshot of the Sentinel / System Vulnerability Status
  Plasma applet.
- Four-card security dashboard (risk, severity, available fixes, top origin).
- Sortable/filterable table with severity chips, persistent column widths and
  an always-visible scrollbar.
- Automatic light/dark theming through `Kirigami.Theme`.
- Dependency-origin data and Nixpkgs security tracker integration.
