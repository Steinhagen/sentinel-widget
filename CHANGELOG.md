# Changelog

## Unreleased

- Refactor the applet into layered `domain` (pure `.mjs`), `services`,
  `state` and `components` modules; `main.qml` is now a ~130-line composition
  root instead of a 3,625-line monolith.
- Add 59 Node domain tests, 25 qmltestrunner test functions, sanitized
  v7/legacy fixtures, a 2,000-row performance budget and CI checks.
- Skip reading `status.json` when its mtime/size is unchanged.
- Add explicit load-error, scan-error and newer-schema states.
- Remove the dead column-width configuration and unused legacy members.
- Fix the tracker pending count, compact-layout inset, stale tracker
  fingerprints and tracker polling gate.

- Replace the wide column table with a two-line findings list: CVSS score,
  CVE, package + version, fix status, and the full dependency-origin chain.
  Removed the column header row, per-column filter row, severity chips, the
  detector column and column resizing.
- Add a grouped findings view with section headers for Priority, Package or
  Origin; every finding row keeps the flat two-line layout.
- Add a **Group by** menu and a global plus/minus control to show or hide all
  findings in the grouped view. Group headers are individually clickable and
  have a larger hover/click target.
- Add a group column bar with the expand control, sortable group names and
  sortable finding counts, above the normal table header. The Group by button
  is a current-state split button (Flat / Priority / Package / Origin), so the
  ungrouped state is no longer blank.
- Hide the toolbar Filters button while the summary cards are visible, since
  the severity and fix-state card rows provide the same choices.
- Disable SearchField auto-accept so live filtering no longer blurs the search
  field after the first keystroke.
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
- Merge scan and tracker progress into one header slot: the scanner animates
  the bar, tracker checks fill it, and the separate scanner spinner is gone.
- Recover the Scanning state from `systemctl is-active` after a shell restart;
  hide stale tracker progress and flag an interrupted scan when the service is
  no longer running.
- Clip the indeterminate scan sweep to its header track so it cannot draw
  over the timestamp or the Scan button.
- Add a compact click-to-sort column header for CVSS, CVE, Package and Fix,
  with an arrow showing the active sort direction.
- Align the toolbar and findings table to the combined width of the three
  cards instead of the full popup width.
- Inset the header content to the cards' width so the logo and Settings button
  line up with the outer card edges.
- Center the card row as a fixed-width group, matching the toolbar and table,
  so the application's left and right padding are symmetric.
- Redesign the READY TO FIX card to mirror the Severity card: title, stacked
  fix-state bar, and five clickable rows (Fixed/Pending/No fix/Unknown/n/a)
  with the same padding and row rhythm. The Fixed row filters to fixes.
- Increase the dashboard card height and spacing, enlarge the small card
  titles, and include n/a in the fix breakdown so the cards read more
  comfortably.
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
