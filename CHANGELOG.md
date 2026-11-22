# Changelog

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
