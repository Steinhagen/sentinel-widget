# Sentinel table — ten design directions

Mockups use the same findings as the current widget. Open
[table-redesigns.html](table-redesigns.html) for the full gallery or
[table-redesigns.png](table-redesigns.png) for a single-page overview.
Individual images are `table-01.png` … `table-10.png`.

## Shared decisions

All ten remove the two heaviest pieces of chrome:

- the per-column filter header row;
- the `All 932 / Critical 34 / High 252 / …` severity chips, which duplicate
  the severity card above.

They keep the three answers the user needs at scan time:

1. **How bad** — CVSS score plus the severity band through colour.
2. **What is vulnerable** — package name **and installed version**.
3. **What put it there** — the dependency origin, so an overlay or bundled
   runtime is immediately visible.

Detector/confidence and tracker links are secondary: hover, expand, or a detail
pane. Fix state is a small pill at the end of the row in designs 02 and 04.

## The ten directions

| # | Design | What it is best at |
|---|--------|--------------------|
| 01 | [Essential three](table-01.png) | Fast one-line scanning; no chrome at all |
| 02 | [Two-line rows](table-02.png) | Same first-line grid as 04, with the full origin chain on line 2 |
| 03 | [Severity sections](table-03.png) | Top-down triage; groups replace the severity chips |
| 04 | [Group by origin](table-04.png) | Origin as the section header, with fix state in the last column |
| 05 | [Group by package](table-05.png) | Patch planning; one package/version with all its CVEs |
| 06 | [Ticket cards](table-06.png) | Touch/low-density; one finding per card |
| 07 | [Master–detail](table-07.png) | Investigating one finding without wide columns |
| 08 | [Dense console](table-08.png) | Maximum rows for power users |
| 09 | [Severity board](table-09.png) | Visual overview across Critical/High/Medium |
| 10 | [Expandable rows](table-10.png) | Quiet summary; details on demand |

## Recommendation

Use **02 (two-line rows)** as the default, add **04 (group by origin)** as an
optional grouping switch, and borrow **10**'s expansion for detector/tracker
detail. Replace the header/filter row with one search field plus a single
**Filters** popover.

## Progress indicator directions

Five header mockups for the scanning/tracker progress, in the same dark
context: [gallery](progress-indicators.html) · [overview](progress-indicators.png).

| # | Design | What it is best at |
|---|--------|--------------------|
| 01 | [Slim inline bar](progress-01.png) | Exact progress + count in minimal space |
| 02 | [Determinate ring](progress-02.png) | Replacing the spinner while keeping a percentage |
| 03 | [Segmented ticks](progress-03.png) | Discrete scanner phases at small sizes |
| 04 | [Progress-filled action](progress-04.png) | Tight header space; the button is the indicator |
| 05 | [Top-edge loading line](progress-05.png) | Almost invisible; best for the scan phase |

**Recommendation:** 01 for the tracker (determinate) with an indeterminate
shimmer during the scan itself; 05 if the header should stay completely clean.

## Grouping control — the flat (ungrouped) state

The current toolbar shows an empty **Group by** label when no grouping is
selected. Five directions for making that state explicit and visually
intentional: [gallery](grouping-empty-states.html) ·
[overview](grouping-empty-states.png).

| # | Design | What it is best at |
|---|--------|--------------------|
| 01 | [Current-state split button](grouping-empty-states.png) | Always names Flat/Package; compact |
| 02 | [Segmented view switcher](grouping-empty-states.png) | Every mode one click away; widest |
| 03 | [View menu](grouping-empty-states.png) | Most compact; complete mode label |
| 04 | [Group chip with Off state](grouping-empty-states.png) | Clearest on/off while keeping “Group” |
| 05 | [Group switch + selector](grouping-empty-states.png) | Most explicit; most chrome |

**Recommendation:** 01 — the split button always shows the active state
(“Flat”, “Package”, …) and keeps the existing menu. 03 is the compact fallback
if a single menu button is preferred over a split control.

**Implemented:** 01, as the current-state split button in the applet toolbar
(without the leading icon; the toolbar Filters button is hidden when the
summary cards are visible).

## CVSS exposure card — ring vs scale

Two ways to fix the exposure ring, which currently draws a fixed 78% arc
instead of mapping the score: [gallery](cvss-ring-directions.html) ·
[overview](cvss-ring-directions.png).

| # | Direction | What it is best at |
|---|-----------|--------------------|
| 01 | [Proportional CVSS ring](cvss-ring-directions.png) | Keeps the current circle; arc maps `maxSeverity / 10` |
| 02 | [CVSS band scale](cvss-ring-directions.png) | Explicit score, 0–10 position and severity band |

**Recommendation:** 02 for readability at this card size; 01 if the circle is
part of the visual identity and near-maximum scores can look almost full.

**Implemented:** 01, with the arc driven by `maxSeverity / 10`.

## Review markers

[review-queue.html](review-queue.html) explores how to identify the false
positives in the list: an amber marker, a **Needs review** filter, and a review
queue grouped by the CVE's vendor → product so a cluster can be dismissed at
once. [review-markers.html](review-markers.html) compares five placements for
the marker without dropping the dependency-origin line; the widget uses the
**REVIEW** chip from variant 4, moved into its own column between the
package and the fix state, with the CVE's vendor → product in its tooltip.

## Review and false-positive states

[review-states.html](review-states.html) · [overview](review-states.png)
explores five ways to show the triage state when the **Triage verdicts**
setting is off, so suppressed false positives are visible alongside the
needs-review rows. The current triage column is now V2: icon-only, centered and
sortable. It is hidden when both **Triage verdicts** and **Unverified findings**
are on. The V4 setting bar is not implemented.

| # | Design | What it is best at |
|---|--------|--------------------|
| V1 | [Dual pill in the Triaj column](review-states.png) | Smallest change; explicit; sortable |
| V2 | [Icon-only Triaj column](review-states.png) | Saves ~3 grid units; still sortable |
| V3 | [Status dot next to the CVE](review-states.png) | Maximum width; sorting moves to a menu |
| V4 | [Triage bar + inline suffix](review-states.png) | Explains when false positives are shown or hidden |
| V5 | [Group by triage / review queue](review-states.png) | Bulk workflow for many findings |

**Implemented:** V2, the icon-only triage column. V4's bar remains the
recommended follow-up for the setting state; V3 if the package/origin width is
the priority.
