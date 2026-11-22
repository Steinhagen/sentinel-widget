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

**Implemented:** 01, as the current-state split button in the applet toolbar.
