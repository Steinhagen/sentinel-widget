# Sentinel

A KDE Plasma 6 widget for **NixOS** that turns the latest vulnerability scan
into a compact security dashboard.

This repository contains both halves: the Plasma applet and the scanner
backend, wired together by a NixOS module (`nix/module.nix`). On NixOS you
import the flake module and enable the service; the applet is installed from
the same revision, so the two cannot drift apart.

## Features

- Three dashboard cards: highest CVSS score, severity mix, and available fixes
  with a fix-state breakdown.
  Dependency origins are shown in the findings list and group-by-origin mode.
- Two-line findings list: CVSS score, CVE, package + version, fix status, with
  the dependency-origin chain aligned under the package and the Nixpkgs source
  (channel and revision, e.g. `nixos-unstable (2786a2a)`) under the CVE.
- Compact click-to-sort header for CVSS, CVE, Package, Fix, Nixpkgs source
  and dependency origin, with direction arrows.
- Flat list by default, with a current-state **Group by** split button
  (Flat / Priority / Package / CVE / Origin), individually clickable group headers
  and a global expand/collapse control.
- The grouped view adds a second header bar for expand/collapse, group-name
  sorting and finding-count sorting.
- Search plus a **Filter** popover for CVE, package, origin, severity and fix
  state. Active filters appear as removable chips under the toolbar.
- The cards, toolbar and findings table share one centered width.
- The header logo and Settings button align with the outer card edges.
- Table scrolls independently.
- A single scan timestamp in the header: relative time, with the exact time on
  hover.
- One header progress bar for both phases: animated while scanning, then
  determinate during the tracker check.
- Resumes the Scanning state after a plasmashell restart by checking the scan
  service; stale tracker progress is flagged instead of shown as active.
- Light and dark themes follow the system color scheme automatically.
- Romanian translation, with the gettext catalog shipped inside the package.
- Panel badge can show the finding count, a dot, or nothing.
- Links to the Nixpkgs security tracker and optional tracker API token.
- Fix-in-progress tracking (`fixed`, `pending`, staging, etc.) from the backend.

## Requirements

- **KDE Plasma 6** and Qt 6.
- **NixOS** with flakes, for the backend. The applet alone is a dashboard; the
  scan needs root and the vulnerability databases.

### NixOS

```nix
inputs.sentinel-widget.url = "github:Steinhagen/sentinel-widget/main";

{
  imports = [ inputs.sentinel-widget.nixosModules.default ];

  services.sentinel = {
    enable = true;
    user = "alice";   # whose applet settings hold the tracker token
    # The NixOS release is not the channel; set the channel you update from.
    channel = "nixos-unstable";
  };
}
```

That is the whole recipe. The module installs the applet and two services:

- `sentinel.service` — runs the scan when **Scan now** is pressed or from the
  daily timer, and writes `/var/lib/sentinel/status.json`;
- `sentinel-tracker.service` — checks the findings against the Nixpkgs security
  tracker, then folds the triage verdicts into the same `status.json`.

The first scan downloads the vulnerability databases; the first tracker pass
can take a while without an API token. The applet picks the report up on its
own timer.

### Source detection

Sentinel never derives the channel from `system.nixos.release` alone: on
unstable that release is the upcoming NixOS release too. The channel is
system-wide and is used for every Nixpkgs package in the closure.

- **NixOS with channels** — set the channel you update from:
  ```nix
  services.sentinel.channel = "nixos-unstable";  # or "nixos-26.11"
  ```
- **NixOS with flakes** — use the branch of your `nixpkgs` input, e.g.
  `channel = "nixos-unstable"`. Set `flake` if the input is named differently
  (default `"nixpkgs"`). If you leave the channel unset, Sentinel selects a
  channel only when its resolved revision exactly matches
  `system.nixos.revision`; otherwise it shows `nixpkgs (<rev>)` rather than
  guessing a stable channel.
- **Non-NixOS with Nix** — run the report/tracker backend against the profile
  or closure you want to scan and set `SENTINEL_NIXPKGS_REV` plus, optionally,
  `SENTINEL_NIXPKGS_FLAKE`. No channel is assumed; the applet shows
  `nixpkgs (<rev>)` and does not label the system as NixOS. The module's
  `/run/current-system` scan target is NixOS-only; a standalone service must
  point `vulnxscan` at its own profile.

The source is the Nixpkgs the closure was built from. Packages pulled from a
different flake or overlay are not tracked per package; the row shows the
system source unless a backend supplies a per-finding `source` object.

The tracker token is optional and can be set in the widget configuration
(stored in the user's KDE config, read by the root service) or installed as a
root-readable file at `/var/lib/sentinel/tracker-token`. Anonymous tracker
access is rate-limited.

## Installation

### From source

```bash
git clone git@github.com:Steinhagen/sentinel-widget.git sentinel-widget
cd sentinel-widget
kpackagetool6 --type Plasma/Applet --install .
./scripts/install-icons.sh
```

To update an existing source installation:

```bash
kpackagetool6 --type Plasma/Applet --upgrade .
./scripts/install-icons.sh
```

The second command installs the six severity shields into your per-user
hicolor icon theme; run it after every update that changes the SVGs. The Nix
module installs them automatically. Then right-click the desktop or panel,
choose **Add Widgets**, and search for **Sentinel**.

### Build a `.plasmoid`

```bash
./package.sh
```

On NixOS, if `python3` is not on `PATH`:

```bash
nix shell nixpkgs#python3 -c './package.sh'
```

The archive is written to `dist/sentinel-<version>.plasmoid`. It contains
`metadata.json` and `contents/`, which is the layout expected by KDE Store and
`kpackagetool6`.

## Release identity

The applet is published as **Sentinel**:

- `KPlugin.Id`: `io.github.steinhagen.sentinel`
- `KPlugin.Name`: `Sentinel`
- `KPlugin.Version`: `0.3.0`
- Repository: `git@github.com:Steinhagen/sentinel-widget.git`

`default.nix` installs the package under the matching
`io.github.steinhagen.sentinel` directory. The QML code itself does not depend
on the ID, but an existing Plasma layout refers to the plugin by ID; either
migrate that entry or remove and re-add the widget after renaming.

A store submission usually needs:

- a `.plasmoid` archive from `./package.sh`;
- at least one real screenshot (add it under `screenshots/`);
- the required backend/configuration explained in the description;
- a version bump and a matching `CHANGELOG.md` entry.

## Configuration

Right-click the widget and choose **Configure…**:

- **Panel badge:** finding count, dot, or hidden.
- **Triage verdicts:** hide findings that the triage pass classified as false
  positives (enabled by default). The verdicts come from
  `/var/lib/sentinel/triage.json`, written by
  [`tools/triage.mjs`](tools/triage.mjs), or from a `verdict` field on the
  finding itself. The triage column uses compact icons: amber **!** for
  unverified rows, green **✓** for confirmed ones, and red **⊘** for the
  suppressed false positives. The column is hidden when both this setting and
  **Unverified findings** are on; turn one off to see that state. Hover the
  icon to see what the CVE actually names (for example
  `Fidelis Cybersecurity → Fidelis Network`). The header is sortable; the
  toolbar count shows hidden rows as `(+ N hidden findings)`. The rule tables
  (language bindings, CMS module names), worked examples and verdict reasons
  are in [docs/triage.md](docs/triage.md).
- **Unverified findings:** hide findings the triage pass could not confirm
  (enabled by default). This is independent of **Triage verdicts**; when both
  are on, the Triaj column is hidden.
- **OSV advisories:** hide findings whose id starts with `OSV-` (enabled by
  default). OSV entries are keyed by package and ecosystem rather than a CPE
  product string, so they use their own setting; the toolbar count includes
  them as hidden findings.
- **Ignored findings:** right-click a row and choose **Ignore this finding
  (false positive)** to hide a finding the scanners matched to the wrong
  package. The list is kept in the applet configuration; the same settings
  page shows how many are ignored and offers **Restore all**.
- **Tracker API token:** used for authenticated Nixpkgs security tracker lookups.

Use the summary cards for quick severity and fix-state filtering, or the
**Filter** popover to enter a CVE, package or origin manually. Clicking a
package or origin in a finding uses the same filters. Every active filter is
shown as a removable chip below the toolbar, with a **Clear filters** action.
Use the **Group by** split button to choose Flat, Priority, Package, CVE or Origin.
Click a section header to show or hide that group, or use the plus/minus
control in the group bar to show or hide every group at once. The group bar
also sorts groups by name or finding count.
The CSV report and scan log are in the widget's context menu; hover the summary
line under the title for the About/help text.

## Development

The layered architecture and module boundaries are documented in
[docs/architecture.md](docs/architecture.md); the backend contract is in
[docs/status-schema.md](docs/status-schema.md) and the test guide is in
[docs/testing.md](docs/testing.md). `tools/triage.mjs` re-classifies a scan as
confirmed / unverified / suppressed; see [docs/triage.md](docs/triage.md).

```bash
nix develop
./scripts/check.sh
kpackagetool6 --type Plasma/Applet --install .
```

The QML uses `Kirigami.Theme`; test both light and dark system color schemes.
The table and summary cards are designed for a minimum width of 36 grid units.

## Translations

The applet is localized through [Ki18n](https://api.kde.org/ki18n-index.html) and
GNU gettext. The Romanian catalog (`translate/ro.po`) is complete, and the widget
description is translated inline in `metadata.json`.

- `translate/merge.sh` extracts `i18n()` calls into `translate/template.pot` and
  merges it into every `.po`.
- `translate/build.sh` compiles the catalogs to
  `contents/locale/<lang>/LC_MESSAGES/plasma_applet_io.github.steinhagen.sentinel.mo`,
  which is the path Plasma reads at runtime. The `.mo` files are committed.
- `./scripts/check.sh` verifies that every catalog is complete and up to date.

See [translate/README.md](translate/README.md) for adding a language.

## License

MIT — see [LICENSE](LICENSE).

## Credits

The widget is part of the author's NixOS setup and depends on its **Sentinel**
scanner service. Built with KDE Plasma 6, Kirigami and Qt Quick.
