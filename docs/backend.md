# Scanner backend

Sentinel ships both halves: the Plasma applet and the scanner backend. The
backend is a NixOS module (`nix/module.nix`) that installs the applet and two
services:

- **`sentinel.service`** runs `vulnxscan` over `/run/current-system` and writes
  `/var/lib/sentinel/status.json` through `nix/backend/sentinel-status.py`. It
  starts from the applet’s **Scan now** button or the daily timer.
- **`sentinel-tracker.service`** annotates the findings with the Nixpkgs
  security tracker, then runs `tools/triage.mjs --embed`, which folds the
  triage verdicts into the same `status.json`. It runs after every scan and on
  its own 15-minute timer (to resume interrupted passes and refresh tracker
  answers).

The applet reads `status.json` only. There is no third service and no second
report file to keep in sync.

## Enabling it

```nix
inputs.sentinel-widget.url = "github:Steinhagen/sentinel-widget/main";

{
  imports = [ inputs.sentinel-widget.nixosModules.default ];

  services.sentinel = {
    enable = true;
    user = "alice";   # whose applet settings hold the tracker token
  };
}
```

Options:

| Option | Meaning |
| --- | --- |
| `enable` | install the applet and the two services |
| `user` | user whose Plasma applet configuration holds the tracker token; `null` uses only `/var/lib/sentinel/tracker-token` |
| `package` | applet package to install; the flake fills it in |

## Files

| File | Written by | Purpose |
| --- | --- | --- |
| `/var/lib/sentinel/status.json` | scan, then tracker/triage | findings, tracker annotations and triage verdicts |
| `/var/lib/sentinel/report.csv` | scan | raw scanner report |
| `/var/lib/sentinel/evidence.json` | scan | component evidence for the origin chains |
| `/var/lib/sentinel/last.log` | scan, tracker, triage | append-only log |
| `/var/lib/sentinel/tracker-token` | operator (optional) | root-readable tracker token |
| `/var/lib/sentinel/triage-ignore.json` | operator (optional) | CVE + package dismissals |

The applet starts the scan with `systemctl start --no-block sentinel.service`;
the module’s polkit rule allows `wheel` users to do that without a password
prompt.

## Tracker package attributes

A tracker suggestion can cover several nixpkgs attributes: `ffmpeg`,
`ffmpeg_6`, `ffmpeg_8`, `openssl_1_1`, `openssl_3_5`, `libressl_4_2`,
`capstone_4`, and `-full`/`-headless` outputs. Matching by the bare package
name is not enough. The backend scores every versioned attribute of the base
package by how many leading version components match the installed finding and
picks the best; the exact base wins a tie:

- `ffmpeg` 9.0.2 → the default `ffmpeg`;
- `ffmpeg` 8.1.3 → `ffmpeg_8`;
- `ffmpeg` 6.1.6 → `ffmpeg_6`;
- `openssl` 1.1.1w → `openssl_1_1`;
- `openssl` 3.5.2 → `openssl_3_5`;
- `libressl` 4.2.1 → `libressl_4_2`;
- `capstone` 4.0.2 → `capstone_4`.

This matters for legacy attributes and vendored dependencies. `tor-browser`
uses `ffmpeg_8`; the tracker's `ffmpeg_8` master and release branches are still
8.1.2 and affected, while the default `ffmpeg` in master is 9.0.1 and fixed.
The applet therefore shows **no fix** for a `ffmpeg` 8.1.3 finding, and its fix
tooltip names `ffmpeg_8` — it does not inherit the default package's `master`
fix. The channel probe reads one version literal from a package file; a
versioned attribute often shares that file with the default, so a channel or
staging reading is only trusted when its leading major.minor matches the
matched attribute's master version.

## Status contract

The applet depends on the fields in [`status-schema.md`](status-schema.md).
Each finding may carry `verdict`, `verdict_reasons`, `verdict_vendor` and
`verdict_product`, produced by `tools/triage.mjs --embed`. A sidecar
`triage.json` is still accepted for manual runs of the tool, but the module
does not write one.
