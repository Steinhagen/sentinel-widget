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

## Status contract

The applet depends on the fields in [`status-schema.md`](status-schema.md).
Each finding may carry `verdict`, `verdict_reasons`, `verdict_vendor` and
`verdict_product`, produced by `tools/triage.mjs --embed`. A sidecar
`triage.json` is still accepted for manual runs of the tool, but the module
does not write one.
