# Scanner backend contract

Sentinel is only the Plasma frontend. The data comes from the **Sentinel**
backend and the applet expects this contract:

- Status file: `/var/lib/sentinel/status.json`
- Scan trigger: `systemctl start --no-block sentinel.service`
- The file is written by the backend after a scan; the applet refreshes it
  periodically and after **Scan now**.

The current backend lives in the author's NixOS flake (`system/sentinel.nix`,
`system/sentinel-status.py`) and is not part of this widget repository.

At the time of writing, the relevant top-level fields are:

```json
{
  "schema_version": 7,
  "state": "vulnerable",
  "findings": 1057,
  "max_severity": 9.9,
  "packages_affected": 132,
  "severity_counts": { "critical": 46, "high": 294, "medium": 545, "low": 72, "unknown": 100 },
  "scanned_at": "2026-11-21 00:04",
  "vulnerabilities": []
}
```

Each `vulnerabilities[]` entry supplies the table fields (`id`, `package`,
`version`, `severity`, `scanners`, `confidence`, `url`) plus `origins` and
`tracker` metadata. Schema details and the scanner implementation stay with the
backend so the widget can remain a thin presentation layer.

If you want to publish a fully self-contained KDE Store widget, package the
backend as a separate service/package and make the store description explicit
about the NixOS requirement.
