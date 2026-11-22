# Scanner status contract

Sentinel is a frontend. The **Sentinel** service writes the files the applet reads;
the applet does not invoke the scanner directly.

| File | Purpose |
| --- | --- |
| `/var/lib/sentinel/status.json` | Latest scan result and tracker progress |
| `/var/lib/sentinel/triage.json` | Optional triage verdicts; see below |
| `/var/lib/sentinel/report.csv` | Optional CSV report opened from the context menu |
| `/var/lib/sentinel/last.log` | Scan log opened from the context menu |

The applet starts the service with:

```sh
systemctl start --no-block sentinel.service
```

and checks it with:

```sh
systemctl is-active sentinel.service
```

## Top-level `status.json`

A machine-readable JSON Schema is in [status.schema.json](status.schema.json).

Current schema version: **7**.

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Optional in older files. A newer version is tolerated. |
| `state` | string | `secure`, `vulnerable`, `warn`, `unknown` |
| `findings` | number | Total finding count |
| `max_severity` | number | Highest CVSS score, 0 when unknown |
| `packages_affected` | number | Optional; the applet falls back to distinct packages |
| `severity_counts` | object | `critical`, `high`, `medium`, `low`, `unknown` |
| `scanned_at` | string | Legacy human-readable timestamp |
| `scanned_at_iso` | string | ISO-8601 timestamp, preferred |
| `scanned_at_epoch` | number | Seconds since the epoch, preferred |
| `error` | string/null | Last scan error, if any |
| `tracker` | object | Tracker progress; see below |
| `vulnerabilities` | array | Finding records; older files may use `top` |

Legacy compatibility:

- `top` is accepted when `vulnerabilities` is absent.
- `severity_counts` is computed from the findings when absent.
- `packages_affected` is computed from distinct `package` values when absent.
- Timestamps fall back to `scanned_at_epoch`, `scanned_at_iso`,
  `scanned_at`, then a `YYYY-MM-DD HH:MM` local-time parse.

## Finding record

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | CVE or OSV id |
| `package` | string | Vulnerable package |
| `version` | string | Installed version |
| `severity` | number/null | CVSS score; `0`, null or missing means unknown |
| `url` | string | Vulnerability database link |
| `scanners` | array | Scanner names, e.g. `vulnix`, `grype` |
| `confidence` | string | `component_exact`, `component_expanded`, `component_mixed`, `package_version_only` |
| `patch_state` | string | Backend-specific patch information |
| `origins` | object | Dependency provenance; see below |
| `tracker` | object | Nixpkgs security tracker annotation; see below |
| `verdict` | string | Optional triage verdict: `confirmed`, `unverified`, `suppressed` |
| `verdict_reasons` | array | Optional reason tokens, e.g. `version-not-affected` |

### Triage verdicts

A finding may carry its triage verdict directly. When it does not, the applet
reads the sidecar report at `/var/lib/sentinel/triage.json`, written by
[`tools/triage.mjs`](../tools/triage.mjs) (see [triage.md](triage.md)). The
report is `{ "findings": [ { "id", "package", "version", "verdict", "reasons" } ] }`;
entries are joined to findings by `id`, `package` and `version`.

With the triage setting enabled, findings whose verdict is `suppressed` are
hidden from the list, the counts and the panel badge. `confirmed` and
`unverified` findings stay visible; `unverified` means the tool could not
prove the match either way.

### `origins`

```json
{
  "introduced_by": ["curl-8.0.0"],
  "chain": ["curl-8.0.0", "openssl-3.0.0"],
  "chains": [["curl-8.0.0", "openssl-3.0.0"]],
  "store_paths": ["/nix/store/...-openssl-3.0.0"]
}
```

The applet uses `introduced_by` for origin grouping and filtering, `chain` for
the second row, and `chains`/`store_paths` only in tooltips. Duplicate
consecutive nodes and a trailing version suffix are normalized for display.

### Finding `tracker`

| Field | Type | Notes |
| --- | --- | --- |
| `found` | bool | Tracker has a suggestion/issue |
| `status` | string | `pending`, `published`, `accepted`, `rejected` |
| `issue` | string | Nixpkgs security issue id |
| `issue_state` | string | Issue state from the tracker |
| `url` | string | Tracker page |
| `master_status` | string | `unaffected`, `affected`, `unknown` |
| `master_version` | string | Version on nixpkgs master |
| `master_status_source` | string | e.g. `version` |
| `master_range` | string | Affected range used for a version verdict |
| `master_url` | string | nixpkgs source link |
| `github_issue_url` | string/null | Fix/bump issue |
| `fix_state` | string | `fixed`, `in-staging`, `in-master`, `in-release`, `issue-open` |
| `fix_branch` | string | Branch that carries the fix |
| `fix_version` | string | Fixed version |
| `fix_url` | string | Fix source link |
| `fix_branches` | array | Per-branch verdicts; see below |
| `system_channel` | string | Channel this system updates from |
| `system_known` | bool | Whether the channel version could be read |
| `suggestion_packages` | array | Packages covered by the tracker suggestion |
| `affected_products` | array | CVE affected-product records |

`fix_branches[]` entries:

```json
{
  "name": "nixos-unstable",
  "version": "1.2.1",
  "kind": "channel",
  "state": "unaffected",
  "url": "https://github.com/NixOS/nixpkgs/blob/..."
}
```

`kind` is `channel`, `branch`, `staging` or `release`; `state` is
`unaffected`, `affected` or `unknown`.

## Top-level tracker progress

| Field | Type | Notes |
| --- | --- | --- |
| `available` | bool | Tracker data is available |
| `complete` | bool | A tracker pass is still running when `false` |
| `phase` | string | `pending`, `waiting`, `packages`, `cves`, `issues`, `probes`, `done` |
| `updated_at` | string | Last progress write |
| `cves` | number | Total CVEs considered |
| `queried` | number | CVEs queried |
| `failed` | number | Failed tracker requests |
| `tracked` | number | Findings with a tracker entry |
| `pending` | number | Pending tracker suggestions |
| `rejected` | number | Rejected matches |
| `unaffected` | number | Unaffected verdicts |
| `missing` | number | Findings absent from the tracker |
| `system_channel` | string | Channel reported by the service |
| `fix_in_progress` | number | Fixes merged but not yet in the system channel |
| `fix_staged` | number | Fixes in staging |
| `fix_available` | number | Fixes available to this system |
| `total_cves`, `queried`, `failed` | number | Legacy CVE phase counters |
| `total_packages`, `packages_checked`, `package_failed` | number | Package phase counters |
| `total_issues`, `issues_checked`, `issue_failed` | number | Issue phase counters |
| `total_probes`, `probes_checked`, `probes_failed` | number | Branch probe counters |
| `fallback_total`, `fallback_done`, `fallback_failed` | number | CVE fallback counters |
| `throttled` | bool | Rate limit reached |
| `auth_failed` | bool | API token rejected |

## Compatibility policy

- Missing optional fields are defaulted, never fatal.
- Unknown fields are preserved.
- A `schema_version` newer than the applet supports still renders known fields
  and surfaces a warning.
- Malformed JSON, permission errors and a missing file are distinct load errors
  in the applet, not the same "not scanned yet" state.

## Fixtures

`tests/fixtures/status-v7.json` is a sanitized 13-finding sample covering the
fix/tracker states above. `status-legacy.json` covers the `top` fallback,
`status-corrupt.json` covers invalid JSON, and `tracker-progress.json` covers a
running package phase. Refresh them from a real scan with the fixture script
described in [testing.md](testing.md).
