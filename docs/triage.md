# Triaging findings

The scanners answer "which advisories mention this package". They do not answer
"is this advisory about this software". `tools/triage.mjs` is a post-scan pass
that re-derives the identity of every finding from the CVE record and labels it
`confirmed`, `unverified` or `suppressed`.

The motivating case is a real one from the author's scan: vulnix reported
`CVE-2021-35049` (CVSS 9.9) against the Haskell `network` package, because the
CVE is about Fidelis' **Network** appliance and vulnix matches CPE products
without looking at the vendor. `3.2.8.0` also compares "less than" `9.3.7`, so
the version check did not save it either. The triage pass labels that finding
`unverified` with the reason `product-only-match` and shows which vendor and
product the CVE actually describes.

## Verdicts

| Verdict | Meaning | Default handling |
| --- | --- | --- |
| `confirmed` | The CVE identity matches and the installed version is in range, or a human/tracker/ecosystem verdict says so | keep |
| `unverified` | Identity is ambiguous, or the CVE has no usable data | review; do not claim affected |
| `suppressed` | The match is provably wrong: other product, other version, or a human rejected it | hide |

`unverified` is a first-class outcome. The tool never deletes a finding and
never writes to the status file: it produces a sidecar report so the decision
can be reviewed and, later, adopted by the backend.

## What it checks

1. **Human and tracker verdicts.** A published or accepted tracker suggestion
   confirms; a rejected suggestion or an `unaffected` master verdict suppresses.
2. **Ecosystem advisories.** Findings whose id is an `OSV-*` advisory are
   confirmed: OSV entries are keyed by package name and ecosystem, not by a CPE
   product string.
3. **Identity.** The CVE's `vendor`/`product` pairs are compared with the
   package name after normalising case, punctuation, trailing digits and filler
   words (`Inc`, `Software`, `Foundation`, …). A product name that merely
   overlaps (`network` vs `Fidelis Network`) is not enough: without vendor
   corroboration it stays `unverified`. A completely unrelated identity is
   suppressed.
4. **Version range.** CVE 5.0 affected ranges (`version` + `lessThan` /
   `lessThanOrEqual`, or a single affected version) are evaluated against the
   installed version. A version outside every range is suppressed, unless the
   tracker reports the same version as affected — then the two sources disagree
   and the finding stays `unverified` (`version-conflict-with-tracker`).
5. **Scoping.** Distributions and platforms (`Red Hat`, `Debian`, `Apple`,
   `Google`, …) describe components *inside* their product. Those CVEs are
   `unverified` rather than suppressed, because the product name says nothing
   about the component.

The alias tables (`PACKAGE_ALIASES`, `DISTRIBUTIONS`, `PLATFORMS` in the tool)
are the maintenance point: when a real CVE is suppressed because two names mean
the same software (`linux`/`kernel`, `libupnp`/`pupnp`), add an alias and a
test.

## Running it

```console
nix develop --command node tools/triage.mjs \
    --status /var/lib/sentinel/status.json \
    --evidence /var/lib/sentinel/evidence.json \
    --fetch --out /tmp/triage.json
```

- `--fetch` downloads missing CVE records from the [CVE List
  V5](https://github.com/CVEProject/cvelistV5) into
  `~/.cache/sentinel-triage`; later runs work offline. Without `--fetch`, the
  tool only uses what is already cached.
- `--only CVE-…,CVE-…` and `--limit N` keep a run short.
- `--quiet` suppresses the summary; the JSON report is written with `--out`.

The report contains the totals, the reason histogram and one record per
finding:

```json
{
  "id": "CVE-2021-35049",
  "package": "network",
  "version": "3.2.8.0",
  "verdict": "unverified",
  "reasons": ["product-only-match"],
  "vendor": "Fidelis Cybersecurity",
  "product": "Fidelis Network",
  "identity": "overlap"
}
```

### Example

On a real NixOS 26.11 closure (932 findings, 622 CVEs) the pass reports:

```text
confirmed:  519 (56%)
unverified: 318 (34%)
suppressed:  95 (10%)
```

The suppressed set is dominated by tracker rejections (70), same-product
version exclusions and application/appliance name collisions (F-Secure
`Safe Browser` against the Haskell `safe` package, Siemens SIMATIC CVEs against
`perl`, `zlib`, `tar`, …).

## Limits

- **CNA data is not NVD data.** Records before roughly 2016 often carry
  `vendor: n/a` and no version ranges, so those findings stay `unverified`
  instead of being cleared. A full run against NVD's CPE data (`--source nvd`
  is not implemented yet) would cover more of them at the cost of slow,
  rate-limited lookups.
- **Same name, same product.** Two different projects can share a name and a
  vendor-ish string; the tool cannot resolve that without an alias.
- **Aggregated packages.** A CVE for a component bundled inside a package
  (vendored libraries, `-full` variants) can be suppressed if the CVE names
  only the bundled product.
- **OSV is trusted.** OSV entries are treated as confirmed without a second
  lookup; that is deliberate, because they are ecosystem-scoped, but it means
  OSV's own mapping errors pass through.

## In the widget

The applet reads the report as a sidecar next to the status file:

```console
sudo nix develop --command node tools/triage.mjs \
    --status /var/lib/sentinel/status.json \
    --evidence /var/lib/sentinel/evidence.json \
    --out /var/lib/sentinel/triage.json
```

The **Triage verdicts** setting (configure dialog, enabled by default) hides
`suppressed` findings from the list, the summary cards, the counts and the panel
badge. The toolbar then shows how many findings were hidden; turning the setting
off brings them back. `confirmed` and `unverified` findings are always shown.

The applet also accepts the verdict on the finding itself (`verdict` and
`verdict_reasons` in `status.json`), so a backend can supply it without a
sidecar — see [status-schema.md](status-schema.md). The sidecar wins nothing:
an embedded verdict takes precedence over the report.

## Adopting it

The natural next step is to make the backend emit the verdict instead of a
sidecar file: add `verdict` and `verdict_reasons[]` to the finding record
(`schema_version` 8), compute them where the CVE data is already loaded, and let
the widget filter `suppressed` by default and count `unverified` separately.
Until then this tool is the place to tune the rules against real scans.
