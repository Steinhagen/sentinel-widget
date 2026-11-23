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
| `confirmed` | The CVE identity matches and the installed version is in range, or a human/ecosystem verdict says so; a tracker issue confirms identity only after the version/fix check | keep |
| `unverified` | Identity is ambiguous, or the CVE has no usable data | review; do not claim affected |
| `suppressed` | The match is provably wrong: other product, other version, or a human rejected it | hide |

`unverified` is a first-class outcome. The tool never deletes a finding and
never writes to the status file: it produces a sidecar report so the decision
can be reviewed and, later, adopted by the backend.

## What it checks

1. **Human and tracker verdicts.** A rejected tracker suggestion or an
   `unaffected` master verdict suppresses. A published or accepted issue
   confirms the CVE's identity, but not the installed version: the pass still
   checks the tracker's channel fix and the CVE range (see below). A tracker
   fix that covers the installed version suppresses (`tracker-fixed`), and an
   installed version outside the range suppresses (`version-not-affected`).
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
6. **Language bindings.** Some packages are bindings to a C library (Hackage
   `zlib`, for example). Their package version is not the C library version.
   When the CVE names the C library, the pass reads the library version the
   binding links against from the finding's store paths (`nix-store
   --references`) and compares that instead. It reports
   `binding-library-unaffected`, `binding-library-in-range`,
   `binding-version-unknown` or `binding-version-incomparable`.
7. **CMS module names.** A generic module name (`Diff`, `Token`, `Views`) can
   collide with a package from a different ecosystem. When the CVE vendor is a
   CMS (`Drupal`, `WordPress`, `Joomla`, `Moodle`, `TYPO3`, `SilverStripe`,
   `Craft CMS`, `Concrete CMS`), the product name matches exactly, and the
   vendor does not corroborate the package, the pass infers the package
   ecosystem from its origin names and store path. A known non-PHP package is
   suppressed (`ecosystem-mismatch`); an unknown or PHP package stays
   `unverified` (`cms-module-cve`).

## Tracker issues are not version confirmations

A published Nixpkgs tracker issue confirms that the CVE was matched to the
package; it does not confirm that the *installed* version is affected. The pass
checks the fix state and the version:

- `fix_state: fixed` with a `fix_version` at or below the installed version on
  the system channel (`fix_branch` == `system_channel`) → `suppressed` /
  `tracker-fixed`;
- the installed version outside every CVE range → `suppressed` /
  `version-not-affected`;
- the tracker's `master_status` says affected while the installed version is
  outside the range → `unverified` / `version-conflict-with-tracker`;
- affected, or a version/range that cannot be compared → the tracker's
  `confirmed` / `tracker-published` (or `tracker-accepted`).

This distinction matters when a scanner flags a version that is already fixed:
the scanner match and the tracker issue are both real, but the installed
version is not affected. CVE 5.1 `packageName` entries are used as product
names when the record has no vendor/product (the upstream GnuTLS entry is an
example).

The tables in the tool are the maintenance points:

| Table | What it holds | When to extend it |
| --- | --- | --- |
| `PACKAGE_ALIASES` | Package names that mean the same software (`linux`/`kernel`, `libupnp`/`pupnp`) | A real CVE is suppressed because the names differ |
| `DISTRIBUTIONS`, `PLATFORMS` | Vendors that ship components inside their own OS or platform | A distribution-scoped CVE is wrongly suppressed |
| `LIBRARY_BINDINGS` | Language binding → C library, plus the ecosystem whose origins identify the binding | A binding package collides with a C library CVE |
| `CMS_VENDORS` | Vendors that publish CMS modules | A CMS module name collides with an unrelated package |
| `ECOSYSTEM_ORIGINS` | Origin-name patterns for Haskell, PHP, Python and Node | A package ecosystem cannot be inferred |

Every new entry needs a regression test in `tests/tools/triage.test.mjs`.
Tests should assert both the fixed case and a control that must keep its
old verdict.

`parseCve` also falls back to `packageName` when a CVE 5.1 entry has no
vendor/product; no table update is needed for that case.

## Worked examples

**CVE-2023-45853 — Hackage `zlib` vs the C zlib library.**

- Finding: `zlib` 0.7.1.1, introduced by `haskell-language-server`.
- CVE: MiniZip in the C zlib library, affected `<1.3.1`.
- Rule: `LIBRARY_BINDINGS`; `nix-store --references` on the finding's store
  path resolves the linked C library to `zlib 1.3.2`.
- Verdict: `suppressed` / `binding-library-unaffected`.
- Why: 0.7.1.1 is the Hackage package version; the C library it links is fixed.

**CVE-2024-13278 — Hackage `Diff` vs the Drupal Diff module.**

- Finding: `Diff` 1.0.2, introduced by `haskell-language-server`; the store
  path contains `lib/ghc-*`, so the package is Haskell.
- CVE: the Drupal `Diff` module, affected `<1.8.0`, vendor `Drupal`.
- Rule: `CMS_VENDORS`; the package ecosystem is Haskell, not PHP.
- Verdict: `suppressed` / `ecosystem-mismatch`.
- Why: the version 1.0.2 only coincides with Drupal's version range; the two
  products are unrelated. An unknown ecosystem would stay `unverified`
  (`cms-module-cve`) for review.

**CVE-2026-111497 — scanner flags a fixed brotli.**

- Finding: `brotli` 1.2.1; the CVE affects 1.0.3–1.2.0 and is fixed in 1.2.1.
- Tracker: published, `fix_state: fixed`, `fix_version: 1.2.1` on
  `nixos-unstable`.
- Rule: the tracker fix covers the installed version.
- Verdict: `suppressed` / `tracker-fixed`.

**CVE-2026-33845 — scanner flags a fixed gnutls.**

- Finding: `gnutls` 3.8.13; the CVE affects `<3.8.13` and is fixed in 3.8.13.
- Tracker: published, but `fix_state` is unknown because the gnutls
  `package.nix` has no plain version to compare; the CVE CNA has only
  `packageName: gnutls`.
- Rule: CVE 5.1 `packageName` fallback plus the version range.
- Verdict: `suppressed` / `version-not-affected`.

## Verdict reasons

The applet maps these tokens to tooltip text in `Labels.qml`.

| Reason | Verdict | Meaning |
| --- | --- | --- |
| `tracker-published`, `tracker-accepted` | confirmed | The tracker confirmed the identity; the installed version did not clear it |
| `tracker-fixed` | suppressed | The tracker fix on the system channel covers the installed version |
| `tracker-rejected`, `tracker-unaffected` | suppressed | The tracker rejected the match or the version |
| `osv-advisory` | confirmed | The finding is an OSV advisory for its own ecosystem |
| `version-in-range` | confirmed | The installed version is inside the affected range |
| `version-not-affected` | suppressed | The installed version is outside every affected range |
| `version-incomparable`, `no-version-range` | unverified | The version or range cannot be compared |
| `version-conflict-with-tracker` | unverified | The tracker says master is affected but the installed version is outside the range |
| `identity-mismatch` | suppressed | The CVE names a different product |
| `product-only-match`, `product-mismatch` | unverified | The name overlaps but the identity is not proven |
| `vendor-scoped-cve` | unverified | The CVE belongs to a distribution or platform |
| `binding-library-unaffected` | suppressed | The binding links a C library version outside the range |
| `binding-library-in-range` | confirmed | The binding links an affected C library version |
| `binding-version-unknown`, `binding-version-incomparable` | unverified | The linked library version could not be used |
| `ecosystem-mismatch` | suppressed | A CMS module name collided with a known non-PHP package |
| `cms-module-cve` | unverified | A CMS module name collided and the ecosystem is unknown/PHP |
| `manual-ignore` | suppressed | The user dismissed this CVE/package pair |

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
- `--ignore FILE` applies a dismissal list; see below.

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


## Ignoring a finding

Some collisions cannot be resolved from the CVE data alone: two different
products share a name and use different version schemes. For those, keep a
dismissal list:

```json
[
  {
    "cve": "CVE-2021-24028",
    "package": "thrift",
    "reason": "Facebook's internal Thrift, not Apache Thrift 0.25.0"
  }
]
```

Pass it with `--ignore FILE`. The scan service reads
`/var/lib/sentinel/triage-ignore.json` when it exists, so an entry only needs
to be written once:

```console
sudo install -m 644 triage-ignore.json /var/lib/sentinel/triage-ignore.json
```

Entries match a CVE **and a package**, not a version: the pair is the unit that
was judged to be a collision. `reason` is documentation only and is not shown
in the applet. A dismissal suppresses the pair with the reason
`manual-ignore`.

Two guards keep the list from hiding something real:

- a tracker `published`/`accepted` verdict wins over a dismissal, so a
  vulnerability a human confirmed is never hidden by a stale list entry;
- a malformed ignore file is reported and ignored as a whole, rather than
  silently dropping entries.

## Ignoring from the applet

The row context menu has **Ignore this finding (false positive)**. It stores the
CVE + package pair in the applet configuration (`triageIgnore`) and hides the
row immediately; the settings page shows the count and a **Restore all**
button. This list is local to the applet, survives disabling **Triage
verdicts**, and is separate from the root-owned
`/var/lib/sentinel/triage-ignore.json` list used by the scan service — use the
file when the dismissal should apply to every consumer of the report, and the
menu when you are triaging interactively.

## In the widget

The NixOS module runs the tool at the end of every tracker pass and embeds the
verdicts into `status.json`:

```console
node tools/triage.mjs \
    --status /var/lib/sentinel/status.json \
    --evidence /var/lib/sentinel/evidence.json \
    --cache /var/cache/sentinel/triage-cache \
    --ignore /var/lib/sentinel/triage-ignore.json \
    --embed
```

There is no sidecar file to manage and nothing extra to schedule. The applet
still accepts a report at `/var/lib/sentinel/triage.json` (written with
`--out`) for manual runs, but the module does not write one.

The **Triage verdicts** setting (configure dialog, enabled by default) hides
`suppressed` findings from the list, the summary cards, the counts and the panel
badge. The **Unverified findings** setting (also enabled by default) hides
`unverified` rows in the same way. The toolbar count shows hidden rows as
`837 of 932 (+ 95 hidden findings)`; turning a setting off brings those rows
back. When both triage settings are on, the Triaj column is hidden; turning
either off shows it. **OSV advisories** (enabled by default) hides findings
whose id starts with `OSV-`; it is independent of the Triaj column. `confirmed`
findings are always shown unless they are OSV advisories and that setting is on.

The triage column between the package and the fix state uses compact icons:
amber **!** for unverified rows, green **✓** for confirmed ones, and red **⊘**
for suppressed false positives when the setting shows them. Hovering the icon
explains why the row could not be confirmed, why it was suppressed, or that the
match was confirmed; for a product-name match it names the CVE's own
vendor → product (`Fidelis Cybersecurity → Fidelis Network`). That is what
distinguishes a name collision from a real hit; the grouped review queue uses the
same pair for its cluster headers.

The applet also accepts the verdict on the finding itself (`verdict` and
`verdict_reasons` in `status.json`), so a backend can supply it without a
sidecar — see [status-schema.md](status-schema.md). The sidecar wins nothing:
an embedded verdict takes precedence over the report.

## Adopting it

The natural next step is to make the backend emit the verdict instead of a
sidecar file: add `verdict` and `verdict_reasons[]` to the finding record
(`schema_version` 8), compute them where the CVE data is already loaded, and let
the widget filter `suppressed` and `unverified` with independent settings and
count all hidden rows together. Until then this tool is the place to tune the
rules against real scans.
