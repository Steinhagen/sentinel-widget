#!/usr/bin/env node
/**
 * Sentinel triage — post-process a scan and classify each finding as
 * `confirmed`, `unverified` or `suppressed`.
 *
 * The widget shows what the scanners report; this tool answers a different
 * question: *does the CVE actually describe this package?* It re-derives the
 * identity of every finding from the CVE record (vendor, product, affected
 * version ranges) and only trusts a match when that identity is corroborated.
 *
 * Usage:
 *
 *   node tools/triage.mjs \
 *     --status /var/lib/sentinel/status.json \
 *     --evidence /var/lib/sentinel/evidence.json \
 *     --cache ~/.cache/sentinel-triage \
 *     --fetch --out /tmp/triage.json
 *
 * The CVE metadata comes from the CVE List V5 (the same records vulnix and
 * grype ingest). `--fetch` populates a local cache; later runs work offline.
 *
 * Verdicts:
 *   confirmed    identity or a human/tracker verdict proves the finding
 *   unverified   identity is ambiguous or the CVE carries no usable data
 *   suppressed   the match is provably wrong (other product, other version)
 *
 * This tool never hides anything by itself. It writes a sidecar report; a
 * backend can later adopt the same rules and expose the verdict.
 */

import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// Text and identity
// ---------------------------------------------------------------------------

/** Words that carry no identity in vendor/product names. */
const STOPWORDS = new Set([
    "a",
    "an",
    "and",
    "company",
    "corp",
    "corporation",
    "for",
    "foundation",
    "gmbh",
    "inc",
    "llc",
    "ltd",
    "of",
    "project",
    "software",
    "team",
    "technologies",
    "technology",
    "the",
]);

/**
 * Split a vendor/product/package name into comparable tokens.
 *
 * Digits are stripped from the end (`python3` -> `python`) but the token is
 * kept, so short names such as `xz` still match.
 *
 * @param {string} value
 * @returns {string[]}
 */
export function tokens(value) {
    return String(value || "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, " ")
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map((token) => token.replace(/[0-9]+$/, ""))
        .filter((token) => token.length >= 2 && !STOPWORDS.has(token));
}

/**
 * Whether two tokens are the same identity (`cpython` vs `python`).
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function tokenMatches(a, b) {
    if (a === b) {
        return true;
    }
    const [short, long] = a.length <= b.length ? [a, b] : [b, a];
    return short.length >= 3 && long.endsWith(short);
}

/**
 * Compare two token sets.
 *
 * @param {string[]} left
 * @param {string[]} right
 * @returns {"equal"|"overlap"|"none"}
 */
export function tokenRelation(left, right) {
    const l = new Set(left);
    const r = new Set(right);
    if (l.size === 0 || r.size === 0) {
        return "none";
    }
    let matchedLeft = 0;
    for (const token of l) {
        if ([...r].some((other) => tokenMatches(token, other))) {
            matchedLeft += 1;
        }
    }
    let matchedRight = 0;
    for (const token of r) {
        if ([...l].some((other) => tokenMatches(token, other))) {
            matchedRight += 1;
        }
    }
    if (matchedLeft === 0) {
        return "none";
    }
    if (matchedLeft === l.size && matchedRight === r.size) {
        return "equal";
    }
    return "overlap";
}

/**
 * Whether every token of `wanted` can be found in `available`.
 *
 * @param {string[]} wanted
 * @param {string[]} available
 * @returns {boolean}
 */
export function containsTokens(wanted, available) {
    if (wanted.length === 0) {
        return false;
    }
    return wanted.every((token) =>
        available.some((other) => tokenMatches(token, other)),
    );
}

/**
 * Product names CVE records use for a package under another name.
 *
 * `linux` is reported as "kernel" or "Linux kernel"; `glibc` as "GNU C
 * Library". Expanding the package side keeps these real matches alive.
 */
const PACKAGE_ALIASES = {
    glibc: ["libc"],
    libc: ["glibc"],
    linux: ["kernel"],
    kernel: ["linux"],
    libupnp: ["pupnp"],
    openssl: ["libssl"],
    pupnp: ["libupnp"],
};

/**
 * Linux distribution vendors. Their CVEs describe a component *as shipped in
 * the distribution*, so a product mismatch with the component name proves
 * nothing: keep the finding for review instead of suppressing it.
 */
const DISTRIBUTIONS = new Set([
    "almalinux",
    "alpine",
    "amazon",
    "arch",
    "centos",
    "canonical",
    "debian",
    "fedora",
    "gentoo",
    "oracle",
    "redhat",
    "rocky",
    "suse",
    "ubuntu",
]);

/**
 * Platform vendors whose CVEs describe a component *inside* their operating
 * system (`Apple: macOS`, `Google: Android`). Same treatment as distributions.
 */
const PLATFORMS = new Set(["apple", "google", "microsoft", "nvidia"]);

/**
 * Expand package tokens with their aliases.
 *
 * @param {string} value
 * @returns {string[]}
 */
export function packageTokensOf(value) {
    const base = tokens(value);
    const expanded = [...base];
    for (const token of base) {
        for (const alias of PACKAGE_ALIASES[token] ?? []) {
            if (!expanded.includes(alias)) {
                expanded.push(alias);
            }
        }
    }
    return expanded;
}

/**
 * Whether a vendor ships components inside its own distribution or platform.
 *
 * @param {string|null} vendor
 * @returns {boolean}
 */
export function isScopedVendor(vendor) {
    const joined = tokens(vendor || "").join("");
    return [...DISTRIBUTIONS, ...PLATFORMS].some(
        (name) => joined === name || joined.startsWith(name),
    );
}

/** @param {unknown} value */
function cleanIdentity(value) {
    const text = String(value ?? "").trim();
    if (text === "" || /^(n\/?a|unknown|\*|-)$/i.test(text)) {
        return null;
    }
    return text;
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/**
 * Parse a dotted numeric version. Returns null when the version is not in a
 * form this tool is willing to compare (suffixes, product names, wildcards).
 *
 * @param {unknown} value
 * @returns {{components: number[]}|null}
 */
export function parseVersion(value) {
    const text = String(value ?? "").trim();
    const match = /^(\d+(?:\.\d+)*)$/.exec(text);
    if (!match) {
        return null;
    }
    return { components: match[1].split(".").map(Number) };
}

/**
 * Compare two parsed versions.
 *
 * @param {{components: number[]}} left
 * @param {{components: number[]}} right
 * @returns {number}
 */
export function compareVersions(left, right) {
    const length = Math.max(left.components.length, right.components.length);
    for (let index = 0; index < length; ++index) {
        const a = left.components[index] ?? 0;
        const b = right.components[index] ?? 0;
        if (a !== b) {
            return a < b ? -1 : 1;
        }
    }
    return 0;
}

/**
 * @typedef {object} VersionRange
 * @property {string|null} exact
 * @property {string|null} startIncluding
 * @property {string|null} startExcluding
 * @property {string|null} endIncluding
 * @property {string|null} endExcluding
 */

/**
 * Turn CVE 5.0 `versions[]` entries into comparable ranges.
 *
 * Entries whose `version` names a product ("Fidelis Network 9.4") are skipped:
 * they carry no comparable bound.
 *
 * @param {Array<Record<string, unknown>>} versions
 * @returns {VersionRange[]}
 */
export function parseRanges(versions) {
    const ranges = [];
    for (const entry of versions || []) {
        if (entry.status && entry.status !== "affected") {
            continue;
        }
        /** @type {VersionRange} */
        const range = {
            exact: null,
            startIncluding: null,
            startExcluding: null,
            endIncluding: null,
            endExcluding: null,
        };
        const exact = cleanIdentity(entry.version);
        if (cleanIdentity(entry.lessThan)) {
            range.endExcluding = String(entry.lessThan).trim();
        }
        if (cleanIdentity(entry.lessThanOrEqual)) {
            range.endIncluding = String(entry.lessThanOrEqual).trim();
        }
        if (cleanIdentity(entry.versionStartIncluding)) {
            range.startIncluding = String(entry.versionStartIncluding).trim();
        }
        if (cleanIdentity(entry.versionStartExcluding)) {
            range.startExcluding = String(entry.versionStartExcluding).trim();
        }
        if (exact && parseVersion(exact)) {
            // CVE 5.0 pairs `version` with `lessThan`/`lessThanOrEqual` to
            // describe a range; `version` alone is a single affected version.
            if (
                range.startIncluding ||
                range.startExcluding ||
                range.endIncluding ||
                range.endExcluding
            ) {
                range.startIncluding = range.startIncluding ?? exact;
            } else {
                range.exact = exact;
            }
        }
        if (
            range.exact ||
            range.startIncluding ||
            range.startExcluding ||
            range.endIncluding ||
            range.endExcluding
        ) {
            ranges.push(range);
        }
    }
    return ranges;
}

/**
 * Whether two versions look like they belong to the same numbering scheme.
 *
 * `3.2.2.0` and `20150422` are both "numeric", but comparing them is
 * meaningless: one is a release number, the other a date. Components of
 * 10000 or more only occur in date-like or build-number schemes.
 *
 * @param {{components: number[]}} left
 * @param {{components: number[]}} right
 * @returns {boolean}
 */
export function plausibleScheme(left, right) {
    const max = (version) => Math.max(...version.components);
    return max(left) >= 10000 === max(right) >= 10000;
}

/**
 * Decide whether an installed version falls inside one range.
 *
 * @param {string} version
 * @param {VersionRange} range
 * @returns {"affected"|"not-affected"|"unknown"}
 */
export function evaluateRange(version, range) {
    const installed = parseVersion(version);
    if (!installed) {
        return "unknown";
    }
    const bounds = [
        ["startIncluding", range.startIncluding, (c) => c >= 0],
        ["startExcluding", range.startExcluding, (c) => c > 0],
        ["endIncluding", range.endIncluding, (c) => c <= 0],
        ["endExcluding", range.endExcluding, (c) => c < 0],
    ];
    if (range.exact !== null) {
        const exact = parseVersion(range.exact);
        if (!exact || !plausibleScheme(installed, exact)) {
            return "unknown";
        }
        return compareVersions(installed, exact) === 0
            ? "affected"
            : "not-affected";
    }
    let unknown = false;
    for (const [, bound, accept] of bounds) {
        if (!bound) {
            continue;
        }
        const parsed = parseVersion(bound);
        if (!parsed || !plausibleScheme(installed, parsed)) {
            unknown = true;
            continue;
        }
        if (!accept(compareVersions(installed, parsed))) {
            return "not-affected";
        }
    }
    return unknown ? "unknown" : "affected";
}

/**
 * Aggregate several affected ranges for one product.
 *
 * @param {string} version
 * @param {VersionRange[]} ranges
 * @returns {"affected"|"not-affected"|"unknown"|"no-ranges"}
 */
export function evaluateRanges(version, ranges) {
    if (!ranges || ranges.length === 0) {
        return "no-ranges";
    }
    let unknown = false;
    for (const range of ranges) {
        const result = evaluateRange(version, range);
        if (result === "affected") {
            return "affected";
        }
        if (result === "unknown") {
            unknown = true;
        }
    }
    return unknown ? "unknown" : "not-affected";
}

// ---------------------------------------------------------------------------
// CVE records
// ---------------------------------------------------------------------------

/**
 * @typedef {object} AffectedProduct
 * @property {string|null} vendor
 * @property {string|null} product
 * @property {VersionRange[]} ranges
 */

/**
 * @typedef {object} CveMetadata
 * @property {string} id
 * @property {AffectedProduct[]} products
 */

/**
 * Extract the parts of a CVE record the triage rules need.
 *
 * @param {any} record
 * @returns {CveMetadata}
 */
export function parseCve(record) {
    const containers = [];
    if (record?.containers?.cna) {
        containers.push(record.containers.cna);
    }
    for (const adp of record?.containers?.adp ?? []) {
        containers.push(adp);
    }
    /** @type {AffectedProduct[]} */
    const products = [];
    for (const container of containers) {
        for (const affected of container.affected ?? []) {
            const vendor = cleanIdentity(affected.vendor);
            const product = cleanIdentity(affected.product);
            if (!vendor && !product) {
                continue;
            }
            products.push({
                vendor,
                product,
                ranges: parseRanges(affected.versions ?? []),
            });
        }
    }
    return {
        id: String(record?.cveMetadata?.cveId ?? ""),
        products,
    };
}

/**
 * Path of a CVE record in the CVE List V5 repository.
 *
 * @param {string} cveId
 * @returns {string|null}
 */
export function cveListPath(cveId) {
    const match = /^CVE-(\d{4})-(\d{4,})$/.exec(cveId);
    if (!match) {
        return null;
    }
    const [, year, number] = match;
    const bucket = `${number.slice(0, Math.max(0, number.length - 3))}xxx`;
    return `cves/${year}/${bucket}/${cveId}.json`;
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/**
 * @typedef {"confirmed"|"unverified"|"suppressed"} Verdict
 */

/**
 * @typedef {object} VerdictResult
 * @property {Verdict} verdict
 * @property {string[]} reasons
 * @property {string|null} vendor
 * @property {string|null} product
 * @property {"equal"|"overlap"|"none"|null} identity
 */

/**
 * Pick the affected product that best describes the package.
 *
 * @param {AffectedProduct[]} products
 * @param {string[]} packageTokens
 */
export function bestProduct(products, packageTokens) {
    /** @type {{product: AffectedProduct, relation: "equal"|"overlap"|"none", vendorMatch: boolean, score: number}} */
    let best = {
        product: products[0],
        relation: "none",
        vendorMatch: false,
        score: -1,
    };
    for (const product of products) {
        const relation = tokenRelation(
            packageTokens,
            tokens(product.product || ""),
        );
        const vendorMatch = containsTokens(
            tokens(product.vendor || ""),
            packageTokens,
        );
        const score =
            (relation === "equal" ? 2 : relation === "overlap" ? 1 : 0) +
            (vendorMatch ? 1 : 0);
        if (score > best.score) {
            best = { product, relation, vendorMatch, score };
        }
    }
    return best;
}

/**
 * Classify a single finding.
 *
 * @param {any} finding
 * @param {CveMetadata|null} cve
 * @param {{osv?: boolean}} [options]
 * @returns {VerdictResult}
 */
export function verdictFor(finding, cve, options = {}) {
    const tracker = finding?.tracker ?? {};
    const result = (verdict, reasons, extra = {}) => ({
        verdict,
        reasons,
        vendor: extra.vendor ?? null,
        product: extra.product ?? null,
        identity: extra.identity ?? null,
    });

    // 1. Verdicts already made by a human or the NixOS tracker.
    if (tracker.status === "published" || tracker.status === "accepted") {
        return result("confirmed", [`tracker-${tracker.status}`]);
    }
    if (tracker.status === "rejected") {
        return result("suppressed", ["tracker-rejected"]);
    }
    if (tracker.master_status === "unaffected") {
        return result("suppressed", ["tracker-unaffected"]);
    }

    // 2. Advisories from the package's own ecosystem (OSV) are identity-exact.
    if (options.osv) {
        return result("confirmed", ["osv-advisory"]);
    }

    if (!cve) {
        return result("unverified", ["no-cve-data"]);
    }
    if (cve.products.length === 0) {
        return result("unverified", ["no-affected-data"]);
    }

    const packageTokens = packageTokensOf(finding?.package ?? "");
    if (packageTokens.length === 0) {
        return result("unverified", ["unidentified-package"]);
    }

    const best = bestProduct(cve.products, packageTokens);
    const identity = {
        vendor: best.product.vendor,
        product: best.product.product,
        identity: best.relation,
    };

    // 3. Identity gate: a matching product name alone is not enough.
    if (best.relation === "none" && !best.vendorMatch) {
        if (isScopedVendor(best.product.vendor)) {
            return result("unverified", ["vendor-scoped-cve"], identity);
        }
        return result("suppressed", ["identity-mismatch"], identity);
    }
    if (best.relation === "overlap" && !best.vendorMatch) {
        return result("unverified", ["product-only-match"], identity);
    }
    if (best.relation === "none" && best.vendorMatch) {
        return result("unverified", ["product-mismatch"], identity);
    }

    // 4. Version gate.
    const versionResult = evaluateRanges(finding?.version ?? "", best.product.ranges);
    if (versionResult === "affected") {
        return result("confirmed", ["version-in-range"], identity);
    }
    if (versionResult === "not-affected") {
        if (tracker.master_status === "affected") {
            return result("unverified", ["version-conflict-with-tracker"], identity);
        }
        return result("suppressed", ["version-not-affected"], identity);
    }
    if (versionResult === "unknown") {
        return result("unverified", ["version-incomparable"], identity);
    }
    return result("unverified", ["no-version-range"], identity);
}

/**
 * Count verdicts and reasons.
 *
 * @param {Array<{verdict: Verdict, reasons: string[]}>} results
 * @returns {{totals: Record<string, number>, reasons: Record<string, number>}}
 */
export function summarize(results) {
    const totals = { confirmed: 0, unverified: 0, suppressed: 0 };
    /** @type {Record<string, number>} */
    const reasons = {};
    for (const result of results) {
        totals[result.verdict] += 1;
        for (const reason of result.reasons) {
            reasons[reason] = (reasons[reason] ?? 0) + 1;
        }
    }
    return { totals, reasons };
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

/**
 * Read a status file, tolerating the legacy `top` key.
 *
 * @param {string} file
 */
export async function readStatus(file) {
    const text = await readFile(file, "utf8");
    const parsed = JSON.parse(text);
    const findings = parsed.vulnerabilities ?? parsed.top ?? [];
    return {
        schemaVersion: parsed.schema_version ?? 0,
        scannedAt: parsed.scanned_at ?? null,
        tracker: parsed.tracker ?? null,
        findings,
    };
}

/**
 * Read the evidence file. Optional: the tool works from the status file alone.
 *
 * @param {string|null} file
 * @returns {Promise<Map<string, any>>}
 */
export async function readEvidence(file) {
    if (!file || !existsSync(file)) {
        return new Map();
    }
    const parsed = JSON.parse(await readFile(file, "utf8"));
    const byId = new Map();
    for (const observation of parsed.observations ?? []) {
        if (observation?.finding_id) {
            byId.set(observation.finding_id, observation);
        }
    }
    return byId;
}

/**
 * Load a CVE record from cache, fetching it on demand.
 *
 * @param {string} cveId
 * @param {{cacheDir: string, fetch: boolean}} options
 * @returns {Promise<CveMetadata|null>}
 */
export async function loadCve(cveId, options) {
    const relative = cveListPath(cveId);
    if (relative === null) {
        return null;
    }
    const cached = path.join(options.cacheDir, relative);
    if (existsSync(cached)) {
        try {
            return parseCve(JSON.parse(await readFile(cached, "utf8")));
        } catch {
            // fall through and refetch a corrupt cache entry
        }
    }
    if (!options.fetch) {
        return null;
    }
    const remote = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/${relative}`;
    const record = await fetchJson(remote);
    if (record === null) {
        return null;
    }
    await mkdir(path.dirname(cached), { recursive: true });
    await writeFile(cached, JSON.stringify(record));
    return parseCve(record);
}

/** @param {string} url */
async function fetchJson(url) {
    for (let attempt = 0; attempt < 4; ++attempt) {
        try {
            const response = await fetch(url, {
                headers: { "user-agent": "sentinel-triage/1.0" },
            });
            if (response.status === 404) {
                return null;
            }
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            if (attempt === 3) {
                process.stderr.write(`\nwarning: ${url}: ${error.message}\n`);
                return null;
            }
            await new Promise((resolve) =>
                setTimeout(resolve, 500 * 2 ** attempt),
            );
        }
    }
    return null;
}

/**
 * Run the whole pass.
 *
 * @param {{status: any, evidence: Map<string, any>, cves: Map<string, CveMetadata|null>}} input
 */
export function triage(input) {
    const results = [];
    for (const finding of input.status.findings) {
        const osv =
            String(finding.id ?? "").startsWith("OSV-") ||
            (finding.scanners ?? []).includes("osv");
        const cve = input.cves.get(finding.id) ?? null;
        const verdict = verdictFor(finding, cve, { osv });
        results.push({
            id: String(finding.id ?? ""),
            package: String(finding.package ?? ""),
            version: String(finding.version ?? ""),
            severity: finding.severity ?? null,
            scanners: finding.scanners ?? [],
            ...verdict,
        });
    }
    return results;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
    const options = {
        status: "/var/lib/sentinel/status.json",
        evidence: "/var/lib/sentinel/evidence.json",
        cache: path.join(
            process.env.XDG_CACHE_HOME ?? path.join(homedir(), ".cache"),
            "sentinel-triage",
        ),
        out: null,
        fetch: false,
        concurrency: 6,
        only: null,
        limit: null,
        quiet: false,
        help: false,
    };
    for (let index = 0; index < argv.length; ++index) {
        const arg = argv[index];
        const next = () => {
            const value = argv[++index];
            if (value === undefined) {
                throw new Error(`missing value for ${arg}`);
            }
            return value;
        };
        switch (arg) {
            case "--status":
                options.status = next();
                break;
            case "--evidence":
                options.evidence = next();
                break;
            case "--cache":
                options.cache = next();
                break;
            case "--out":
                options.out = next();
                break;
            case "--fetch":
                options.fetch = true;
                break;
            case "--concurrency":
                options.concurrency = Number(next());
                break;
            case "--only":
                options.only = next().split(",").map((id) => id.trim());
                break;
            case "--limit":
                options.limit = Number(next());
                break;
            case "--quiet":
                options.quiet = true;
                break;
            case "--help":
            case "-h":
                options.help = true;
                break;
            default:
                throw new Error(`unknown argument: ${arg}`);
        }
    }
    return options;
}

/** @param {number} count */
async function pool(items, concurrency, worker) {
    const queue = [...items];
    const workers = Array.from(
        { length: Math.min(concurrency, queue.length) },
        async () => {
            while (queue.length > 0) {
                const item = queue.shift();
                if (item !== undefined) {
                    await worker(item);
                }
            }
        },
    );
    await Promise.all(workers);
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
        process.stdout.write(
            [
                "usage: node tools/triage.mjs [options]",
                "",
                "  --status FILE       status.json (default /var/lib/sentinel/status.json)",
                "  --evidence FILE     evidence.json (optional)",
                "  --cache DIR         CVE cache directory",
                "  --fetch             download missing CVE records",
                "  --concurrency N     parallel downloads (default 6)",
                "  --only IDS          comma separated CVE ids",
                "  --limit N           at most N findings",
                "  --out FILE          write the JSON report",
                "  --quiet             no summary output",
                "",
            ].join("\n"),
        );
        return;
    }

    const status = await readStatus(options.status);
    const evidence = await readEvidence(options.evidence);

    /** @type {any[]} */
    let findings = status.findings;
    if (options.only) {
        const wanted = new Set(options.only);
        findings = findings.filter((finding) => wanted.has(finding.id));
    }
    if (options.limit) {
        findings = findings.slice(0, options.limit);
    }

    const cveIds = [
        ...new Set(
            findings
                .map((finding) => String(finding.id ?? ""))
                .filter((id) => /^CVE-/.test(id)),
        ),
    ];

    /** @type {Map<string, CveMetadata|null>} */
    const cves = new Map();
    let fetched = 0;
    await pool(cveIds, options.concurrency, async (cveId) => {
        const cve = await loadCve(cveId, {
            cacheDir: options.cache,
            fetch: options.fetch,
        });
        cves.set(cveId, cve);
        if (cve) {
            fetched += 1;
        }
    });

    const results = triage({
        status: { ...status, findings },
        evidence,
        cves,
    });
    const { totals, reasons } = summarize(results);

    const report = {
        schema_version: 1,
        generated_at: new Date().toISOString(),
        source: {
            status: options.status,
            evidence: options.evidence,
            cache: options.cache,
        },
        scanned_at: status.scannedAt,
        cves: {
            referenced: cveIds.length,
            resolved: fetched,
        },
        totals,
        reasons,
        findings: results,
    };

    if (options.out) {
        await writeFile(options.out, `${JSON.stringify(report, null, 2)}\n`);
    }

    if (!options.quiet) {
        const total = results.length;
        const percent = (value) =>
            total === 0 ? "0%" : `${Math.round((value / total) * 100)}%`;
        process.stdout.write(
            [
                `findings: ${total}  cves resolved: ${fetched}/${cveIds.length}`,
                `confirmed:  ${totals.confirmed} (${percent(totals.confirmed)})`,
                `unverified: ${totals.unverified} (${percent(totals.unverified)})`,
                `suppressed: ${totals.suppressed} (${percent(totals.suppressed)})`,
                "",
                "reasons:",
                ...Object.entries(reasons)
                    .sort((a, b) => b[1] - a[1])
                    .map(([reason, count]) => `  ${count.toString().padStart(5)}  ${reason}`),
                "",
            ].join("\n"),
        );
        for (const result of results) {
            if (result.verdict === "suppressed") {
                process.stdout.write(
                    `  ${result.id}  ${result.package}@${result.version}  ${result.reasons.join(",")}` +
                        (result.product ? `  [${result.vendor}: ${result.product}]` : "") +
                        "\n",
                );
            }
        }
        const collisions = new Map();
        for (const result of results) {
            if (result.reasons.includes("product-only-match")) {
                collisions.set(
                    result.package,
                    (collisions.get(result.package) ?? 0) + 1,
                );
            }
        }
        if (collisions.size > 0) {
            process.stdout.write("\nneeds review (product name only):\n");
            for (const [packageName, count] of [...collisions]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)) {
                process.stdout.write(
                    `  ${count.toString().padStart(5)}  ${packageName}\n`,
                );
            }
            process.stdout.write("\n");
        }
    }

    if (options.out) {
        process.stdout.write(`report: ${options.out}\n`);
    }
}

const isMain =
    process.argv[1] !== undefined &&
    import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
    main().catch((error) => {
        process.stderr.write(`${error.stack ?? error}\n`);
        process.exitCode = 1;
    });
}
