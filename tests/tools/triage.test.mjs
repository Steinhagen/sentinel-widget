import test from "node:test";
import assert from "node:assert/strict";
import {
    compareVersions,
    cveListPath,
    ignoreEntryOf,
    embedVerdicts,
    evaluateRange,
    evaluateRanges,
    isScopedVendor,
    packageTokensOf,
    parseCve,
    parseIgnoreText,
    parseRanges,
    parseVersion,
    plausibleScheme,
    summarize,
    tokenMatches,
    tokenRelation,
    tokens,
    verdictFor,
} from "../../tools/triage.mjs";

/** A trimmed CVE-2021-35049 record (Fidelis Network/Deception CommandPost). */
const fidelis = parseCve({
    cveMetadata: { cveId: "CVE-2021-35049" },
    containers: {
        cna: {
            affected: [
                {
                    vendor: "Fidelis Cybersecurity",
                    product: "Fidelis Network",
                    versions: [
                        { version: "Fidelis Network 9.4", status: "affected" },
                        {
                            version: "Fidelis Network",
                            lessThan: "9.3.7",
                            versionType: "custom",
                            status: "affected",
                        },
                    ],
                },
            ],
        },
    },
});

/** CVE-2023-45853: MiniZip in the C zlib library. */
const zlibCve = parseCve({
    cveMetadata: { cveId: "CVE-2023-45853" },
    containers: {
        adp: [{
            affected: [{
                vendor: "zlib",
                product: "zlib",
                versions: [{ version: "0", lessThan: "1.3", status: "affected" }],
            }],
        }],
    },
});

const haskellZlib = {
    id: "CVE-2023-45853",
    package: "zlib",
    version: "0.7.1.1",
    origins: {
        introduced_by: ["haskell-language-server-2.13.0.0"],
        chain: ["haskell-language-server-2.13.0.0", "zlib-0.7.1.1"],
        store_paths: ["/nix/store/i0ann5d1v85kfvsz7jfm6agyqbrymdsq-zlib-0.7.1.1"],
    },
};

test("tokens strip non-alphanumerics, trailing digits and filler words", () => {
    assert.deepEqual(tokens("Fidelis Cybersecurity"), ["fidelis", "cybersecurity"]);
    assert.deepEqual(tokens("python3.14"), ["python"]);
    assert.deepEqual(tokens("F-Secure Mobile Security"), [
        "secure",
        "mobile",
        "security",
    ]);
    assert.deepEqual(tokens(""), []);
});

test("tokenMatches accepts a known suffix but not an arbitrary word", () => {
    assert.equal(tokenMatches("cpython", "python"), true);
    assert.equal(tokenMatches("network", "networking"), false);
    assert.equal(tokenMatches("safe", "secure"), false);
});

test("tokenRelation distinguishes equal, overlapping and unrelated names", () => {
    assert.equal(tokenRelation(["ffmpeg"], ["ffmpeg"]), "equal");
    assert.equal(tokenRelation(["network"], ["fidelis", "network"]), "overlap");
    assert.equal(tokenRelation(["safe"], ["secure", "security"]), "none");
});

test("package aliases keep kernel and libupnp matches alive", () => {
    assert.deepEqual(packageTokensOf("linux"), ["linux", "kernel"]);
    assert.deepEqual(packageTokensOf("libupnp"), ["libupnp", "pupnp"]);
    assert.deepEqual(packageTokensOf("ffmpeg"), ["ffmpeg"]);
});

test("distribution and platform vendors are recognised", () => {
    assert.equal(isScopedVendor("Red Hat"), true);
    assert.equal(isScopedVendor("Red Hat Hardened Images"), true);
    assert.equal(isScopedVendor("Apple"), true);
    assert.equal(isScopedVendor("F-Secure"), false);
    assert.equal(isScopedVendor(null), false);
});

test("cveListPath buckets identifiers by their numeric prefix", () => {
    assert.equal(
        cveListPath("CVE-2021-35049"),
        "cves/2021/35xxx/CVE-2021-35049.json",
    );
    assert.equal(cveListPath("CVE-2015-4155"), "cves/2015/4xxx/CVE-2015-4155.json");
    assert.equal(cveListPath("CVE-2000-0006"), "cves/2000/0xxx/CVE-2000-0006.json");
    assert.equal(
        cveListPath("CVE-2026-134289"),
        "cves/2026/134xxx/CVE-2026-134289.json",
    );
    assert.equal(cveListPath("OSV-2026-1"), null);
});

test("versions compare numerically and reject suffixes", () => {
    assert.deepEqual(parseVersion("3.2.8.0"), { components: [3, 2, 8, 0] });
    assert.equal(parseVersion("10.6p1"), null);
    assert.equal(parseVersion("Fidelis Network 9.4"), null);
    assert.equal(compareVersions(parseVersion("3.2.8.0"), parseVersion("9.3.7")), -1);
    assert.equal(compareVersions(parseVersion("9.3.7"), parseVersion("9.3.7.0")), 0);
    assert.equal(plausibleScheme(parseVersion("3.2.2.0"), parseVersion("20150422")), false);
});

test("a version paired with lessThan is the start of a range", () => {
    const ranges = parseRanges([
        { version: "7.1", lessThanOrEqual: "9.0.2", status: "affected" },
        { version: "3.4.8", status: "affected" },
    ]);
    assert.deepEqual(ranges[0], {
        exact: null,
        startIncluding: "7.1",
        startExcluding: null,
        endIncluding: "9.0.2",
        endExcluding: null,
    });
    assert.equal(ranges[1].exact, "3.4.8");
    assert.equal(evaluateRange("9.0.2", ranges[0]), "affected");
    assert.equal(evaluateRange("7.0.0", ranges[0]), "not-affected");
});

test("ranges skip product names and non-affected entries", () => {
    const ranges = parseRanges([
        { version: "Fidelis Network 9.4", status: "affected" },
        { version: "0", status: "unaffected" },
        { lessThan: "9.3.7", status: "affected" },
    ]);
    assert.equal(ranges.length, 1);
    assert.equal(ranges[0].endExcluding, "9.3.7");
});

test("evaluateRanges aggregates affected, unaffected and incomparable data", () => {
    const ranges = parseRanges([{ version: "1.0", lessThan: "2.0", status: "affected" }]);
    assert.equal(evaluateRanges("1.5", ranges), "affected");
    assert.equal(evaluateRanges("2.5", ranges), "not-affected");
    assert.equal(evaluateRanges("1.5", []), "no-ranges");
    assert.equal(
        evaluateRanges("3.2.2.0", parseRanges([{ lessThan: "20150422", status: "affected" }])),
        "unknown",
    );
});

test("parseCve extracts vendor, product and ranges", () => {
    assert.equal(fidelis.id, "CVE-2021-35049");
    assert.equal(fidelis.products.length, 1);
    assert.equal(fidelis.products[0].vendor, "Fidelis Cybersecurity");
    assert.equal(fidelis.products[0].product, "Fidelis Network");
    assert.equal(fidelis.products[0].ranges.length, 1);
});

test("a same-name Haskell package is not confirmed by a product match alone", () => {
    const result = verdictFor(
        { package: "network", version: "3.2.8.0" },
        fidelis,
    );
    assert.equal(result.verdict, "unverified");
    assert.deepEqual(result.reasons, ["product-only-match"]);
    assert.equal(result.vendor, "Fidelis Cybersecurity");
    assert.equal(result.product, "Fidelis Network");
});

test("a real Fidelis version is confirmed when the range covers it", () => {
    const result = verdictFor(
        { package: "fidelis-network", version: "9.3.0" },
        fidelis,
    );
    assert.equal(result.verdict, "confirmed");
    assert.deepEqual(result.reasons, ["version-in-range"]);
});

test("an installed version outside the range is suppressed", () => {
    const result = verdictFor(
        { package: "fidelis-network", version: "9.4.0" },
        fidelis,
    );
    assert.equal(result.verdict, "suppressed");
    assert.deepEqual(result.reasons, ["version-not-affected"]);
});

test("distribution-scoped CVEs stay visible for review", () => {
    const redhat = parseCve({
        cveMetadata: { cveId: "CVE-2026-55654" },
        containers: {
            cna: {
                affected: [
                    {
                        vendor: "Red Hat",
                        product: "Red Hat Enterprise Linux 10",
                        versions: [{ version: "0", status: "affected" }],
                    },
                ],
            },
        },
    });
    const result = verdictFor({ package: "openssh", version: "10.6p1" }, redhat);
    assert.equal(result.verdict, "unverified");
    assert.deepEqual(result.reasons, ["vendor-scoped-cve"]);
});

test("kernel aliases connect linux to the kernel product", () => {
    const kernel = parseCve({
        cveMetadata: { cveId: "CVE-2026-1" },
        containers: {
            cna: {
                affected: [
                    {
                        vendor: "Linux Kernel",
                        product: "kernel",
                        versions: [{ version: "4.0", lessThan: "6.0", status: "affected" }],
                    },
                ],
            },
        },
    });
    const fixed = verdictFor({ package: "linux", version: "7.3.5" }, kernel);
    assert.equal(fixed.verdict, "suppressed");
    assert.deepEqual(fixed.reasons, ["version-not-affected"]);
    const affected = verdictFor({ package: "linux", version: "5.15.0" }, kernel);
    assert.equal(affected.verdict, "confirmed");
});

test("tracker and OSV verdicts short-circuit the identity checks", () => {
    const published = verdictFor(
        { package: "ffmpeg", version: "1", tracker: { status: "published" } },
        null,
    );
    assert.deepEqual(published, {
        verdict: "confirmed",
        reasons: ["tracker-published"],
        vendor: null,
        product: null,
        identity: null,
    });
    const rejected = verdictFor(
        { package: "ffmpeg", version: "1", tracker: { status: "rejected" } },
        null,
    );
    assert.equal(rejected.verdict, "suppressed");
    const unaffected = verdictFor(
        { package: "ffmpeg", version: "1", tracker: { master_status: "unaffected" } },
        null,
    );
    assert.equal(unaffected.verdict, "suppressed");
    const osv = verdictFor({ package: "openexr", version: "1" }, null, { osv: true });
    assert.deepEqual(osv.reasons, ["osv-advisory"]);
});

test("missing data is unverified, never suppressed", () => {
    assert.deepEqual(verdictFor({ package: "x", version: "1" }, null), {
        verdict: "unverified",
        reasons: ["no-cve-data"],
        vendor: null,
        product: null,
        identity: null,
    });
    const empty = parseCve({ cveMetadata: { cveId: "CVE-2026-2" }, containers: {} });
    assert.deepEqual(verdictFor({ package: "x", version: "1" }, empty).reasons, [
        "no-affected-data",
    ]);
});

test("a conflicting tracker verdict downgrades an out-of-range match", () => {
    const result = verdictFor(
        {
            package: "fidelis-network",
            version: "9.4.0",
            tracker: { master_status: "affected" },
        },
        fidelis,
    );
    assert.equal(result.verdict, "unverified");
    assert.deepEqual(result.reasons, ["version-conflict-with-tracker"]);
});

test("summarize counts verdicts and reasons", () => {
    const counts = summarize([
        { verdict: "confirmed", reasons: ["version-in-range"] },
        { verdict: "confirmed", reasons: ["version-in-range"] },
        { verdict: "suppressed", reasons: ["identity-mismatch"] },
        { verdict: "unverified", reasons: [] },
    ]);
    assert.deepEqual(counts.totals, {
        confirmed: 2,
        unverified: 1,
        suppressed: 1,
    });
    assert.equal(counts.reasons["version-in-range"], 2);
    assert.equal(counts.reasons["identity-mismatch"], 1);
});

test("parseIgnoreText reads a dismissal list", () => {
    const parsed = parseIgnoreText(JSON.stringify([
        { cve: "CVE-2021-24028", package: "thrift", reason: "Facebook Thrift" },
        { cve: "CVE-2021-2", package: "network" },
        { cve: "", package: "ignored" },
        { package: "ignored" },
    ]));
    assert.equal(parsed.ok, true);
    assert.equal(parsed.count, 2);
    assert.equal(parsed.byPair["CVE-2021-24028|thrift"].reason, "Facebook Thrift");
    assert.deepEqual(ignoreEntryOf(
        { id: "CVE-2021-24028", package: "thrift" }, parsed), {
        reason: "Facebook Thrift",
    });
    assert.equal(ignoreEntryOf(
        { id: "CVE-2021-24028", package: "apache-thrift" }, parsed), null);
});

test("parseIgnoreText accepts wrapped and bare forms, rejects junk", () => {
    const entry = [{ cve: "CVE-2021-24028", package: "thrift" }];
    assert.equal(parseIgnoreText(JSON.stringify(entry)).ok, true);
    assert.equal(parseIgnoreText(JSON.stringify({ entries: entry })).ok, true);
    assert.equal(parseIgnoreText(JSON.stringify({ ignored: entry })).ok, true);
    assert.equal(parseIgnoreText("").ok, false);
    assert.equal(parseIgnoreText("{ nope").ok, false);
    assert.equal(parseIgnoreText('{"entries": 3}').ok, false);
    assert.equal(parseIgnoreText('{"entries": []}').ok, true);
});

test("a manual dismissal suppresses the pair", () => {
    const ignore = parseIgnoreText(JSON.stringify([
        { cve: "CVE-2021-35049", package: "network", reason: "Fidelis" },
    ]));
    const result = verdictFor(
        { id: "CVE-2021-35049", package: "network", version: "3.2.8.0" },
        fidelis, { ignore });
    assert.equal(result.verdict, "suppressed");
    assert.deepEqual(result.reasons, ["manual-ignore"]);
});

test("a tracker confirmation wins over a manual dismissal", () => {
    const ignore = parseIgnoreText(JSON.stringify([
        { cve: "CVE-2021-35049", package: "network" },
    ]));
    const result = verdictFor(
        {
            id: "CVE-2021-35049",
            package: "network",
            version: "3.2.8.0",
            tracker: { status: "published" },
        },
        fidelis,
        { ignore });
    assert.equal(result.verdict, "confirmed");
    assert.deepEqual(result.reasons, ["tracker-published"]);
});

test("dismissals are scoped to one package", () => {
    const ignore = parseIgnoreText(JSON.stringify([
        { cve: "CVE-2021-35049", package: "other-package" },
    ]));
    const result = verdictFor(
        { id: "CVE-2021-35049", package: "network", version: "3.2.8.0" },
        fidelis, { ignore });
    assert.equal(result.verdict, "unverified");
});

test("embedVerdicts writes the verdicts into the findings", () => {
    const status = {
        vulnerabilities: [
            { id: "CVE-2021-24028", package: "thrift", version: "0.25.0" },
            { id: "CVE-2026-1", package: "ffmpeg", version: "9.0.2" },
            { id: "CVE-2026-2", package: "other", version: "1" },
        ],
    };
    const updated = embedVerdicts(status, [
        {
            id: "CVE-2021-24028",
            package: "thrift",
            version: "0.25.0",
            verdict: "unverified",
            reasons: ["product-only-match"],
            vendor: "Facebook",
            product: "Facebook Thrift",
        },
        {
            id: "CVE-2026-1",
            package: "ffmpeg",
            version: "9.0.2",
            verdict: "confirmed",
            reasons: ["version-in-range"],
        },
    ]);
    assert.equal(updated, 2);
    assert.equal(status.vulnerabilities[0].verdict, "unverified");
    assert.deepEqual(status.vulnerabilities[0].verdict_reasons, ["product-only-match"]);
    assert.equal(status.vulnerabilities[0].verdict_vendor, "Facebook");
    assert.equal(status.vulnerabilities[0].verdict_product, "Facebook Thrift");
    assert.equal(status.vulnerabilities[1].verdict, "confirmed");
    assert.equal("verdict_vendor" in status.vulnerabilities[1], false);
    assert.equal("verdict" in status.vulnerabilities[2], false);
});

test("a Haskell binding is checked against the linked C library version", () => {
    const result = verdictFor(haskellZlib, zlibCve, {
        resolveLibraryVersion: () => "1.3.2",
    });
    assert.equal(result.verdict, "suppressed");
    assert.deepEqual(result.reasons, ["binding-library-unaffected"]);
    assert.equal(result.vendor, "zlib");
    assert.equal(result.product, "zlib");
});

test("a binding with an affected C library stays confirmed", () => {
    const result = verdictFor(haskellZlib, zlibCve, {
        resolveLibraryVersion: () => "1.2.13",
    });
    assert.equal(result.verdict, "confirmed");
    assert.deepEqual(result.reasons, ["binding-library-in-range"]);
});

test("an unknown binding version is unverified", () => {
    const result = verdictFor(haskellZlib, zlibCve, {
        resolveLibraryVersion: () => "",
    });
    assert.equal(result.verdict, "unverified");
    assert.deepEqual(result.reasons, ["binding-version-unknown"]);
});

test("the 0.x version fallback still recognises the Haskell binding", () => {
    const result = verdictFor({
        id: "CVE-2023-45853",
        package: "zlib",
        version: "0.7.1.1",
    }, zlibCve, {
        resolveLibraryVersion: () => "1.3.2",
    });
    assert.equal(result.verdict, "suppressed");
});

test("the C library finding keeps the normal version gate", () => {
    const result = verdictFor({
        id: "CVE-2023-45853",
        package: "zlib",
        version: "1.2.13",
        origins: {
            introduced_by: ["crossover-26.3.0"],
            chain: ["zlib-1.2.13"],
        },
    }, zlibCve);
    assert.equal(result.verdict, "confirmed");
    assert.deepEqual(result.reasons, ["version-in-range"]);
});
