import test from "node:test";
import assert from "node:assert/strict";
import {
    detailsOf,
    hideOsvFindings,
    isForcedVisible,
    isIgnored,
    isOsvFinding,
    isVerdict,
    keyOf,
    parseTriageText,
    reasonsOf,
    reviewCount,
    suppressedCount,
    verdictOf,
    visibleFindings,
} from "../../contents/ui/domain/triage.mjs";

const report = {
    findings: [
        {
            id: "CVE-2021-35049",
            package: "network",
            version: "3.2.8.0",
            verdict: "unverified",
            reasons: ["product-only-match"],
        },
        {
            id: "CVE-2026-1",
            package: "ffmpeg",
            version: "9.0.2",
            verdict: "suppressed",
            reasons: ["version-not-affected"],
        },
        {
            id: "CVE-2026-2",
            package: "zlib",
            version: "1.3.2",
            verdict: "confirmed",
            reasons: ["version-in-range"],
        },
    ],
};

test("keyOf identifies a finding across both files", () => {
    assert.equal(
        keyOf({ id: "CVE-2021-35049", package: "network", version: "3.2.8.0" }),
        "CVE-2021-35049|network|3.2.8.0",
    );
    assert.equal(keyOf({}), "||");
});

test("isVerdict accepts only the three verdicts", () => {
    assert.equal(isVerdict("confirmed"), true);
    assert.equal(isVerdict("suppressed"), true);
    assert.equal(isVerdict("unverified"), true);
    assert.equal(isVerdict("maybe"), false);
    assert.equal(isVerdict(""), false);
});

test("parseTriageText reads a tool report and counts the verdicts", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    assert.equal(parsed.ok, true);
    assert.deepEqual(parsed.counts, {
        confirmed: 1,
        unverified: 1,
        suppressed: 1,
    });
    assert.equal(
        parsed.byKey["CVE-2021-35049|network|3.2.8.0"].verdict,
        "unverified",
    );
    assert.ok(parsed.fingerprint.length > 0);
});

test("parseTriageText accepts a bare array and rejects junk", () => {
    assert.equal(parseTriageText(JSON.stringify(report.findings)).ok, true);
    assert.equal(parseTriageText("").ok, false);
    assert.equal(parseTriageText("{ nope").ok, false);
    assert.equal(parseTriageText('{"findings": 3}').ok, false);
    assert.equal(parseTriageText('{"findings": []}').ok, true);
});

test("OSV advisories can be hidden independently", () => {
    const findings = [
        { id: "OSV-2026-1", package: "a", version: "1" },
        { id: "CVE-2026-1", package: "b", version: "1" },
    ];
    assert.equal(isOsvFinding(findings[0]), true);
    assert.equal(isOsvFinding(findings[1]), false);
    assert.equal(hideOsvFindings(findings, true).length, 1);
    assert.equal(hideOsvFindings(findings, false).length, 2);
});

test("the sidecar verdict is looked up by id, package and version", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const finding = { id: "CVE-2026-1", package: "ffmpeg", version: "9.0.2" };
    assert.equal(verdictOf(finding, parsed), "suppressed");
    assert.deepEqual(reasonsOf(finding, parsed), ["version-not-affected"]);

    const otherVersion = { id: "CVE-2026-1", package: "ffmpeg", version: "8.0" };
    assert.equal(verdictOf(otherVersion, parsed), "");
    assert.deepEqual(verdictOf({}, parsed), "");
});

test("an embedded verdict wins over the sidecar", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const finding = {
        id: "CVE-2021-35049",
        package: "network",
        version: "3.2.8.0",
        verdict: "confirmed",
        verdict_reasons: ["tracker-published"],
    };
    assert.equal(verdictOf(finding, parsed), "confirmed");
    assert.deepEqual(reasonsOf(finding, parsed), ["tracker-published"]);
});

test("visibleFindings hides suppressed findings only when enabled", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const all = report.findings;
    const plain = all.map(({ verdict, reasons, ...rest }) => rest);
    assert.equal(visibleFindings(all, parsed, true).length, 2);
    assert.equal(visibleFindings(all, parsed, false).length, 3);
    assert.equal(visibleFindings(plain, null, true).length, 3);
    assert.equal(suppressedCount(all, parsed, true), 1);
    assert.equal(suppressedCount(all, parsed, false), 0);
    assert.equal(suppressedCount(plain, null, true), 0);
});

test("embedded suppressed verdicts hide without a sidecar", () => {
    assert.equal(visibleFindings(report.findings, null, true).length, 2);
    assert.equal(suppressedCount(report.findings, null, true), 1);
});

test("unverified findings can be hidden independently", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const all = report.findings;
    assert.equal(visibleFindings(all, parsed, true, [], true).length, 1);
    assert.equal(visibleFindings(all, parsed, false, [], true).length, 2);
    assert.equal(visibleFindings(all, parsed, true, [], false).length, 2);
    assert.equal(reviewCount(all, parsed, true), 1);
    assert.equal(reviewCount(all, parsed, false), 0);

    // Embedded verdicts work without a sidecar report.
    const unverified = report.findings[0];
    assert.equal(visibleFindings([unverified], null, true, [], true).length, 0);
    assert.equal(reviewCount([unverified], null, true), 1);
});

test("only suppressed findings are removed", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const visible = visibleFindings(report.findings, parsed, true);
    assert.deepEqual(
        visible.map((finding) => finding.id),
        ["CVE-2021-35049", "CVE-2026-2"],
    );
});

test("a pair ignored from the applet is suppressed without a report", () => {
    const findings = [
        { id: "CVE-2021-24028", package: "thrift", version: "0.25.0" },
        { id: "CVE-2026-1", package: "ffmpeg", version: "9.0.2" },
    ];
    const pairs = [{ cve: "CVE-2021-24028", package: "thrift" }];

    assert.equal(isIgnored(findings[0], pairs), true);
    assert.equal(isIgnored({ id: "CVE-2021-24028", package: "apache-thrift" }, pairs), false);
    assert.equal(isIgnored(findings[1], pairs), false);
    assert.equal(isIgnored(findings[0], []), false);

    assert.equal(visibleFindings(findings, null, true, pairs).length, 1);
    assert.equal(suppressedCount(findings, null, true, pairs), 1);
    // A manual ignore is an explicit user decision: it holds even when the
    // triage-verdict setting is off.
    assert.equal(visibleFindings(findings, null, false, pairs).length, 1);
    assert.equal(suppressedCount(findings, null, false, pairs), 1);
});

test("a versioned ignore only hides that exact version", () => {
    const findings = [
        { id: "CVE-2026-1", package: "ffmpeg", version: "6.1.6" },
        { id: "CVE-2026-1", package: "ffmpeg", version: "6.1.7" },
    ];
    const versioned = [{ cve: "CVE-2026-1", package: "ffmpeg", version: "6.1.6" }];
    assert.equal(isIgnored(findings[0], versioned), true);
    assert.equal(isIgnored(findings[1], versioned), false);
    assert.equal(visibleFindings(findings, null, true, versioned).length, 1);

    // Old entries without a version keep the package-wide behaviour.
    const legacy = [{ cve: "CVE-2026-1", package: "ffmpeg" }];
    assert.equal(isIgnored(findings[0], legacy), true);
    assert.equal(isIgnored(findings[1], legacy), true);
});

test("a forced-visible finding bypasses triage and OSV hiding", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const suppressed = report.findings.find((finding) => finding.verdict === "suppressed");
    const forced = [{ cve: suppressed.id, package: suppressed.package, version: suppressed.version }];
    assert.equal(isForcedVisible(suppressed, forced), true);
    assert.equal(isForcedVisible({ ...suppressed, version: "other" }, forced), false);
    assert.equal(visibleFindings(report.findings, parsed, true, [], false, forced)
        .some((finding) => finding.id === suppressed.id), true);

    const osv = { id: "OSV-2026-1", package: "a", version: "1" };
    const osvForced = [{ cve: osv.id, package: osv.package, version: osv.version }];
    assert.equal(hideOsvFindings([osv], true).length, 0);
    assert.equal(hideOsvFindings([osv], true, osvForced).length, 1);
});

test("suppressedCount counts ignores but not disabled verdicts", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const pairs = [{ cve: "CVE-2021-24028", package: "thrift" }];
    const findings = report.findings.concat([
        { id: "CVE-2021-24028", package: "thrift", version: "0.25.0" },
    ]);
    assert.equal(suppressedCount(findings, parsed, false, pairs), 1);
    assert.equal(suppressedCount(findings, parsed, true, pairs), 2);
});

test("ignored pairs and report verdicts hide together", () => {
    const parsed = parseTriageText(JSON.stringify(report));
    const pairs = [{ cve: "CVE-2021-24028", package: "thrift" }];
    const findings = report.findings.concat([
        { id: "CVE-2021-24028", package: "thrift", version: "0.25.0" },
    ]);
    assert.equal(suppressedCount(findings, parsed, true, pairs), 2);
    assert.equal(visibleFindings(findings, parsed, true, pairs).length, 2);
});

test("parseTriageText keeps the CVE identity for the tooltip", () => {
    const parsed = parseTriageText(JSON.stringify({
        findings: [{
            id: "CVE-2021-24028",
            package: "thrift",
            version: "0.25.0",
            verdict: "unverified",
            reasons: ["product-only-match"],
            vendor: "Facebook",
            product: "Facebook Thrift",
        }],
    }));
    const details = detailsOf(
        { id: "CVE-2021-24028", package: "thrift", version: "0.25.0" }, parsed);
    assert.deepEqual(details, {
        verdict: "unverified",
        reasons: ["product-only-match"],
        vendor: "Facebook",
        product: "Facebook Thrift",
    });
    assert.deepEqual(detailsOf({ id: "CVE-2021-24028", package: "other" }, parsed), {
        verdict: "",
        reasons: [],
        vendor: "",
        product: "",
    });
});

test("detailsOf falls back to an embedded verdict", () => {
    const details = detailsOf({
        id: "CVE-2026-1",
        package: "ffmpeg",
        version: "9.0.2",
        verdict: "unverified",
        verdict_reasons: ["no-version-range"],
        verdict_vendor: "Facebook",
        verdict_product: "Facebook Thrift",
    }, null);
    assert.deepEqual(details, {
        verdict: "unverified",
        reasons: ["no-version-range"],
        vendor: "Facebook",
        product: "Facebook Thrift",
    });
});
