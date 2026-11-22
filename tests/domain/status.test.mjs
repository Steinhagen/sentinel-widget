import test from "node:test";
import assert from "node:assert/strict";
import {
    countPackages,
    normalizeReport,
    normalizeSeverityCounts,
    parseStatusText,
    parseTimestamp,
    stampOf
} from "../../contents/ui/domain/status.mjs";
import { legacyRaw, v7, v7Raw } from "../helpers/fixtures.mjs";

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

test("parse a v7 status file", () => {
    const result = parseStatusText(JSON.stringify(v7Raw));
    assert.equal(result.ok, true);
    const report = result.report;
    assert.equal(report.schemaVersion, 7);
    assert.equal(report.schemaNewer, false);
    assert.equal(report.state, "vulnerable");
    assert.equal(report.findings, 13);
    assert.equal(report.vulnerabilities.length, 13);
    assert.equal(report.maxSeverity, 9.9);
    assert.deepEqual(report.severityCounts,
        { critical: 5, high: 4, medium: 2, low: 0, unknown: 2 });
    assert.equal(report.scannedAtMs, 1795359935000);
    assert.equal(report.stamp, "2026-11-22T17:05:35+02:00");
    assert.ok(report.fingerprint.length === 8);
    assert.ok(report.trackerFingerprint.length === 8);
});

test("legacy top and fallback counts", () => {
    const result = parseStatusText(JSON.stringify(legacyRaw));
    assert.equal(result.ok, true);
    const report = result.report;
    assert.equal(report.schemaVersion, 0);
    assert.equal(report.vulnerabilities.length, 2);
    assert.equal(report.findings, 2);
    assert.deepEqual(report.severityCounts,
        { critical: 1, high: 0, medium: 0, low: 0, unknown: 1 });
    assert.ok(report.scannedAtMs > 0);
    assert.equal(report.tracker, null);
});

test("corrupt and empty files are invalid-json", () => {
    assert.deepEqual(parseStatusText(""), { ok: false, error: "invalid-json" });
    assert.deepEqual(parseStatusText("{ nope"), { ok: false, error: "invalid-json" });
    assert.deepEqual(parseStatusText("[]"), { ok: false, error: "invalid-json" });
});

test("missing fields produce a safe report", () => {
    const report = normalizeReport({});
    assert.equal(report.state, "unknown");
    assert.equal(report.findings, 0);
    assert.equal(report.maxSeverity, 0);
    assert.equal(report.packagesAffected, 0);
    assert.deepEqual(report.severityCounts,
        { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
    assert.equal(report.scannedAtMs, null);
    assert.deepEqual(report.vulnerabilities, []);
    assert.equal(report.tracker, null);
    assert.equal(report.fingerprint.length, 8);
    assert.equal(report.trackerFingerprint, "");
});

test("a newer schema renders known fields and is flagged", () => {
    const report = normalizeReport({ schema_version: 99, state: "secure" });
    assert.equal(report.schemaNewer, true);
    assert.equal(report.state, "secure");
});

test("fingerprints detect row-relevant changes", () => {
    const base = normalizeReport(clone(v7Raw));

    const severityChanged = clone(v7Raw);
    severityChanged.vulnerabilities[0].severity = 1.0;
    assert.notEqual(normalizeReport(severityChanged).fingerprint, base.fingerprint);

    const branchChanged = clone(v7Raw);
    branchChanged.vulnerabilities[0].tracker.fix_branches[0].version = "9.9.9";
    assert.notEqual(normalizeReport(branchChanged).fingerprint, base.fingerprint);

    const chainChanged = clone(v7Raw);
    chainChanged.vulnerabilities[0].origins.chains = [["different"]];
    assert.notEqual(normalizeReport(chainChanged).fingerprint, base.fingerprint);

    const trackerOnly = clone(v7Raw);
    trackerOnly.tracker.updated_at = "2026-11-22T18:00:00+02:00";
    const report = normalizeReport(trackerOnly);
    assert.equal(report.fingerprint, base.fingerprint);
    assert.notEqual(report.trackerFingerprint, base.trackerFingerprint);
});

test("timestamps prefer epoch, then ISO, then legacy local", () => {
    assert.equal(parseTimestamp({ scanned_at_epoch: 10 }), 10000);
    assert.equal(parseTimestamp({ scanned_at_iso: "2026-11-22T17:05:35+02:00" }),
        Date.parse("2026-11-22T17:05:35+02:00"));
    assert.equal(parseTimestamp({ scanned_at: "not a date" }), null);
    assert.equal(parseTimestamp(null), null);
    const legacy = parseTimestamp({ scanned_at: "2026-11-20 08:15 UTC" });
    assert.ok(legacy > 0);
});

test("stamp and package helpers", () => {
    assert.equal(stampOf({ scanned_at: "a", scanned_at_iso: "b" }), "b");
    assert.equal(stampOf({ scanned_at: "a" }), "a");
    assert.equal(stampOf(null), "");
    assert.equal(countPackages([{ package: "a" }, { package: "a" }, { package: "b" }, {}]), 2);
    assert.deepEqual(
        normalizeSeverityCounts(null, [{ severity: 9 }, { severity: 0 }]),
        { critical: 1, high: 0, medium: 0, low: 0, unknown: 1 }
    );
});

test("the fixture normalizes origins and tracker fields", () => {
    const item = v7.vulnerabilities.find((v) => v.id === "CVE-2026-111497");
    assert.equal(item.id, "CVE-2026-111497");
    assert.ok(Array.isArray(item.origins.chain));
    assert.equal(item.tracker.fix_state, "fixed");
});
