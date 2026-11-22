import test from "node:test";
import assert from "node:assert/strict";
import { apply, countsOf, empty, isActive, matches } from "../../contents/ui/domain/filters.mjs";
import { buildRows } from "../../contents/ui/domain/table.mjs";
import { v7 } from "../helpers/fixtures.mjs";

const rows = buildRows(v7.vulnerabilities, {
    systemChannel: v7.tracker.system_channel,
    checked: {}
});

test("empty state is inactive", () => {
    assert.equal(isActive(empty()), false);
    assert.equal(isActive({ text: "x" }), true);
    assert.equal(isActive({ severity: "high" }), true);
    assert.equal(isActive({ fixState: "fixed" }), true);
    assert.equal(isActive({ trackerState: "missing" }), true);
    assert.equal(isActive({ package: "zlib" }), true);
    assert.equal(isActive({ origin: "curl" }), true);
    assert.equal(isActive({ cve: "CVE-2026-111497" }), true);
});

test("search is case-insensitive and covers CVE, package and origin", () => {
    assert.equal(apply(rows, { text: "brotli" }).length, 1);
    assert.equal(apply(rows, { text: "CVE-2026-111497" }).length, 1);
    assert.equal(apply(rows, { text: "imagemagick" }).length >= 1, true);
    assert.equal(apply(rows, { text: "no-such-thing" }).length, 0);
});

test("severity, fix and tracker filters compose", () => {
    const critical = apply(rows, { severity: "critical" });
    assert.ok(critical.length > 0);
    assert.ok(critical.every((row) => row.severityBand === "critical"));

    const fixed = apply(rows, { fixState: "fixed" });
    assert.ok(fixed.length > 0);
    assert.ok(fixed.every((row) => row.fix.bucket === "fixed"));

    const missing = apply(rows, { trackerState: "missing" });
    assert.ok(missing.length > 0);
    assert.ok(missing.every((row) => row.trackerState === "missing"));

    const combined = apply(rows, {
        severity: "critical",
        fixState: "fixed",
        trackerState: "linked"
    });
    assert.ok(combined.every((row) =>
        row.severityBand === "critical"
        && row.fix.bucket === "fixed"
        && row.trackerState === "found"));
});

test("package and origin drill-down use substrings", () => {
    assert.ok(apply(rows, { package: "brot" }).length >= 1);
    assert.ok(apply(rows, { origin: "imagemagick" }).length >= 1);
    assert.ok(apply(rows, { package: "brot", origin: "imagemagick" }).length >= 1);
});

test("CVE filter is a case-insensitive substring", () => {
    assert.equal(apply(rows, { cve: "CVE-2026-111497" }).length, 1);
    assert.equal(apply(rows, { cve: "111497" }).length, 1);
    assert.equal(apply(rows, { cve: "not-a-cve" }).length, 0);
    assert.equal(apply(rows, { cve: "111497", package: "brotli" }).length, 1);
});

test("aggregate counts cover every row", () => {
    const counts = countsOf(rows);
    const severityTotal = Object.values(counts.severity).reduce((a, b) => a + b, 0);
    const fixTotal = Object.values(counts.fix).reduce((a, b) => a + b, 0);
    assert.equal(severityTotal, rows.length);
    assert.equal(counts.tracker.linked + counts.tracker.missing + counts.tracker.unchecked, rows.length);
    assert.ok(fixTotal <= rows.length);
    assert.ok(counts.severity.critical > 0);
    assert.ok(counts.fix.fixed > 0);
    assert.ok(counts.tracker.linked > 0);
});

test("matches is usable on a single row", () => {
    assert.equal(matches(rows[0], empty()), true);
    assert.equal(matches(rows[0], { text: "definitely-not-here" }), false);
});
