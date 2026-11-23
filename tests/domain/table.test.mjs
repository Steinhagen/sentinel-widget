import test from "node:test";
import assert from "node:assert/strict";
import {
    buildFindingRow,
    buildRows,
    compareRows,
    findingCount,
    flattenGroups,
    groupKeysOf,
    sortRows,
    valueOf
} from "../../contents/ui/domain/table.mjs";
import { v7 } from "../helpers/fixtures.mjs";

const context = { systemChannel: "nixos-unstable", checked: {}, source: v7.source };
const rows = buildRows(v7.vulnerabilities, context);

test("a view row carries display data and tokens", () => {
    const row = buildFindingRow(v7.vulnerabilities.find((v) => v.id === "CVE-2026-111497"), context);
    assert.equal(row.rowType, "finding");
    assert.equal(row.severityText, "9.8");
    assert.equal(row.severityBand, "critical");
    assert.equal(row.severityValue, 9.8);
    assert.equal(row.fix.bucket, "fixed");
    assert.equal(row.fix.labelKey, "fixed");
    assert.equal(row.origin.primary, "imagemagick-7.1.2-35");
    assert.equal(row.trackerState, "found");
    assert.equal(row.sourceText, "nixpkgs/nixos-unstable (2786a2a)");
    assert.equal(row.source.rev, "2786a2a72088ecf32aea5b3ec52099e6a7cff78f");
    assert.ok(row.searchText.includes("cve-2026-111497"));
    assert.ok(row.originSearch.includes("imagemagick"));
});

test("a finding source overrides the report source", () => {
    const shown = buildFindingRow({
        id: "CVE-2026-0002",
        package: "zlib",
        source: { flake: "sentinel-widget", ref: "main", rev: "abcdef0123456789" }
    }, context);
    assert.equal(shown.sourceText, "sentinel-widget/main (abcdef0)");

    const fallback = buildFindingRow({ id: "CVE-2026-0003", package: "zlib" }, context);
    assert.equal(fallback.sourceText, "nixpkgs/nixos-unstable (2786a2a)");

    const missing = buildFindingRow({ id: "CVE-2026-0004", package: "zlib" }, {});
    assert.equal(missing.sourceText, "");
    assert.equal(missing.source, null);
});

test("buildRows keeps the input order and count", () => {
    assert.equal(rows.length, 13);
    assert.equal(rows[0].id, "CVE-2026-111497");
    assert.equal(rows[12].id, "CVE-2099-0005");
});

test("sorting handles numeric and text columns", () => {
    const bySeverity = sortRows(rows.slice(), "severity", true);
    assert.equal(bySeverity[0].severityValue, 9.9);
    const bySeverityAsc = sortRows(rows.slice(), "severity", false);
    assert.equal(bySeverityAsc[0].severityValue, 0);
    const byCve = sortRows(rows.slice(), "cve", false);
    assert.ok(byCve[0].id <= byCve[byCve.length - 1].id);
    const byPackage = sortRows(rows.slice(), "package", false);
    assert.ok(byPackage[0].package <= byPackage[byPackage.length - 1].package);
});

test("row values are stable for each column", () => {
    const row = rows[0];
    assert.equal(valueOf(row, "severity"), row.severityValue);
    assert.equal(valueOf(row, "cve"), row.id);
    assert.equal(valueOf(row, "package"), row.package);
    assert.equal(valueOf(row, "origin"), row.originSearch);
    assert.equal(valueOf(row, "version"), row.version);
    assert.equal(valueOf(row, "nope"), "");
    assert.equal(compareRows(row, row, "severity", true), 0);
});

test("grouping is flat, ordered and complete", () => {
    const sorted = sortRows(rows.slice(), "severity", true);
    const grouped = flattenGroups(sorted);
    assert.equal(findingCount(grouped), sorted.length);

    let currentGroup = null;
    for (const entry of grouped) {
        if (entry.rowType === "group") {
            currentGroup = entry;
            assert.ok(entry.count > 0);
        } else {
            assert.equal(entry.rowType, "finding");
            assert.equal(entry.origin.groupKey, currentGroup.key);
        }
    }

    // Group order: highest max severity first, then larger groups, then name.
    const headers = grouped.filter((entry) => entry.rowType === "group");
    for (let i = 1; i < headers.length; ++i) {
        const a = headers[i - 1];
        const b = headers[i];
        assert.ok(a.maxSeverity > b.maxSeverity
            || (a.maxSeverity === b.maxSeverity && a.count >= b.count));
    }
});

test("grouping does not mutate the input rows", () => {
    const before = rows.map((row) => row.id).join(",");
    flattenGroups(rows);
    assert.equal(rows.map((row) => row.id).join(","), before);
});

test("grouping modes use priority, package and origin keys", () => {
    const priority = flattenGroups(rows, "priority", true);
    const priorityHeaders = priority.filter((entry) => entry.rowType === "group");
    assert.deepEqual(priorityHeaders.map((entry) => entry.key),
        ["critical", "high", "medium", "unknown"]);
    assert.ok(priorityHeaders.every((entry) => entry.groupBy === "priority"));
    assert.equal(findingCount(priority), rows.length);

    const packages = flattenGroups(rows, "package", true);
    const packageHeaders = packages.filter((entry) => entry.rowType === "group");
    assert.ok(packageHeaders.length > 0);
    assert.ok(packageHeaders.every((entry) => entry.groupBy === "package"));
    assert.equal(findingCount(packages), rows.length);

    const origins = flattenGroups(rows, "origin", true);
    assert.ok(origins.filter((entry) => entry.rowType === "group")
        .every((entry) => entry.groupBy === "origin"));
});

test("collapsed groups keep only headers and full counts", () => {
    const collapsed = flattenGroups(rows, "package", false);
    assert.ok(collapsed.length > 0);
    assert.ok(collapsed.every((entry) => entry.rowType === "group"));
    assert.equal(collapsed.reduce((sum, entry) => sum + entry.count, 0), rows.length);
    assert.equal(findingCount(collapsed), 0);
});

test("individual groups can be collapsed", () => {
    const keys = groupKeysOf(rows, "priority");
    assert.deepEqual([...keys].sort(), ["critical", "high", "medium", "unknown"]);
    const partial = flattenGroups(rows, "priority", true, { critical: true });
    const criticalHeader = partial.find((entry) =>
        entry.rowType === "group" && entry.key === "critical");
    const highHeader = partial.find((entry) =>
        entry.rowType === "group" && entry.key === "high");
    assert.equal(criticalHeader.expanded, false);
    assert.equal(highHeader.expanded, true);
    assert.ok(partial.every((entry) =>
        entry.rowType === "group" || entry.severityBand !== "critical"));
    assert.equal(findingCount(partial), rows.length - criticalHeader.count);
});

test("groups can be sorted by name or finding count", () => {
    const byName = flattenGroups(rows, "package", true, {}, "name", false)
        .filter((entry) => entry.rowType === "group")
        .map((entry) => entry.key);
    assert.deepEqual(byName, [...byName].sort((a, b) => a.localeCompare(b)));

    const byNameDesc = flattenGroups(rows, "package", true, {}, "name", true)
        .filter((entry) => entry.rowType === "group")
        .map((entry) => entry.key);
    assert.deepEqual(byNameDesc, [...byNameDesc].sort((a, b) => b.localeCompare(a)));

    const byCount = flattenGroups(rows, "package", true, {}, "count", true)
        .filter((entry) => entry.rowType === "group");
    for (let i = 1; i < byCount.length; ++i) {
        assert.ok(byCount[i - 1].count >= byCount[i].count);
    }
});
