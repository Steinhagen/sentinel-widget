import test from "node:test";
import assert from "node:assert/strict";
import { apply } from "../../contents/ui/domain/filters.mjs";
import { buildRows, flattenGroups, sortRows } from "../../contents/ui/domain/table.mjs";

function syntheticFindings(count) {
    const findings = [];
    for (let i = 0; i < count; ++i) {
        const critical = i % 11 === 0;
        findings.push({
            id: "CVE-2099-" + String(10000 + i),
            package: "package-" + (i % 120),
            version: "1." + (i % 9) + ".0",
            severity: critical ? 9.8 : (i % 5) + 4,
            url: "https://example.invalid/" + i,
            scanners: ["vulnix"],
            confidence: "component_exact",
            origins: {
                introduced_by: ["root-" + (i % 70)],
                chain: ["root-" + (i % 70), "package-" + (i % 120)],
                chains: [["root-" + (i % 70), "package-" + (i % 120)]]
            },
            tracker: i % 7 === 0
                ? { found: true, status: "pending", fix_state: "in-master", fix_branch: "master",
                    fix_branches: [{ name: "master", version: "2.0", kind: "branch", state: "unaffected" }] }
                : { found: false }
        });
    }
    return findings;
}

test("two thousand findings stay within the interaction budget", () => {
    const findings = syntheticFindings(2000);
    const start = performance.now();
    const rows = buildRows(findings, { systemChannel: "nixos-unstable", checked: {} });
    const filtered = apply(rows, { text: "package-42" });
    sortRows(filtered, "severity", true);
    const grouped = flattenGroups(rows);
    const elapsed = performance.now() - start;

    assert.equal(rows.length, 2000);
    assert.ok(filtered.length > 0);
    assert.equal(grouped.filter((row) => row.rowType === "finding").length, 2000);
    assert.ok(elapsed < 1000, `2,000-row pass took ${elapsed.toFixed(1)} ms`);
});
