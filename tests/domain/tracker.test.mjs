import test from "node:test";
import assert from "node:assert/strict";
import {
    affectedProductsOf,
    countsOf,
    isCve,
    matches,
    progressOf,
    stateOf,
    statusLabelKey,
    urlFor
} from "../../contents/ui/domain/tracker.mjs";
import { finding, readFixture, v7 } from "../helpers/fixtures.mjs";

test("CVE recognition", () => {
    assert.equal(isCve("CVE-2026-1234"), true);
    assert.equal(isCve("OSV-2026-1234"), false);
    assert.equal(isCve(""), false);
});

test("tracker states", () => {
    assert.equal(stateOf(finding("CVE-2021-35049"), {}), "missing");
    assert.equal(stateOf(finding("CVE-2026-111497"), {}), "found");
    assert.equal(stateOf(finding("OSV-2026-1517"), {}), "none");
    assert.equal(stateOf({ id: "CVE-2026-9999" }, {}), "unknown");
    assert.equal(stateOf({ id: "CVE-2026-9999" }, { "CVE-2026-9999": true }), "found");
    assert.equal(stateOf({ id: "CVE-2026-9999" }, { "CVE-2026-9999": false }), "missing");
});

test("tracker filters", () => {
    assert.equal(matches(finding("CVE-2026-111497"), "linked", {}), true);
    assert.equal(matches(finding("CVE-2026-125267"), "pending", {}), true);
    assert.equal(matches(finding("CVE-2021-35049"), "missing", {}), true);
    assert.equal(matches(finding("CVE-2026-13221"), "rejected", {}), true);
    assert.equal(matches(finding("CVE-2026-111497"), "", {}), true);
});

test("fixture tracker counts add up", () => {
    const counts = countsOf(v7.vulnerabilities, {});
    assert.equal(counts.linked + counts.missing + counts.unchecked, 13);
    assert.ok(counts.linked > 0);
    assert.ok(counts.missing > 0);
});

test("progress follows the active phase", () => {
    const progress = progressOf(readFixture("tracker-progress.json"));
    assert.equal(progress.phase, "packages");
    assert.equal(progress.total, 8);
    assert.equal(progress.done, 6);
    assert.equal(progress.busy, true);
    assert.equal(progress.complete, false);

    const done = progressOf(v7.tracker);
    assert.equal(done.phase, "done");
    assert.equal(done.total, 14);
    assert.equal(done.done, 14);
    assert.equal(done.busy, false);

    const empty = progressOf(null);
    assert.equal(empty.total, 0);
    assert.equal(empty.busy, false);
});

test("progress handles every phase", () => {
    assert.deepEqual(
        [progressOf({ phase: "cves", fallback_total: 4, fallback_done: 1, fallback_failed: 2 }).total,
         progressOf({ phase: "cves", fallback_total: 4, fallback_done: 1, fallback_failed: 2 }).done],
        [4, 3]
    );
    assert.deepEqual(
        [progressOf({ phase: "issues", total_issues: 5, issues_checked: 2, issue_failed: 1 }).total,
         progressOf({ phase: "issues", total_issues: 5, issues_checked: 2, issue_failed: 1 }).done],
        [5, 3]
    );
    assert.deepEqual(
        [progressOf({ phase: "probes", total_probes: 6, probes_checked: 3, probes_failed: 2 }).total,
         progressOf({ phase: "probes", total_probes: 6, probes_checked: 3, probes_failed: 2 }).done],
        [6, 5]
    );
});

test("URLs only exist for tracked findings", () => {
    assert.equal(urlFor("https://tracker.security.nixos.org", finding("CVE-2021-35049"), {}), "");
    assert.equal(urlFor("https://tracker.security.nixos.org", finding("CVE-2026-111497"), {}),
        "https://tracker.security.nixos.org/issues/NIXPKGS-2026-3162");
    assert.equal(urlFor("https://tracker.security.nixos.org", { id: "CVE-2099-9999" }, {}),
        "https://tracker.security.nixos.org/suggestions/by-cve/CVE-2099-9999");
});

test("tracker labels and affected products", () => {
    assert.equal(statusLabelKey("published"), "published");
    assert.equal(statusLabelKey("nope"), "");
    const products = affectedProductsOf({ affected_products: [
        { name: "python", version_constraints: [["affected", "<3.13"]] }
    ] });
    assert.deepEqual(products, [{ name: "python", constraints: ["<3.13"] }]);
});
