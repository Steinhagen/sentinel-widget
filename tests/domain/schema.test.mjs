import test from "node:test";
import assert from "node:assert/strict";
import { readFixture } from "../helpers/fixtures.mjs";

const raw = readFixture("status-v7.json");

function isStringArray(value) {
    return Array.isArray(value) && value.every((item) => typeof item === "string");
}

test("the v7 fixture satisfies the top-level contract", () => {
    assert.equal(typeof raw.schema_version, "number");
    assert.ok(["secure", "vulnerable", "warn", "unknown"].includes(raw.state));
    assert.ok(Array.isArray(raw.vulnerabilities));
    assert.equal(typeof raw.findings, "number");
    assert.equal(typeof raw.max_severity, "number");
    assert.ok(raw.severity_counts && typeof raw.severity_counts === "object");
    assert.ok(raw.tracker && typeof raw.tracker === "object");
});

test("every finding has the fields the applet reads", () => {
    for (const finding of raw.vulnerabilities) {
        assert.equal(typeof finding.id, "string");
        assert.equal(typeof finding.package, "string");
        assert.ok(finding.severity === null || typeof finding.severity === "number");
        assert.ok(isStringArray(finding.scanners || []));
        assert.ok(Array.isArray(finding.origins.introduced_by || []));
        assert.ok(Array.isArray(finding.origins.chain || []));
        assert.ok(Array.isArray(finding.origins.chains || []));
        if (finding.tracker) {
            assert.ok(typeof finding.tracker.found === "boolean");
            if (finding.tracker.fix_branches) {
                for (const branch of finding.tracker.fix_branches) {
                    assert.equal(typeof branch.name, "string");
                    assert.ok(["unaffected", "affected", "unknown"].includes(branch.state));
                }
            }
        }
    }
});

test("unknown fields are tolerated", () => {
    const copy = structuredClone(raw);
    copy.future_field = { nested: true };
    copy.vulnerabilities[0].future_field = 42;
    assert.equal(copy.future_field.nested, true);
    assert.equal(copy.vulnerabilities[0].future_field, 42);
});
