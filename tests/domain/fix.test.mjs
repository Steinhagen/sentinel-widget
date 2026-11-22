import test from "node:test";
import assert from "node:assert/strict";
import {
    branchRows,
    classify,
    isUnstableChannel,
    masterFixUrl,
    masterStatusOf,
    shortBranchName,
    shortChannelName,
    shortRefName
} from "../../contents/ui/domain/fix.mjs";
import { finding } from "../helpers/fixtures.mjs";

const channel = "nixos-unstable";

test("fixed on the system channel", () => {
    const fix = classify(finding("CVE-2026-111497"), channel);
    assert.equal(fix.state, "fixed");
    assert.equal(fix.bucket, "fixed");
    assert.equal(fix.labelKey, "fixed");
    assert.equal(fix.branch, "nixos-unstable");
    assert.equal(fix.version, "1.2.1");
    assert.equal(fix.nextStep, "update");
    assert.equal(fix.rows.length, 6);
    assert.ok(fix.url.startsWith("https://tracker.security.nixos.org/"));
});

test("in-master is pending and names the next step", () => {
    const fix = classify(finding("CVE-2026-125267"), channel);
    assert.equal(fix.state, "in-master");
    assert.equal(fix.bucket, "progress");
    assert.equal(fix.labelKey, "master");
    // This fixture has system_known=false, so the channel version is unknown.
    assert.equal(fix.nextStep, "channel-unknown");
    assert.equal(fix.master.status, "unaffected");
});

test("in-staging knows whether it missed staging-next", () => {
    const fix = classify(finding("CVE-2026-119741"), channel);
    assert.equal(fix.state, "in-staging");
    assert.equal(fix.bucket, "progress");
    assert.equal(fix.labelKey, "staging");
    assert.equal(fix.branch, "staging-next");
    assert.equal(fix.nextStep, "staging-merged");
});

test("a release branch is not the system channel", () => {
    const fix = classify(finding("CVE-2099-0001"), channel);
    assert.equal(fix.state, "in-release");
    assert.equal(fix.bucket, "progress");
    assert.equal(fix.labelKey, "release");
    assert.equal(fix.labelArg, "26.05");
    assert.equal(fix.nextStep, "other-line");
});

test("an open issue has no fix yet", () => {
    const fix = classify(finding("CVE-2099-0002"), channel);
    assert.equal(fix.state, "issue-open");
    assert.equal(fix.bucket, "progress");
    assert.equal(fix.labelKey, "issue");
    assert.equal(fix.nextStep, "no-fix");
});

test("a legacy master verdict still classifies", () => {
    const affected = classify(finding("CVE-2026-89147"), channel);
    assert.equal(affected.state, "");
    assert.equal(affected.bucket, "none");
    assert.equal(affected.labelKey, "no fix");

    const unknown = classify(finding("CVE-2026-33845"), channel);
    assert.equal(unknown.bucket, "unknown");
    assert.equal(unknown.labelKey, "unknown");

    const unaffected = classify(finding("CVE-2099-0003"), channel);
    assert.equal(unaffected.bucket, "fixed");
    assert.equal(unaffected.labelKey, "fixed");

    const unmatched = classify({
        package: "x",
        version: "1",
        tracker: { found: true, status: "pending" }
    }, channel);
    assert.equal(unmatched.bucket, "n/a");
    assert.equal(unmatched.labelKey, "n/a");
});

test("missing tracker data does not invent a fix", () => {
    const missing = classify(finding("CVE-2021-35049"), channel);
    assert.equal(missing.state, "");
    assert.equal(missing.bucket, "");
    assert.equal(missing.labelKey, "unknown");
    assert.equal(missing.rows.length, 0);
    assert.equal(missing.url, "");
});

test("stable channels ask for a backport", () => {
    const inMaster = {
        package: "ffmpeg",
        version: "6.1.6",
        tracker: {
            fix_state: "in-master",
            fix_branch: "master",
            system_known: true,
            master_status: "unaffected"
        }
    };
    assert.equal(classify(inMaster, "nixos-26.05").nextStep, "backport");
    assert.equal(classify(inMaster, "nixos-unstable").nextStep, "channel-bump");
    assert.equal(isUnstableChannel("nixos-26.05"), false);
    assert.equal(isUnstableChannel("nixos-unstable"), true);
    assert.equal(isUnstableChannel(""), true);
});

test("short names", () => {
    assert.equal(shortChannelName("nixos-unstable"), "unstable");
    assert.equal(shortChannelName("nixos-26.05"), "26.05");
    assert.equal(shortBranchName("release-26.05"), "26.05");
    assert.equal(shortRefName("release-26.05"), "26.05");
    assert.equal(shortRefName("nixos-26.05"), "26.05");
});

test("master status and URL fallbacks", () => {
    assert.equal(masterStatusOf(finding("CVE-2026-33845")), "unknown");
    assert.equal(masterStatusOf({ tracker: { found: true, status: "rejected" } }), "");
    assert.equal(masterFixUrl(finding("CVE-2026-111497")),
        "https://tracker.security.nixos.org/issues/NIXPKGS-2026-3162");
    assert.deepEqual(branchRows(finding("CVE-2026-111497")).length, 6);
});
