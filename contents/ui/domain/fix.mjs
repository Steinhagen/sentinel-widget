// Fix-state classification.
//
// The backend gives three kinds of evidence:
//   1. fix_state + fix_branches (current schema),
//   2. only a master_status (older schema),
//   3. nothing.
//
// The precedence here mirrors the applet's existing behaviour. Do not "improve"
// a rule without a fixture and a test: labels and filters depend on it.

import { FixStage, FixBucket } from "./types.mjs";

function trackerOf(finding) {
    return finding && finding.tracker ? finding.tracker : null;
}

export function fixStateOf(finding) {
    const tracker = trackerOf(finding);
    return tracker && tracker.fix_state ? String(tracker.fix_state) : "";
}

export function branchRows(finding) {
    const tracker = trackerOf(finding);
    const rows = tracker ? tracker.fix_branches : null;
    return Array.isArray(rows) ? rows : [];
}

export function masterStatusOf(finding) {
    const tracker = trackerOf(finding);
    if (!tracker) {
        return "";
    }
    const status = tracker.master_status;
    if (status === "unaffected" || status === "affected" || status === "unknown") {
        return status;
    }
    if (tracker.found === true && tracker.status && tracker.status !== "rejected") {
        // A suggestion exists, but it has no branch for this package (for
        // example it covers haskellPackages.cpython while the finding is
        // python3), so there is no master verdict to show.
        return "unmatched";
    }
    return "";
}

export function shortChannelName(name) {
    const value = String(name || "");
    if (value === "nixos-unstable") {
        return "unstable";
    }
    return value.indexOf("nixos-") === 0
        ? value.substring("nixos-".length)
        : value;
}

export function shortBranchName(name) {
    const value = String(name || "");
    return value.indexOf("release-") === 0
        ? value.substring("release-".length)
        : value;
}

export function shortRefName(name) {
    const value = String(name || "");
    return value.indexOf("nixos-") === 0
        ? shortChannelName(value)
        : shortBranchName(value);
}

export function isUnstableChannel(systemChannel) {
    const channel = String(systemChannel || "");
    return channel.length === 0 || channel === "nixos-unstable";
}

function nextStepOf(state, finding, systemChannel) {
    const tracker = trackerOf(finding);
    switch (state) {
    case FixStage.STAGING:
        return (tracker && tracker.fix_branch) === "staging-next"
            ? "staging-merged"
            : "staging-wait";
    case FixStage.MASTER:
        if (tracker && tracker.system_known === false) {
            return "channel-unknown";
        }
        return isUnstableChannel(systemChannel) ? "channel-bump" : "backport";
    case FixStage.RELEASE:
        return "other-line";
    case FixStage.ISSUE:
        return "no-fix";
    case FixStage.FIXED:
        return "update";
    default:
        return "";
    }
}

function labelOf(state, finding) {
    const tracker = trackerOf(finding);
    switch (state) {
    case FixStage.FIXED:
        return { key: "fixed", arg: "" };
    case FixStage.STAGING:
        return { key: "staging", arg: "" };
    case FixStage.MASTER:
        return { key: "master", arg: "" };
    case FixStage.RELEASE:
        return {
            key: "release",
            arg: shortRefName(tracker && tracker.fix_branch ? tracker.fix_branch : "")
        };
    case FixStage.ISSUE:
        return { key: "issue", arg: "" };
    default:
        return { key: "", arg: "" };
    }
}

export function classify(finding, systemChannel) {
    const tracker = trackerOf(finding);
    const state = fixStateOf(finding);
    const rows = branchRows(finding);
    const masterStatus = masterStatusOf(finding);
    const label = labelOf(state, finding);
    let bucket = "";

    if (state === FixStage.FIXED) {
        bucket = FixBucket.FIXED;
    } else if (state === FixStage.STAGING
            || state === FixStage.MASTER
            || state === FixStage.RELEASE
            || state === FixStage.ISSUE) {
        bucket = FixBucket.PROGRESS;
    } else if (rows.length === 0 && masterStatus === "unaffected") {
        bucket = FixBucket.FIXED;
    } else if (masterStatus === "affected") {
        bucket = FixBucket.NONE;
    } else if (masterStatus === "unknown") {
        bucket = FixBucket.UNKNOWN;
    } else if (masterStatus === "unmatched") {
        bucket = FixBucket.NA;
    }

    // The Fix column's label is not exactly the bucket. For current files it
    // follows fix_state; for legacy files it follows the master verdict.
    if (!label.key) {
        if (rows.length > 0) {
            if (masterStatus === "unknown") {
                label.key = "unknown";
            } else if (masterStatus === "unmatched") {
                label.key = "n/a";
            } else {
                label.key = "no fix";
            }
        } else if (masterStatus === "unaffected") {
            label.key = "fixed";
        } else if (masterStatus === "affected") {
            label.key = "no fix";
        } else if (masterStatus === "unknown") {
            label.key = "unknown";
        } else if (masterStatus === "unmatched") {
            label.key = "n/a";
        } else {
            // The row pill says "unknown" rather than rendering an empty pill.
            label.key = "unknown";
        }
    }

    return {
        state: state,
        bucket: bucket,
        labelKey: label.key,
        labelArg: label.arg,
        branch: tracker && tracker.fix_branch ? String(tracker.fix_branch) : "",
        matchedPackage: tracker && tracker.matched_package
            ? String(tracker.matched_package) : "",
        branchShort: state === FixStage.RELEASE
            ? shortRefName(tracker && tracker.fix_branch ? tracker.fix_branch : "")
            : "",
        version: tracker && tracker.fix_version ? String(tracker.fix_version) : "",
        rows: rows,
        master: {
            status: masterStatus,
            version: tracker && tracker.master_version
                ? String(tracker.master_version) : "",
            source: tracker && tracker.master_status_source
                ? String(tracker.master_status_source) : "",
            range: tracker && tracker.master_range
                ? String(tracker.master_range) : "",
            url: tracker && tracker.master_url ? String(tracker.master_url) : ""
        },
        url: masterFixUrl(finding),
        systemKnown: !(tracker && tracker.system_known === false),
        nextStep: nextStepOf(state, finding, systemChannel),
        hasRows: rows.length > 0
    };
}

export function masterFixUrl(finding) {
    const tracker = trackerOf(finding);
    if (!tracker) {
        return "";
    }
    return tracker.github_issue_url || tracker.url || "";
}
