// Nixpkgs security tracker rules and progress model.

import { TrackerState } from "./types.mjs";

const CVE_RE = /^CVE-\d{4}-\d+$/;

export function isCve(id) {
    return CVE_RE.test(String(id || ""));
}

export function statusOf(finding) {
    return finding && finding.tracker && finding.tracker.status
        ? String(finding.tracker.status) : "";
}

export function stateOf(finding, checked) {
    if (!finding || !isCve(finding.id)) {
        return TrackerState.NONE;
    }
    if (finding.tracker) {
        return finding.tracker.found === false
            ? TrackerState.MISSING
            : TrackerState.FOUND;
    }
    if (checked && Object.prototype.hasOwnProperty.call(checked, finding.id)) {
        if (checked[finding.id] === true) {
            return TrackerState.FOUND;
        }
        if (checked[finding.id] === false) {
            return TrackerState.MISSING;
        }
    }
    return TrackerState.UNKNOWN;
}

export function pageUrl(baseUrl, id) {
    return baseUrl + "/suggestions/by-cve/" + encodeURIComponent(String(id || ""));
}

export function apiUrl(baseUrl, id) {
    return baseUrl + "/api/v1/suggestions/by-cve/" + encodeURIComponent(String(id || ""));
}

export function urlFor(baseUrl, finding, checked) {
    const state = stateOf(finding, checked);
    if (state === TrackerState.NONE || state === TrackerState.MISSING) {
        return "";
    }
    if (finding && finding.tracker && finding.tracker.url) {
        return String(finding.tracker.url);
    }
    return pageUrl(baseUrl, finding ? finding.id : "");
}

export function matches(finding, filter, checked) {
    if (!filter) {
        return true;
    }
    const tracker = finding ? finding.tracker : null;
    const found = !!(tracker && tracker.found);
    switch (filter) {
    case "linked":
        return found;
    case "pending":
        return found && tracker.status === "pending";
    case "published":
        return found && tracker.status === "published";
    case "rejected":
        return found && tracker.status === "rejected";
    case "missing":
        return stateOf(finding, checked) === TrackerState.MISSING;
    case "unknown":
        return stateOf(finding, checked) === TrackerState.UNKNOWN;
    case "none":
    case "unchecked":
        return stateOf(finding, checked) === TrackerState.NONE
            || stateOf(finding, checked) === TrackerState.UNKNOWN;
    default:
        return true;
    }
}

export function countsOf(findings, checked) {
    const counts = {
        linked: 0,
        pending: 0,
        published: 0,
        rejected: 0,
        missing: 0,
        unchecked: 0
    };
    for (let i = 0; i < findings.length; ++i) {
        const finding = findings[i];
        const tracker = finding ? finding.tracker : null;
        if (tracker && tracker.found === true) {
            counts.linked += 1;
            if (tracker.status === "pending") {
                counts.pending += 1;
            } else if (tracker.status === "published") {
                counts.published += 1;
            } else if (tracker.status === "rejected") {
                counts.rejected += 1;
            }
        } else if (stateOf(finding, checked) === TrackerState.MISSING) {
            counts.missing += 1;
        } else {
            counts.unchecked += 1;
        }
    }
    return counts;
}

export function progressOf(tracker) {
    if (!tracker) {
        return {
            available: false,
            complete: true,
            busy: false,
            phase: "",
            total: 0,
            done: 0,
            failed: 0,
            throttled: false,
            authFailed: false
        };
    }

    let total = 0;
    let done = 0;
    const phase = String(tracker.phase || "");

    if (phase === "packages") {
        total = Number(tracker.total_packages || 0);
        done = Number(tracker.packages_checked || 0)
            + Number(tracker.package_failed || 0);
    } else if (phase === "cves") {
        total = Number(tracker.fallback_total || 0);
        done = Number(tracker.fallback_done || 0)
            + Number(tracker.fallback_failed || 0);
    } else if (phase === "issues") {
        total = Number(tracker.total_issues || 0);
        done = Number(tracker.issues_checked || 0)
            + Number(tracker.issue_failed || 0);
    } else if (phase === "probes") {
        total = Number(tracker.total_probes || 0);
        done = Number(tracker.probes_checked || 0)
            + Number(tracker.probes_failed || 0);
    } else {
        total = Number(tracker.total_cves || tracker.cves || 0);
        done = Number(tracker.queried || 0) + Number(tracker.failed || 0);
    }

    return {
        available: tracker.available === true,
        complete: tracker.complete !== false,
        busy: tracker.complete === false,
        phase: phase,
        total: total,
        done: done,
        failed: Number(tracker.failed || 0),
        packageFailed: Number(tracker.package_failed || 0),
        issueFailed: Number(tracker.issue_failed || 0),
        probeFailed: Number(tracker.probes_failed || 0),
        fallbackFailed: Number(tracker.fallback_failed || 0),
        throttled: tracker.throttled === true,
        authFailed: tracker.auth_failed === true,
        systemChannel: tracker.system_channel ? String(tracker.system_channel) : ""
    };
}

export function statusLabelKey(status) {
    switch (status) {
    case "published":
        return "published";
    case "accepted":
        return "accepted";
    case "pending":
        return "pending";
    case "rejected":
        return "rejected";
    default:
        return "";
    }
}

export function affectedProductsOf(tracker) {
    const products = tracker && Array.isArray(tracker.affected_products)
        ? tracker.affected_products : [];
    const result = [];
    for (let i = 0; i < products.length; ++i) {
        const product = products[i] || {};
        const constraints = [];
        const values = Array.isArray(product.version_constraints)
            ? product.version_constraints : [];
        for (let j = 0; j < values.length; ++j) {
            if (values[j] && values[j].length >= 2) {
                constraints.push(String(values[j][1]));
            }
        }
        result.push({
            name: String(product.name || "?"),
            constraints: constraints
        });
    }
    return result;
}
