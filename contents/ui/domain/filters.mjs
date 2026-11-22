// Table filters and aggregate counts.
//
// A filter state is deliberately small: only controls reachable from the
// toolbar and row cells are represented. `cve`, `version`, `via` and `master`
// per-column filters from the old table are not exposed anywhere.

import { TrackerState } from "./types.mjs";

export function empty() {
    return {
        text: "",
        severity: "",
        fixState: "",
        trackerState: "",
        package: "",
        origin: ""
    };
}

export function isActive(filters) {
    const value = filters || {};
    return String(value.text || "").length > 0
        || String(value.severity || "").length > 0
        || String(value.fixState || "").length > 0
        || String(value.trackerState || "").length > 0
        || String(value.package || "").length > 0
        || String(value.origin || "").length > 0;
}

function trackerMatches(row, filter) {
    if (!filter) {
        return true;
    }
    switch (filter) {
    case "linked":
        return row.trackerState === TrackerState.FOUND;
    case "pending":
        return row.trackerState === TrackerState.FOUND
            && row.trackerStatus === "pending";
    case "missing":
        return row.trackerState === TrackerState.MISSING;
    case "unknown":
        return row.trackerState === TrackerState.UNKNOWN;
    case "none":
    case "unchecked":
        return row.trackerState === TrackerState.NONE
            || row.trackerState === TrackerState.UNKNOWN;
    default:
        return true;
    }
}

export function matches(row, filters) {
    const value = filters || {};
    const query = String(value.text || "").trim().toLowerCase();
    if (query.length > 0 && String(row.searchText || "").indexOf(query) === -1) {
        return false;
    }
    if (value.severity && row.severityBand !== value.severity) {
        return false;
    }
    if (value.fixState && (!row.fix || row.fix.bucket !== value.fixState)) {
        return false;
    }
    if (value.trackerState && !trackerMatches(row, value.trackerState)) {
        return false;
    }
    if (value.package) {
        const needle = String(value.package).trim().toLowerCase();
        if (String(row.package || "").toLowerCase().indexOf(needle) === -1) {
            return false;
        }
    }
    if (value.origin) {
        const needle = String(value.origin).trim().toLowerCase();
        if (String(row.originSearch || "").toLowerCase().indexOf(needle) === -1) {
            return false;
        }
    }
    return true;
}

export function apply(rows, filters) {
    const result = [];
    for (let i = 0; i < rows.length; ++i) {
        if (matches(rows[i], filters)) {
            result.push(rows[i]);
        }
    }
    return result;
}

export function countsOf(rows) {
    const result = {
        severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
        fix: { fixed: 0, progress: 0, none: 0, unknown: 0, "n/a": 0 },
        tracker: { linked: 0, pending: 0, missing: 0, unchecked: 0 }
    };
    for (let i = 0; i < rows.length; ++i) {
        const row = rows[i];
        const band = row.severityBand || "unknown";
        result.severity[band] = (result.severity[band] || 0) + 1;

        const bucket = row.fix ? row.fix.bucket : "";
        if (bucket && Object.prototype.hasOwnProperty.call(result.fix, bucket)) {
            result.fix[bucket] += 1;
        }

        if (row.trackerState === TrackerState.FOUND) {
            result.tracker.linked += 1;
            if (row.trackerStatus === "pending") {
                result.tracker.pending += 1;
            }
        } else if (row.trackerState === TrackerState.MISSING) {
            result.tracker.missing += 1;
        } else {
            result.tracker.unchecked += 1;
        }
    }
    return result;
}
