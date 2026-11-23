// Row construction, sorting and flat grouping.

import { bandOf, formatScore, hasScore, isBold, numberOf } from "./severity.mjs";
import {
    chainText,
    chainsOf,
    groupKeyOf,
    namesOf,
    normalizedChain,
    searchTextOf,
    storePathsOf
} from "./origins.mjs";
import { classify } from "./fix.mjs";
import {
    normalizeSource,
    sourceNameText,
    sourceRefText,
    sourceRevLabel,
    sourceText
} from "./source.mjs";
import { stateOf, statusOf } from "./tracker.mjs";

function arrayOf(value) {
    return Array.isArray(value) ? value : [];
}

export function buildFindingRow(finding, context) {
    const options = context || {};
    const source = finding || {};
    const row = {};
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            row[key] = source[key];
        }
    }

    const severity = hasScore(source.severity) ? Number(source.severity) : 0;
    const originNames = namesOf(source);
    const chain = normalizedChain(source);
    const tracker = source.tracker || null;
    const fix = classify(source, options.systemChannel || "");
    const provenance = normalizeSource(source.source)
        || normalizeSource(options.source);

    row.rowType = "finding";
    row.severityValue = numberOf(severity);
    row.severityBand = bandOf(source.severity);
    row.severityText = formatScore(source.severity);
    row.severityBold = isBold(source.severity);
    row.package = String(source.package || "");
    row.version = String(source.version || "");
    row.id = String(source.id || "");
    row.url = String(source.url || "");
    row.scanners = arrayOf(source.scanners).map(String);
    row.confidence = String(source.confidence || "");
    row.fix = fix;
    row.origin = {
        names: originNames,
        primary: originNames.length > 0 ? originNames[0] : "",
        chain: chain,
        chainText: chain.join(" → "),
        chains: chainsOf(source),
        storePaths: storePathsOf(source),
        groupKey: groupKeyOf(source),
        searchText: searchTextOf(source)
    };
    row.trackerState = stateOf(source, options.checked || {});
    row.trackerStatus = statusOf(source);
    row.tracker = tracker;
    row.source = provenance;
    row.sourceText = sourceText(provenance);
    row.sourceName = sourceNameText(provenance);
    row.sourceRef = sourceRefText(provenance);
    row.sourceRev = sourceRevLabel(provenance);
    row.originSearch = row.origin.searchText;
    row.fixSortText = "";
    row.viaLabel = "";

    const haystack = [
        row.id,
        row.package,
        row.version,
        row.severityText,
        row.scanners.join(", "),
        row.confidence,
        fix.state,
        fix.branch,
        fix.version,
        fix.master.status,
        fix.master.version,
        originNames.join(" "),
        chainText(source),
        tracker ? [
            tracker.issue,
            tracker.status,
            tracker.master_status,
            tracker.master_version,
            tracker.issue_state
        ].join(" ") : ""
    ].join(" ");
    row.searchText = haystack.toLowerCase();
    return row;
}

export function buildRows(findings, context) {
    const rows = [];
    const source = arrayOf(findings);
    for (let i = 0; i < source.length; ++i) {
        rows.push(buildFindingRow(source[i], context));
    }
    return rows;
}

export function valueOf(row, key) {
    switch (key) {
    case "severity":
        return row.severityValue;
    case "cve":
        return row.id;
    case "package":
        return row.package;
    case "origin":
        return row.originSearch;
    case "version":
        return row.version;
    case "master":
        return row.fixSortText || (row.fix ? row.fix.labelKey : "");
    case "via":
        return row.viaLabel || (row.scanners.join(", ") + " " + row.confidence);
    default:
        return "";
    }
}

export function compareRows(a, b, key, descending) {
    let av = valueOf(a, key);
    let bv = valueOf(b, key);
    if (typeof av === "number" && typeof bv === "number") {
        if (av === bv) {
            return 0;
        }
        return descending ? bv - av : av - bv;
    }
    av = String(av).toLowerCase();
    bv = String(bv).toLowerCase();
    if (av === bv) {
        return 0;
    }
    const cmp = av < bv ? -1 : 1;
    return descending ? -cmp : cmp;
}

export function sortRows(rows, key, descending) {
    rows.sort(function (a, b) {
        return compareRows(a, b, key, descending);
    });
    return rows;
}

const PRIORITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

export function rowGroupKeyOf(row, groupBy) {
    switch (groupBy) {
    case "priority":
        return row.severityBand || "unknown";
    case "package":
        return row.package || "";
    case "origin":
        return row.origin && row.origin.groupKey ? row.origin.groupKey : "";
    default:
        return "";
    }
}

export function groupKeysOf(rows, groupBy) {
    const mode = groupBy || "origin";
    if (mode === "none") {
        return [];
    }
    const seen = {};
    const keys = [];
    for (let i = 0; i < rows.length; ++i) {
        const key = rowGroupKeyOf(rows[i], mode);
        if (!seen[key]) {
            seen[key] = true;
            keys.push(key);
        }
    }
    return keys;
}

export function flattenGroups(rows, groupBy, expanded, collapsedGroups, groupSortKey, groupSortDescending) {
    const mode = groupBy || "origin";
    if (mode === "none") {
        return rows;
    }
    const showRows = expanded !== false;
    const collapsed = collapsedGroups || {};
    const groups = {};
    const order = [];
    for (let i = 0; i < rows.length; ++i) {
        const row = rows[i];
        const key = rowGroupKeyOf(row, mode);
        if (!groups[key]) {
            groups[key] = { key: key, count: 0, maxSeverity: -1, rows: [] };
            order.push(key);
        }
        groups[key].count += 1;
        groups[key].rows.push(row);
        if (row.severityValue > groups[key].maxSeverity) {
            groups[key].maxSeverity = row.severityValue;
        }
    }

    order.sort(function (a, b) {
        if (groupSortKey === "name") {
            const cmp = a.localeCompare(b);
            return groupSortDescending ? -cmp : cmp;
        }
        if (groupSortKey === "count") {
            if (groups[a].count !== groups[b].count) {
                return groupSortDescending
                    ? groups[b].count - groups[a].count
                    : groups[a].count - groups[b].count;
            }
            return a.localeCompare(b);
        }
        if (mode === "priority") {
            const ai = PRIORITY_ORDER.indexOf(a);
            const bi = PRIORITY_ORDER.indexOf(b);
            return (ai < 0 ? PRIORITY_ORDER.length : ai)
                - (bi < 0 ? PRIORITY_ORDER.length : bi);
        }
        if (groups[a].maxSeverity !== groups[b].maxSeverity) {
            return groups[b].maxSeverity - groups[a].maxSeverity;
        }
        if (groups[a].count !== groups[b].count) {
            return groups[b].count - groups[a].count;
        }
        return a.localeCompare(b);
    });

    const result = [];
    for (let g = 0; g < order.length; ++g) {
        const group = groups[order[g]];
        const groupExpanded = showRows && collapsed[group.key] !== true;
        result.push({
            rowType: "group",
            groupBy: mode,
            key: group.key,
            count: group.count,
            maxSeverity: group.maxSeverity,
            expanded: groupExpanded
        });
        if (groupExpanded) {
            for (let i = 0; i < group.rows.length; ++i) {
                result.push(group.rows[i]);
            }
        }
    }
    return result;
}

export function findingCount(rows) {
    let count = 0;
    for (let i = 0; i < rows.length; ++i) {
        if (rows[i].rowType === "finding") {
            count += 1;
        }
    }
    return count;
}
