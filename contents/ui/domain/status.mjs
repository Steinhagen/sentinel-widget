// status.json parsing, normalization and change fingerprints.
//
// This is the only module that knows the backend's snake_case shape. The rest
// of the applet works with a stable ScanReport.

import { bandOf } from "./severity.mjs";
import { normalizeSource } from "./source.mjs";
import { SUPPORTED_SCHEMA_VERSION } from "./types.mjs";

function arrayOf(value) {
    return Array.isArray(value) ? value : [];
}

function stringOf(value) {
    return value === null || value === undefined ? "" : String(value);
}

export function stampOf(value) {
    if (!value) {
        return "";
    }
    return stringOf(value.scanned_at_iso || value.scanned_at);
}

export function parseTimestamp(value) {
    if (!value) {
        return null;
    }
    const epoch = value.scanned_at_epoch;
    if (typeof epoch === "number" && epoch > 0) {
        return epoch * 1000;
    }
    const raw = stringOf(value.scanned_at_iso || value.scanned_at);
    if (raw.length === 0) {
        return null;
    }
    const parsed = Date.parse(raw);
    if (!isNaN(parsed)) {
        return parsed;
    }
    // Older status files used "%Y-%m-%d %H:%M %Z"; JavaScript does not
    // reliably parse it, and the date/time part is local time.
    const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/.exec(raw);
    if (match) {
        return new Date(
            Number(match[1]),
            Number(match[2]) - 1,
            Number(match[3]),
            Number(match[4]),
            Number(match[5])
        ).getTime();
    }
    return null;
}

export function normalizeFinding(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const finding = {};
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            finding[key] = source[key];
        }
    }

    finding.id = stringOf(source.id);
    finding.package = stringOf(source.package);
    finding.version = stringOf(source.version);
    finding.url = stringOf(source.url);
    finding.scanners = arrayOf(source.scanners).map(String);
    finding.confidence = stringOf(source.confidence);
    finding.patch_state = stringOf(source.patch_state);

    const severity = Number(source.severity);
    finding.severity = isFinite(severity) ? severity : null;

    const origins = source.origins && typeof source.origins === "object"
        ? source.origins : {};
    finding.origins = {
        introduced_by: arrayOf(origins.introduced_by).map(String),
        chain: arrayOf(origins.chain).map(String),
        chains: arrayOf(origins.chains).map(function (chain) {
            return arrayOf(chain).map(String);
        }),
        store_paths: arrayOf(origins.store_paths).map(String)
    };

    finding.tracker = source.tracker && typeof source.tracker === "object"
        ? source.tracker : null;

    // Optional triage verdict. Backends may embed it; otherwise the applet
    // reads the sidecar report written by tools/triage.mjs.
    finding.verdict = stringOf(source.verdict);
    finding.verdict_reasons = arrayOf(source.verdict_reasons).map(String);
    // A finding may name the flake source its package was built from; the row
    // falls back to the report-level source otherwise.
    finding.source = normalizeSource(source.source);
    return finding;
}

export function normalizeTracker(raw) {
    if (!raw || typeof raw !== "object") {
        return null;
    }
    const tracker = {};
    for (const key in raw) {
        if (Object.prototype.hasOwnProperty.call(raw, key)) {
            tracker[key] = raw[key];
        }
    }
    return tracker;
}

export function normalizeSeverityCounts(raw, vulnerabilities) {
    if (raw && typeof raw === "object") {
        return {
            critical: Number(raw.critical || 0),
            high: Number(raw.high || 0),
            medium: Number(raw.medium || 0),
            low: Number(raw.low || 0),
            unknown: Number(raw.unknown || 0)
        };
    }
    const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (let i = 0; i < vulnerabilities.length; ++i) {
        counts[bandOf(vulnerabilities[i].severity)] += 1;
    }
    return counts;
}

export function countPackages(vulnerabilities) {
    const seen = {};
    for (let i = 0; i < vulnerabilities.length; ++i) {
        const name = vulnerabilities[i].package;
        if (name) {
            seen[name] = true;
        }
    }
    return Object.keys(seen).length;
}

export function fnv1a(text) {
    let hash = 0x811c9dc5;
    const value = String(text);
    for (let i = 0; i < value.length; ++i) {
        hash ^= value.charCodeAt(i);
        hash = (hash * 0x01000193) >>> 0;
    }
    return ("00000000" + hash.toString(16)).slice(-8);
}

export function fingerprint(report) {
    const parts = [
        report.schemaVersion,
        report.state,
        report.findings,
        report.maxSeverity,
        report.packagesAffected,
        JSON.stringify(report.severityCounts),
        report.stamp,
        report.error,
        JSON.stringify(report.source),
        JSON.stringify(report.vulnerabilities)
    ];
    return fnv1a(parts.join("|"));
}

export function normalizeReport(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const sourceVulnerabilities = Array.isArray(source.vulnerabilities)
        ? source.vulnerabilities
        : (Array.isArray(source.top) ? source.top : []);
    const vulnerabilities = sourceVulnerabilities.map(normalizeFinding);
    const tracker = normalizeTracker(source.tracker);
    const report = {
        schemaVersion: Number(source.schema_version || 0),
        state: stringOf(source.state || "unknown"),
        findings: Number(source.findings || 0),
        maxSeverity: Number(source.max_severity || 0),
        packagesAffected: typeof source.packages_affected === "number"
            ? source.packages_affected
            : countPackages(vulnerabilities),
        severityCounts: normalizeSeverityCounts(source.severity_counts, vulnerabilities),
        scannedAtMs: parseTimestamp(source),
        stamp: stampOf(source),
        error: stringOf(source.error),
        source: normalizeSource(source.source),
        triageReady: source.triage_ready !== false,
        triageFailed: source.triage_failed === true,
        vulnerabilities: vulnerabilities,
        tracker: tracker
    };
    report.schemaNewer = report.schemaVersion > SUPPORTED_SCHEMA_VERSION;
    report.fingerprint = fingerprint(report);
    report.trackerFingerprint = tracker ? fnv1a(JSON.stringify(tracker)) : "";
    return report;
}

export function parseStatusText(text) {
    if (typeof text !== "string" || text.length === 0) {
        return { ok: false, error: "invalid-json" };
    }
    let raw = null;
    try {
        raw = JSON.parse(text);
    } catch (error) {
        return { ok: false, error: "invalid-json" };
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return { ok: false, error: "invalid-json" };
    }
    return { ok: true, report: normalizeReport(raw) };
}
