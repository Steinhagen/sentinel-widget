// Triage verdicts, either from the scanner backend (a `verdict` field on the
// finding) or from the sidecar report written by tools/triage.mjs.
//
// The applet uses this to drop findings that the triage pass proved wrong. It
// never changes the report itself: the filter is applied when rows are built,
// so the raw status file stays the source of truth.

import { fnv1a } from "./status.mjs";

export const TriagedVerdict = Object.freeze({
    CONFIRMED: "confirmed",
    UNVERIFIED: "unverified",
    SUPPRESSED: "suppressed"
});

const VERDICTS = [
    TriagedVerdict.CONFIRMED,
    TriagedVerdict.UNVERIFIED,
    TriagedVerdict.SUPPRESSED
];

function arrayOf(value) {
    return Array.isArray(value) ? value : [];
}

function stringOf(value) {
    return value === null || value === undefined ? "" : String(value);
}

/** Identity of a finding across status.json and the triage report. */
export function keyOf(finding) {
    const item = finding && typeof finding === "object" ? finding : {};
    return [stringOf(item.id), stringOf(item.package), stringOf(item.version)].join("|");
}

export function isVerdict(value) {
    return VERDICTS.indexOf(String(value)) >= 0;
}

/**
 * Parse the sidecar report. Accepts either the full report
 * ({ findings: [...] }) or a bare array.
 */
export function parseTriageText(text) {
    if (typeof text !== "string" || text.length === 0) {
        return { ok: false };
    }
    let raw = null;
    try {
        raw = JSON.parse(text);
    } catch (error) {
        return { ok: false };
    }
    const entries = Array.isArray(raw)
        ? raw
        : (raw && Array.isArray(raw.findings) ? raw.findings : null);
    if (!entries) {
        return { ok: false };
    }
    const byKey = {};
    const counts = { confirmed: 0, unverified: 0, suppressed: 0 };
    for (let i = 0; i < entries.length; ++i) {
        const entry = entries[i];
        if (!entry || typeof entry !== "object") {
            continue;
        }
        const verdict = stringOf(entry.verdict);
        if (!isVerdict(verdict)) {
            continue;
        }
        byKey[keyOf(entry)] = {
            verdict: verdict,
            reasons: arrayOf(entry.reasons).map(String)
        };
        counts[verdict] += 1;
    }
    return {
        ok: true,
        byKey: byKey,
        counts: counts,
        fingerprint: fnv1a(JSON.stringify(byKey))
    };
}

/** The verdict for one finding: embedded first, then the sidecar. */
export function verdictOf(finding, triage) {
    if (!finding || typeof finding !== "object") {
        return "";
    }
    const embedded = stringOf(finding.verdict);
    if (isVerdict(embedded)) {
        return embedded;
    }
    if (!triage || !triage.byKey) {
        return "";
    }
    const entry = triage.byKey[keyOf(finding)];
    return entry && isVerdict(entry.verdict) ? entry.verdict : "";
}

/** The reasons behind a finding's verdict, if any. */
export function reasonsOf(finding, triage) {
    if (!finding || typeof finding !== "object") {
        return [];
    }
    if (isVerdict(stringOf(finding.verdict))) {
        return arrayOf(finding.verdict_reasons).map(String);
    }
    if (!triage || !triage.byKey) {
        return [];
    }
    const entry = triage.byKey[keyOf(finding)];
    return entry ? entry.reasons.slice() : [];
}

export function isSuppressed(finding, triage, enabled) {
    return enabled === true
        && verdictOf(finding, triage) === TriagedVerdict.SUPPRESSED;
}

/** The findings to display, honoring the triage setting. */
export function visibleFindings(findings, triage, enabled) {
    const source = arrayOf(findings);
    if (!enabled || !triage) {
        return source;
    }
    const visible = [];
    for (let i = 0; i < source.length; ++i) {
        if (!isSuppressed(source[i], triage, true)) {
            visible.push(source[i]);
        }
    }
    return visible;
}

export function suppressedCount(findings, triage, enabled) {
    const source = arrayOf(findings);
    if (!enabled || !triage) {
        return 0;
    }
    let count = 0;
    for (let i = 0; i < source.length; ++i) {
        if (isSuppressed(source[i], triage, true)) {
            count += 1;
        }
    }
    return count;
}
