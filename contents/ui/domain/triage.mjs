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
            reasons: arrayOf(entry.reasons).map(String),
            vendor: stringOf(entry.vendor),
            product: stringOf(entry.product)
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

/** Verdict, reasons and the CVE's identity for one finding. */
export function detailsOf(finding, triage) {
    const empty = { verdict: "", reasons: [], vendor: "", product: "" };
    if (!finding || typeof finding !== "object") {
        return empty;
    }
    const embedded = stringOf(finding.verdict);
    if (isVerdict(embedded)) {
        return {
            verdict: embedded,
            reasons: arrayOf(finding.verdict_reasons).map(String),
            vendor: stringOf(finding.verdict_vendor),
            product: stringOf(finding.verdict_product)
        };
    }
    if (!triage || !triage.byKey) {
        return empty;
    }
    const entry = triage.byKey[keyOf(finding)];
    if (!entry) {
        return empty;
    }
    return {
        verdict: entry.verdict,
        reasons: entry.reasons || [],
        vendor: entry.vendor || "",
        product: entry.product || ""
    };
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

/** Whether the user explicitly forced this finding back into the main list. */
export function isForcedVisible(finding, forcedVisible) {
    if (!finding || !Array.isArray(forcedVisible) || forcedVisible.length === 0) {
        return false;
    }
    for (let i = 0; i < forcedVisible.length; ++i) {
        const entry = forcedVisible[i];
        if (!entry
                || stringOf(entry.cve) !== stringOf(finding.id)
                || stringOf(entry.package) !== stringOf(finding.package)) {
            continue;
        }
        const wantedVersion = stringOf(entry.version);
        if (wantedVersion.length > 0
                && wantedVersion !== stringOf(finding.version)) {
            continue;
        }
        return true;
    }
    return false;
}

/** Whether the user ignored this finding from the applet. */
export function isIgnored(finding, ignoredPairs) {
    if (!finding || !Array.isArray(ignoredPairs) || ignoredPairs.length === 0) {
        return false;
    }
    for (let i = 0; i < ignoredPairs.length; ++i) {
        const pair = ignoredPairs[i];
        if (!pair
                || stringOf(pair.cve) !== stringOf(finding.id)
                || stringOf(pair.package) !== stringOf(finding.package)) {
            continue;
        }
        const wantedVersion = stringOf(pair.version);
        if (wantedVersion.length > 0
                && wantedVersion !== stringOf(finding.version)) {
            // A versioned ignore only hides the exact row that was ignored.
            // A package bump makes the finding visible again for review.
            continue;
        }
        return true;
    }
    return false;
}

export function isSuppressed(finding, triage, enabled, ignoredPairs) {
    if (isIgnored(finding, ignoredPairs)) {
        return true;
    }
    return enabled === true
        && verdictOf(finding, triage) === TriagedVerdict.SUPPRESSED;
}

/** Whether a finding is an OSV advisory rather than a CVE. */
export function isOsvFinding(finding) {
    return /^OSV-/i.test(stringOf(finding && finding.id));
}

/** The findings left after optionally hiding all OSV advisories. */
export function hideOsvFindings(findings, hideOsv, forcedVisible) {
    const source = arrayOf(findings);
    if (hideOsv !== true) {
        return source;
    }
    return source.filter((finding) => !isOsvFinding(finding)
        || isForcedVisible(finding, forcedVisible));
}

/** The findings to display, honoring the triage settings. */
export function visibleFindings(findings, triage, enabled, ignoredPairs,
        hideUnverified, forcedVisible) {
    const source = arrayOf(findings);
    const hideSuppressed = enabled === true;
    const hideReview = hideUnverified === true;
    const hasIgnores = Array.isArray(ignoredPairs) && ignoredPairs.length > 0;
    const hasForced = Array.isArray(forcedVisible) && forcedVisible.length > 0;
    if (!hideSuppressed && !hideReview && !hasIgnores && !hasForced) {
        return source;
    }
    const visible = [];
    for (let i = 0; i < source.length; ++i) {
        const finding = source[i];
        if (isForcedVisible(finding, forcedVisible)) {
            visible.push(finding);
            continue;
        }
        if (isIgnored(finding, ignoredPairs)) {
            continue;
        }
        const verdict = verdictOf(finding, triage);
        if (hideSuppressed && verdict === TriagedVerdict.SUPPRESSED) {
            continue;
        }
        if (hideReview && verdict === TriagedVerdict.UNVERIFIED) {
            continue;
        }
        visible.push(finding);
    }
    return visible;
}

export function suppressedCount(findings, triage, enabled, ignoredPairs) {
    const source = arrayOf(findings);
    const hideSuppressed = enabled === true;
    let count = 0;
    for (let i = 0; i < source.length; ++i) {
        const finding = source[i];
        if (isIgnored(finding, ignoredPairs)) {
            count += 1;
            continue;
        }
        if (hideSuppressed
                && verdictOf(finding, triage) === TriagedVerdict.SUPPRESSED) {
            count += 1;
        }
    }
    return count;
}

/** Unverified findings hidden by the "hide unverified" setting. */
export function reviewCount(findings, triage, hideUnverified, ignoredPairs) {
    if (hideUnverified !== true) {
        return 0;
    }
    const source = arrayOf(findings);
    let count = 0;
    for (let i = 0; i < source.length; ++i) {
        const finding = source[i];
        if (isIgnored(finding, ignoredPairs)) {
            continue;
        }
        if (verdictOf(finding, triage) === TriagedVerdict.UNVERIFIED) {
            count += 1;
        }
    }
    return count;
}
