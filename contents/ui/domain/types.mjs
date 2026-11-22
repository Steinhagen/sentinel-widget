// Shared tokens for the Sentinel domain. Keep this module dependency-free:
// the same values are used by the applet, the Node tests and the docs.

export const SUPPORTED_SCHEMA_VERSION = 7;

export const SeverityBand = Object.freeze({
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    UNKNOWN: "unknown"
});

export const FixStage = Object.freeze({
    FIXED: "fixed",
    STAGING: "in-staging",
    MASTER: "in-master",
    RELEASE: "in-release",
    ISSUE: "issue-open"
});

export const FixBucket = Object.freeze({
    FIXED: "fixed",
    PROGRESS: "progress",
    NONE: "none",
    UNKNOWN: "unknown",
    NA: "n/a",
});

export const TrackerState = Object.freeze({
    NONE: "none",
    MISSING: "missing",
    FOUND: "found",
    UNKNOWN: "unknown"
});
