// Shared tokens for the Sentinel domain. Keep this module dependency-free:
// the same values are used by the applet, the Node tests and the docs.

export const SUPPORTED_SCHEMA_VERSION = 7;

export const ScanState = Object.freeze({
    SECURE: "secure",
    VULNERABLE: "vulnerable",
    WARN: "warn",
    UNKNOWN: "unknown"
});

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
    NONE_MATCH: ""
});

export const TrackerState = Object.freeze({
    NONE: "none",
    MISSING: "missing",
    FOUND: "found",
    UNKNOWN: "unknown"
});

export const ScanPhase = Object.freeze({
    IDLE: "idle",
    STARTING: "starting",
    SCANNING: "scanning",
    FINISHING: "finishing",
    FAILED: "failed"
});

export const LoadError = Object.freeze({
    NONE: "",
    MISSING: "missing",
    PERMISSION: "permission",
    INVALID_JSON: "invalid-json",
    UNSUPPORTED_SCHEMA: "unsupported-schema",
    UNKNOWN: "unknown"
});
