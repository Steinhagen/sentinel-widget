// Severity rules. No i18n and no QML: callers map bands to colours and words.

import { SeverityBand } from "./types.mjs";

export function hasScore(severity) {
    return severity !== null
        && severity !== undefined
        && Number(severity) > 0;
}

export function numberOf(severity) {
    const value = Number(severity);
    return isFinite(value) ? value : 0;
}

export function bandOf(severity) {
    if (!hasScore(severity)) {
        return SeverityBand.UNKNOWN;
    }
    const value = Number(severity);
    if (value >= 9) {
        return SeverityBand.CRITICAL;
    }
    if (value >= 7) {
        return SeverityBand.HIGH;
    }
    if (value >= 4) {
        return SeverityBand.MEDIUM;
    }
    return SeverityBand.LOW;
}

export function formatScore(severity) {
    return hasScore(severity) ? Number(severity).toFixed(1) : "—";
}

export function isBold(severity) {
    return hasScore(severity) && Number(severity) >= 7;
}
