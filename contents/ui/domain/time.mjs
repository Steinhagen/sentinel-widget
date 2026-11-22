// Scan timestamp helpers. The caller supplies `now` so tests are deterministic.

export function scanAge(scannedAtMs, nowMs) {
    if (!scannedAtMs || !nowMs) {
        return -1;
    }
    return Math.max(0, (nowMs - scannedAtMs) / 1000);
}

export function relativeToken(ageSeconds) {
    if (ageSeconds < 0) {
        return { key: "", value: 0 };
    }
    if (ageSeconds < 60) {
        return { key: "just-now", value: 0 };
    }
    if (ageSeconds < 3600) {
        return { key: "minutes", value: Math.floor(ageSeconds / 60) };
    }
    if (ageSeconds < 86400) {
        return { key: "hours", value: Math.floor(ageSeconds / 3600) };
    }
    return { key: "days", value: Math.floor(ageSeconds / 86400) };
}
