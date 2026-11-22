// External URL construction and safety checks.

export const TRACKER_BASE = "https://tracker.security.nixos.org";

export function trackerApi(baseUrl, id) {
    return String(baseUrl || TRACKER_BASE)
        + "/api/v1/suggestions/by-cve/"
        + encodeURIComponent(String(id || ""));
}

export function trackerPage(baseUrl, id) {
    return String(baseUrl || TRACKER_BASE)
        + "/suggestions/by-cve/"
        + encodeURIComponent(String(id || ""));
}

export function nixpkgsSearch(packageName) {
    return "https://search.nixos.org/packages?channel=unstable&query="
        + encodeURIComponent(String(packageName || ""));
}

export function trackerIssue(baseUrl, issue) {
    return String(baseUrl || TRACKER_BASE)
        + "/issues/"
        + encodeURIComponent(String(issue || ""));
}

export function isSafeExternalUrl(url) {
    const value = String(url || "");
    return value.indexOf("https://") === 0 || value.indexOf("http://") === 0;
}

export function isLocalFilePath(path) {
    const value = String(path || "");
    return value.length > 0 && value.indexOf("://") === -1;
}
