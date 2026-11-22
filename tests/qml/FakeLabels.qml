import QtQml

QtObject {
    function fixText(fix) {
        return fix ? fix.labelKey : "";
    }

    function fixTooltip(row, channel) {
        return "fix:" + (row.fix ? row.fix.labelKey : "");
    }

    function viaLabel(row) {
        return row.scanners.join(", ") + " " + row.confidence;
    }

    function originTooltip(origin) {
        return origin && origin.names ? origin.names.join(",") : "";
    }

    function cveTooltip(id, hasUrl) {
        return id;
    }

    function filterPackageTooltip(name) {
        return name;
    }

    function rowAccessibleName(id, pkg, sev) {
        return id + "/" + pkg + "/" + sev;
    }

    function headerLabel(key) {
        return key;
    }

    function sortTooltip(key, active, desc, label) {
        return label;
    }

    function noMatchesText() {
        return "No matches";
    }

    function severityTitle() {
        return "SEVERITY";
    }

    function severityBandLabel(band) {
        return band || "All";
    }

    function fixBucketLabel(bucket) {
        return bucket || "All";
    }

    function groupLabel(name) {
        return name || "Unknown origin";
    }

    function groupCountText(count) {
        return count + " findings";
    }

    function searchPlaceholder() {
        return "Search";
    }

    function filtersButton() {
        return "Filters";
    }

    function filtersTooltip() {
        return "Filters";
    }

    function allSeverities() {
        return "All severities";
    }

    function unknownSeverity() {
        return "Unknown";
    }

    function allFixStates() {
        return "All fix states";
    }

    function fixFilterLabel(bucket) {
        return bucket;
    }

    function clearFiltersText() {
        return "Clear";
    }

    function clearFiltersTooltip() {
        return "Clear filters";
    }

    function groupByText(grouped) {
        return grouped ? "Flat" : "Group";
    }

    function groupByTooltip(grouped) {
        return grouped ? "Flat" : "Group";
    }

    function countLabel(visible, total) {
        return visible + " of " + total;
    }
    function showAllForPackage(name) { return "all " + name; }
    function filterByOrigin() { return "origin"; }
    function openTrackerText() { return "tracker"; }
    function openMasterFixText() { return "fix"; }
    function openMasterSourceText() { return "source"; }
    function copyCveText() { return "cve"; }
    function copyPackageText() { return "package"; }
    function copyFixUrlText() { return "fixurl"; }
    function searchNixpkgsText(name) { return "search " + name; }
}
