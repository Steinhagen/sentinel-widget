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
    function groupTitle(groupBy, key) {
        return key;
    }
    function groupColumnLabel(groupBy) { return groupBy; }
    function groupCountColumnLabel() { return "Findings"; }
    function groupSortTooltip(groupBy, key, active, descending) { return key; }
    function groupToggleTooltip(expanded) {
        return expanded ? "Hide" : "Show";
    }
    function groupByButton(groupBy) {
        return groupBy === "none" ? "Group by" : "Group by: " + groupBy;
    }
    function groupByTooltip(groupBy) { return "group"; }
    function groupNone() { return "No grouping"; }
    function groupPriority() { return "Priority"; }
    function groupPackage() { return "Package"; }
    function groupOrigin() { return "Origin"; }
    function expandAllGroups() { return "Expand all"; }
    function collapseAllGroups() { return "Collapse all"; }
}
