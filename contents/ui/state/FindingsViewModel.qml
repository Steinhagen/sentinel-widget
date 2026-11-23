import QtQml
import "../domain/filters.mjs" as Filters
import "../domain/severity.mjs" as Severity
import "../domain/table.mjs" as Table
import "../domain/time.mjs" as Time
import "../domain/triage.mjs" as Triage

// Selection and derived rows for the findings table. It knows nothing about
// ListView, tooltips, colors or the applet shell.
QtObject {
    id: vm

    required property var store
    required property var labels

    // Bound to the widget settings in main.qml.
    property bool triageEnabled: true
    property bool hideUnverified: true
    // { cve, package } pairs the user ignored from the applet.
    property var ignoredPairs: []

    property string searchText: ""
    property string severityBand: ""
    property string fixState: ""
    property string trackerState: ""
    property string packageFilter: ""
    property string originFilter: ""
    property string cveFilter: ""
    property string sortKey: "severity"
    property bool sortDescending: true
    property string groupBy: "none"
    property var collapsedGroups: ({})
    property int groupsRevision: 0
    property string groupSortKey: ""
    property bool groupSortDescending: false

    readonly property var reportModel: store ? store.report : null
    readonly property int checkedRevision: store ? store.checkedRevision : 0
    readonly property string systemChannel: store ? store.systemChannel : ""
    readonly property var triage: store && store.triage !== undefined
        ? store.triage : null
    readonly property int triageRevision: store && store.triageRevision !== undefined
        ? store.triageRevision : 0
    readonly property bool triageAvailable: {
        if (vm.triage !== null) {
            return true;
        }
        const list = vm.reportModel ? vm.reportModel.vulnerabilities : null;
        if (!list) {
            return false;
        }
        for (let i = 0; i < list.length; ++i) {
            if (list[i].verdict) {
                return true;
            }
        }
        return false;
    }
    readonly property bool triageColumnVisible: vm.triageAvailable
        && !(vm.triageEnabled && vm.hideUnverified)
    readonly property bool hasFindings: vm.totalCount > 0

    readonly property var visibleFindings: {
        const revision = vm.triageRevision;
        if (revision < 0) {
            return [];
        }
        const source = vm.reportModel ? vm.reportModel.vulnerabilities : null;
        if (!source) {
            return [];
        }
        return Triage.visibleFindings(source, vm.triage, vm.triageEnabled,
            vm.ignoredPairs, vm.hideUnverified);
    }

    readonly property int hiddenCount: {
        const revision = vm.triageRevision;
        const source = vm.reportModel ? vm.reportModel.vulnerabilities : null;
        if (revision < 0 || !source) {
            return 0;
        }
        return Triage.suppressedCount(source, vm.triage, vm.triageEnabled,
            vm.ignoredPairs)
            + Triage.reviewCount(source, vm.triage, vm.hideUnverified,
                vm.ignoredPairs);
    }

    readonly property var filters: ({
        text: vm.searchText,
        severity: vm.severityBand,
        fixState: vm.fixState,
        trackerState: vm.trackerState,
        package: vm.packageFilter,
        origin: vm.originFilter,
        cve: vm.cveFilter
    })

    readonly property var allRows: vm.buildAllRows()
    readonly property var filteredRows: vm.buildFilteredRows()
    readonly property var rows: {
        const revision = vm.groupsRevision;
        if (revision < 0) {
            return [];
        }
        return vm.groupBy === "none"
            ? vm.filteredRows
            : Table.flattenGroups(vm.filteredRows, vm.groupBy, true,
                vm.collapsedGroups, vm.groupSortKey, vm.groupSortDescending);
    }
    readonly property var counts: Filters.countsOf(vm.allRows)
    readonly property var visibleGroupKeys: {
        const revision = vm.groupsRevision;
        if (revision < 0) {
            return [];
        }
        return Table.groupKeysOf(vm.filteredRows, vm.groupBy);
    }
    readonly property int collapsedVisibleGroups: {
        const revision = vm.groupsRevision;
        let count = 0;
        for (let i = 0; i < vm.visibleGroupKeys.length; ++i) {
            if (vm.collapsedGroups[vm.visibleGroupKeys[i]] === true) {
                count += 1;
            }
        }
        return revision < 0 ? 0 : count;
    }
    readonly property bool groupsExpanded: vm.collapsedVisibleGroups === 0

    readonly property int totalCount: vm.visibleFindings.length
    readonly property int visibleCount: Table.findingCount(vm.filteredRows)
    readonly property bool anyFilterActive: Filters.isActive(vm.filters)

    readonly property real maxSeverity: {
        let max = 0;
        const list = vm.visibleFindings;
        for (let i = 0; i < list.length; ++i) {
            const value = Number(list[i].severity);
            if (isFinite(value) && value > max) {
                max = value;
            }
        }
        return max;
    }
    readonly property int affectedPackages: {
        const seen = {};
        const list = vm.visibleFindings;
        for (let i = 0; i < list.length; ++i) {
            const name = list[i].package;
            if (name) {
                seen[name] = true;
            }
        }
        return Object.keys(seen).length;
    }
    readonly property int trackedCves: vm.store && vm.store.tracker
        ? Number(vm.store.tracker.cves || 0) : 0

    readonly property var severityBands: {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
        const list = vm.visibleFindings;
        for (let i = 0; i < list.length; ++i) {
            counts[Severity.bandOf(list[i].severity)] += 1;
        }
        return [
            { key: "", count: vm.totalCount },
            { key: "critical", count: counts.critical },
            { key: "high", count: counts.high },
            { key: "medium", count: counts.medium },
            { key: "low", count: counts.low },
            { key: "unknown", count: counts.unknown }
        ];
    }

    readonly property var fixBands: [
        { key: "", count: vm.totalCount },
        { key: "fixed", count: vm.counts.fix.fixed },
        { key: "progress", count: vm.counts.fix.progress },
        { key: "none", count: vm.counts.fix.none },
        { key: "unknown", count: vm.counts.fix.unknown },
        { key: "n/a", count: vm.counts.fix["n/a"] }
    ]

    readonly property var trackerBands: [
        { key: "", count: vm.totalCount },
        { key: "linked", count: vm.counts.tracker.linked },
        { key: "pending", count: vm.counts.tracker.pending },
        { key: "missing", count: vm.counts.tracker.missing },
        { key: "unchecked", count: vm.counts.tracker.unchecked }
    ]

    readonly property int fixedCount: vm.counts.fix.fixed
    readonly property int fixStateTotal: vm.fixedCount
        + vm.counts.fix.progress
        + vm.counts.fix.none
        + vm.counts.fix.unknown
        + vm.counts.fix["n/a"]

    readonly property string state: vm.reportModel ? vm.reportModel.state : "unknown"
    readonly property string scanError: vm.store && vm.store.scanError
        ? vm.store.scanError
        : (vm.reportModel ? vm.reportModel.error : "")
    readonly property string loadError: vm.store ? vm.store.loadError : ""
    readonly property bool schemaNewer: vm.store ? vm.store.schemaNewer : false
    readonly property real lastScanAge: vm.reportModel && vm.store && vm.store.clock
        ? Time.scanAge(vm.reportModel.scannedAtMs, vm.store.clock.now)
        : -1

    signal rowsReset(bool preserveScroll)

    onReportModelChanged: vm.rowsReset(true)
    onCheckedRevisionChanged: vm.rowsReset(true)
    onSystemChannelChanged: vm.rowsReset(true)
    onTriageRevisionChanged: vm.rowsReset(true)
    onTriageEnabledChanged: vm.rowsReset(true)
    onHideUnverifiedChanged: vm.rowsReset(true)
    onIgnoredPairsChanged: vm.rowsReset(true)
    onTriageColumnVisibleChanged: {
        if (!vm.triageColumnVisible && vm.sortKey === "review") {
            vm.sortKey = "severity";
            vm.sortDescending = true;
            vm.resetScroll();
        }
    }

    function buildAllRows() {
        const revision = vm.checkedRevision;
        const report = vm.reportModel;
        if (!report) {
            return [];
        }
        const source = vm.visibleFindings;
        const rows = Table.buildRows(source, {
            systemChannel: vm.systemChannel,
            checked: vm.store ? vm.store.checked : {},
            source: report.source
        });
        for (let i = 0; i < rows.length; ++i) {
            const row = rows[i];
            const fixText = vm.labels && vm.labels.fixText
                ? vm.labels.fixText(row.fix)
                : row.fix.labelKey;
            row.fixText = fixText;
            row.fixSortText = fixText + " " + (row.fix.master.version || "");
            row.viaLabel = vm.labels && vm.labels.viaLabel
                ? vm.labels.viaLabel(row)
                : (row.scanners.join(", ") + " " + row.confidence);
            const triageInfo = Triage.detailsOf(row, vm.triage);
            row.triageVerdict = triageInfo.verdict;
            row.triageReasons = triageInfo.reasons;
            row.triageVendor = triageInfo.vendor;
            row.triageProduct = triageInfo.product;
            row.needsReview = triageInfo.verdict === "unverified";
            row.searchText = row.searchText
                + " " + String(fixText).toLowerCase()
                + " " + String(row.viaLabel).toLowerCase();
        }
        // Touch the revision so the binding tracks on-demand tracker results.
        if (revision < 0) {
            return [];
        }
        return rows;
    }

    function buildFilteredRows() {
        const filtered = Filters.apply(vm.allRows, vm.filters);
        Table.sortRows(filtered, vm.sortKey, vm.sortDescending);
        return filtered;
    }

    function resetScroll() {
        vm.rowsReset(false);
    }

    function setSearchText(text) {
        const value = String(text || "");
        if (vm.searchText === value) {
            return;
        }
        vm.searchText = value;
        vm.resetScroll();
    }

    function setSeverityBand(band) {
        if (vm.severityBand === band) {
            return;
        }
        vm.severityBand = band;
        vm.resetScroll();
    }

    function setFixState(bucket) {
        if (vm.fixState === bucket) {
            return;
        }
        vm.fixState = bucket;
        vm.resetScroll();
    }

    function setTrackerState(filter) {
        if (vm.trackerState === filter) {
            return;
        }
        vm.trackerState = filter;
        vm.resetScroll();
    }

    function clearFilters() {
        if (!vm.anyFilterActive) {
            return;
        }
        vm.searchText = "";
        vm.severityBand = "";
        vm.fixState = "";
        vm.trackerState = "";
        vm.packageFilter = "";
        vm.originFilter = "";
        vm.cveFilter = "";
        vm.resetScroll();
    }

    function clearFilter(key) {
        switch (key) {
        case "text":
            vm.searchText = "";
            break;
        case "severity":
            vm.severityBand = "";
            break;
        case "fixState":
            vm.fixState = "";
            break;
        case "package":
            vm.packageFilter = "";
            break;
        case "origin":
            vm.originFilter = "";
            break;
        case "cve":
            vm.cveFilter = "";
            break;
        default:
            return;
        }
        vm.resetScroll();
    }

    function applyFilters(cve, packageName, originName, severity, fix) {
        vm.cveFilter = String(cve || "").trim();
        vm.packageFilter = String(packageName || "").trim();
        vm.originFilter = String(originName || "").trim();
        vm.severityBand = String(severity || "");
        vm.fixState = String(fix || "");
        vm.resetScroll();
    }

    function showPackage(name) {
        if (!name) {
            return;
        }
        vm.searchText = "";
        vm.severityBand = "";
        vm.fixState = "";
        vm.trackerState = "";
        vm.originFilter = "";
        vm.cveFilter = "";
        vm.packageFilter = String(name);
        vm.resetScroll();
    }

    function showOrigin(name) {
        if (!name) {
            return;
        }
        vm.searchText = "";
        vm.severityBand = "";
        vm.fixState = "";
        vm.trackerState = "";
        vm.packageFilter = "";
        vm.cveFilter = "";
        vm.originFilter = String(name);
        vm.resetScroll();
    }

    function toggleSort(key) {
        if (vm.sortKey === key) {
            vm.sortDescending = !vm.sortDescending;
        } else {
            vm.sortKey = key;
            vm.sortDescending = (key === "severity");
        }
        vm.resetScroll();
    }

    function setGroupBy(mode) {
        const value = ["none", "priority", "package", "origin"].indexOf(mode) >= 0
            ? mode : "none";
        if (vm.groupBy === value) {
            return;
        }
        vm.groupBy = value;
        vm.collapsedGroups = ({});
        vm.groupSortKey = "";
        vm.groupSortDescending = false;
        vm.groupsRevision += 1;
        vm.resetScroll();
    }

    function toggleGroupSort(key) {
        if (key !== "name" && key !== "count") {
            return;
        }
        if (vm.groupSortKey === key) {
            vm.groupSortDescending = !vm.groupSortDescending;
        } else {
            vm.groupSortKey = key;
            vm.groupSortDescending = (key === "count");
        }
        vm.resetScroll();
    }

    function groupExpanded(key) {
        return vm.collapsedGroups[key] !== true;
    }

    function toggleGroup(key) {
        const next = {};
        for (const name in vm.collapsedGroups) {
            if (name !== key && vm.collapsedGroups[name] === true) {
                next[name] = true;
            }
        }
        if (vm.collapsedGroups[key] !== true) {
            next[key] = true;
        }
        vm.collapsedGroups = next;
        vm.groupsRevision += 1;
        vm.rowsReset(true);
    }

    function toggleGroupsExpanded() {
        if (vm.groupBy === "none") {
            return;
        }
        if (vm.groupsExpanded) {
            const next = {};
            for (let i = 0; i < vm.visibleGroupKeys.length; ++i) {
                next[vm.visibleGroupKeys[i]] = true;
            }
            vm.collapsedGroups = next;
        } else {
            vm.collapsedGroups = ({});
        }
        vm.groupsRevision += 1;
        vm.resetScroll();
    }
}
