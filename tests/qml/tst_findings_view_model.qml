import QtQuick
import QtTest
import "../../contents/ui/domain/status.mjs" as Status

TestCase {
    id: testCase
    name: "FindingsViewModel"

    function spy(target, signalName) {
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.signalName = signalName;
        spy.target = target;
        return spy;
    }

    function loadFixture(name) {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", Qt.resolvedUrl("../fixtures/" + name), false);
        xhr.send();
        return JSON.parse(xhr.responseText);
    }

    function makeVm() {
        const store = Qt.createComponent(Qt.resolvedUrl("FakeStore.qml")).createObject(testCase);
        const labels = Qt.createComponent(Qt.resolvedUrl("FakeLabels.qml")).createObject(testCase);
        const clock = Qt.createQmlObject("import QtQml; QtObject { property double now: 1795360000000 }", testCase);
        const vm = Qt.createComponent(Qt.resolvedUrl("../../contents/ui/state/FindingsViewModel.qml"))
            .createObject(testCase, { store: store, labels: labels });
        store.clock = clock;
        const report = Status.normalizeReport(testCase.loadFixture("status-v7.json"));
        store.report = report;
        store.tracker = report.tracker;
        store.systemChannel = report.tracker.system_channel;
        return { store: store, labels: labels, clock: clock, vm: vm };
    }

    function test_initial_rows_and_counts() {
        const env = testCase.makeVm();
        compare(env.vm.totalCount, 13);
        compare(env.vm.visibleCount, 13);
        compare(env.vm.rows.length, 13);
        compare(env.vm.maxSeverity, 9.9);
        compare(env.vm.affectedPackages, 13);
        compare(env.vm.severityBands[1].count, 5);
        compare(env.vm.fixStateTotal, 9);
        compare(env.vm.hasFindings, true);
        compare(env.vm.anyFilterActive, false);
        verify(env.vm.lastScanAge > 0);

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_search_filter_and_clear() {
        const env = testCase.makeVm();
        const reset = testCase.spy(env.vm, "rowsReset");

        env.vm.setSearchText("brotli");
        compare(env.vm.visibleCount, 1);
        compare(env.vm.rows[0].id, "CVE-2026-111497");
        compare(env.vm.anyFilterActive, true);
        compare(reset.count, 1);
        compare(reset.signalArguments[0][0], false);

        env.vm.setSeverityBand("critical");
        compare(env.vm.rows.every(row => row.severityBand === "critical"), true);
        env.vm.setFixState("fixed");
        compare(env.vm.rows.every(row => row.fix.bucket === "fixed"), true);
        env.vm.setTrackerState("linked");
        compare(env.vm.rows.every(row => row.trackerState === "found"), true);

        env.vm.clearFilters();
        compare(env.vm.visibleCount, 13);
        compare(env.vm.anyFilterActive, false);

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_package_and_origin_drill_down() {
        const env = testCase.makeVm();
        env.vm.showPackage("brotli");
        compare(env.vm.packageFilter, "brotli");
        compare(env.vm.visibleCount, 1);

        env.vm.showOrigin("imagemagick");
        compare(env.vm.packageFilter, "");
        compare(env.vm.originFilter, "imagemagick");
        verify(env.vm.visibleCount >= 1);
        verify(env.vm.rows.every(row => row.originSearch.indexOf("imagemagick") >= 0));

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_sort_and_group() {
        const env = testCase.makeVm();
        env.vm.toggleSort("severity");
        compare(env.vm.sortKey, "severity");
        compare(env.vm.sortDescending, false);
        env.vm.toggleSort("severity");
        compare(env.vm.sortDescending, true);
        compare(env.vm.rows[0].severityValue, 9.9);

        env.vm.setGroupBy("origin");
        compare(env.vm.groupBy, "origin");
        compare(env.vm.rows[0].rowType, "group");
        compare(env.vm.rows[0].groupBy, "origin");
        verify(env.vm.rows[0].count > 0);
        compare(env.vm.visibleCount, 13);

        env.vm.setGroupBy("priority");
        compare(env.vm.rows[0].rowType, "group");
        compare(env.vm.rows[0].groupBy, "priority");
        compare(env.vm.rows[0].key, "critical");
        compare(env.vm.visibleCount, 13);
        const priorityHeaders = env.vm.rows.filter(row => row.rowType === "group");
        compare(priorityHeaders[0].key, "critical");
        verify(priorityHeaders.length > 1);

        env.vm.setGroupBy("package");
        compare(env.vm.rows[0].rowType, "group");
        compare(env.vm.rows[0].groupBy, "package");
        const packageHeaders = env.vm.rows.filter(row => row.rowType === "group");
        verify(packageHeaders.length > 0);

        const reset = testCase.spy(env.vm, "rowsReset");
        env.vm.toggleGroupsExpanded();
        compare(env.vm.groupsExpanded, false);
        compare(reset.count, 1);
        verify(env.vm.rows.length > 0);
        verify(env.vm.rows.every(row => row.rowType === "group"));
        let collapsedTotal = 0;
        for (const row of env.vm.rows) {
            collapsedTotal += row.count;
        }
        compare(collapsedTotal, 13);
        compare(env.vm.visibleCount, 13);

        env.vm.toggleGroupsExpanded();
        compare(env.vm.groupsExpanded, true);
        verify(env.vm.rows.some(row => row.rowType === "finding"));

        env.vm.setGroupBy("priority");
        const critical = env.vm.rows.find(row =>
            row.rowType === "group" && row.key === "critical");
        verify(critical !== undefined);
        compare(critical.expanded, true);
        const criticalCount = critical.count;
        env.vm.toggleGroup("critical");
        compare(env.vm.groupExpanded("critical"), false);
        compare(env.vm.groupsExpanded, false);
        const collapsedCritical = env.vm.rows.find(row =>
            row.rowType === "group" && row.key === "critical");
        compare(collapsedCritical.expanded, false);
        verify(env.vm.rows.every(row =>
            row.rowType === "group" || row.severityBand !== "critical"));
        compare(env.vm.visibleCount, 13);
        verify(env.vm.rows.length < env.vm.filteredRows.length);

        env.vm.toggleGroupsExpanded();
        compare(env.vm.groupsExpanded, true);
        verify(env.vm.rows.some(row =>
            row.rowType === "finding" && row.severityBand === "critical"));

        env.vm.toggleGroupsExpanded();
        compare(env.vm.groupsExpanded, false);
        verify(env.vm.rows.every(row => row.rowType === "group"));
        let allCollapsedTotal = 0;
        for (const row of env.vm.rows) {
            allCollapsedTotal += row.count;
        }
        compare(allCollapsedTotal, 13);
        compare(env.vm.visibleCount, 13);

        env.vm.setGroupBy("none");
        compare(env.vm.groupBy, "none");
        compare(env.vm.rows[0].rowType, "finding");

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_group_sorting() {
        const env = testCase.makeVm();
        env.vm.setGroupBy("package");
        env.vm.toggleGroupSort("name");
        compare(env.vm.groupSortKey, "name");
        compare(env.vm.groupSortDescending, false);
        const names = env.vm.rows.filter(row => row.rowType === "group")
            .map(row => row.key);
        const sorted = names.slice().sort((a, b) => a.localeCompare(b));
        compare(names.join("|"), sorted.join("|"));

        env.vm.toggleGroupSort("name");
        compare(env.vm.groupSortDescending, true);
        const namesDesc = env.vm.rows.filter(row => row.rowType === "group")
            .map(row => row.key);
        const sortedDesc = namesDesc.slice().sort((a, b) => b.localeCompare(a));
        compare(namesDesc.join("|"), sortedDesc.join("|"));

        env.vm.toggleGroupSort("count");
        compare(env.vm.groupSortKey, "count");
        compare(env.vm.groupSortDescending, true);
        const counts = env.vm.rows.filter(row => row.rowType === "group")
            .map(row => row.count);
        for (let i = 1; i < counts.length; ++i) {
            verify(counts[i - 1] >= counts[i]);
        }
        compare(env.vm.visibleCount, 13);

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_report_change_preserves_scroll_signal() {
        const env = testCase.makeVm();
        const reset = testCase.spy(env.vm, "rowsReset");
        const next = Status.normalizeReport(testCase.loadFixture("status-v7.json"));
        next.state = "secure";
        env.store.report = next;
        compare(reset.count, 1);
        compare(reset.signalArguments[0][0], true);
        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }
}
