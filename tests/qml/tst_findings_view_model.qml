import QtQuick
import QtTest
import "../../contents/ui/domain/status.mjs" as Status
import "../../contents/ui/domain/triage.mjs" as Triage

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

    function makeVmRaw() {
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

    function makeVm() {
        const env = testCase.makeVmRaw();
        // Most tests exercise the complete fixture; the OSV default is tested
        // separately so the fixture keeps all 13 findings.
        env.vm.hideOsv = false;
        return env;
    }

    function test_initial_rows_and_counts() {
        const env = testCase.makeVm();
        compare(env.vm.totalCount, 13);
        compare(env.vm.visibleCount, 13);
        compare(env.vm.rows.length, 13);
        compare(env.vm.rows[0].sourceText, "nixpkgs/nixos-unstable (2786a2a)");
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

    function test_osv_findings_are_hidden_by_default() {
        const env = testCase.makeVmRaw();
        compare(env.vm.hideOsv, true);
        compare(env.vm.totalCount, 12);
        compare(env.vm.hiddenCount, 1);
        verify(!env.vm.rows.some(row => /^OSV-/.test(row.id)));

        env.vm.hideOsv = false;
        compare(env.vm.totalCount, 13);
        compare(env.vm.hiddenCount, 0);
        verify(env.vm.rows.some(row => row.id === "OSV-2026-1517"));

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_hidden_view_shows_only_hidden_findings() {
        const env = testCase.makeVmRaw();
        compare(env.vm.hideOsv, true);
        compare(env.vm.hiddenCount, 1);
        env.vm.toggleHiddenView();
        compare(env.vm.showHidden, true);
        compare(env.vm.rows.length, 1);
        compare(env.vm.rows[0].id, "OSV-2026-1517");
        compare(env.vm.displayTotalCount, 1);

        const hidden = env.store.report.vulnerabilities.find(
            (finding) => finding.id === "OSV-2026-1517");
        env.vm.forcedVisible = [{
            cve: hidden.id,
            package: hidden.package,
            version: hidden.version
        }];
        compare(env.vm.hiddenCount, 0);
        compare(env.vm.rows.length, 0);
        verify(env.vm.visibleFindings.some(
            (finding) => finding.id === "OSV-2026-1517"));

        env.vm.toggleHiddenView();
        compare(env.vm.showHidden, false);
        compare(env.vm.totalCount, 13);

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

    function test_search_and_drill_down_filters_are_combined() {
        const env = testCase.makeVm();
        env.vm.setSearchText("crossover");
        env.vm.showOrigin("net-snmp-lib");
        compare(env.vm.searchText, "crossover");
        compare(env.vm.originFilter, "net-snmp-lib");
        compare(env.vm.anyFilterActive, true);
        verify(env.vm.rows.every((row) =>
            row.searchText.indexOf("crossover") >= 0
            && row.originSearch.indexOf("net-snmp-lib") >= 0));


        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_exclude_filter_and_chip_key() {
        const env = testCase.makeVm();
        env.vm.excludeText = "ffmpeg";
        compare(env.vm.anyFilterActive, true);
        verify(env.vm.rows.every((row) => row.searchText.indexOf("ffmpeg") === -1));
        env.vm.clearFilter("exclude");
        compare(env.vm.excludeText, "");
        compare(env.vm.visibleCount, 13);

        env.vm.applyFilters("", "", "", "", "", "brotli");
        compare(env.vm.excludeText, "brotli");
        verify(env.vm.rows.every((row) => row.searchText.indexOf("brotli") === -1));

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_cve_advanced_filter() {
        const env = testCase.makeVm();
        env.vm.applyFilters("CVE-2026-111497", "", "", "", "");
        compare(env.vm.cveFilter, "CVE-2026-111497");
        compare(env.vm.visibleCount, 1);
        compare(env.vm.anyFilterActive, true);

        env.vm.clearFilter("cve");
        compare(env.vm.cveFilter, "");
        compare(env.vm.visibleCount, 13);

        env.vm.applyFilters("111497", "", "", "", "");
        env.vm.showPackage("brotli");
        compare(env.vm.cveFilter, "");

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
        compare(env.vm.packageFilter, "brotli");
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

        env.vm.toggleSort("source");
        compare(env.vm.sortKey, "source");
        env.vm.toggleSort("origin");
        compare(env.vm.sortKey, "origin");
        env.vm.toggleSort("severity");
        compare(env.vm.sortKey, "severity");

        env.vm.setGroupBy("cve");
        compare(env.vm.rows[0].rowType, "group");
        compare(env.vm.rows[0].groupBy, "cve");
        const cveHeaders = env.vm.rows.filter(row => row.rowType === "group");
        verify(cveHeaders.length > 0);
        verify(cveHeaders.every(row => row.key.length > 0));
        compare(env.vm.visibleCount, 13);

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

    function test_locally_ignored_findings_are_hidden() {
        const env = testCase.makeVm();
        env.vm.ignoredPairs = [{ cve: "CVE-2021-35049", package: "network" }];
        compare(env.vm.totalCount, 12);
        compare(env.vm.hiddenCount, 1);
        verify(!env.vm.rows.some(row => row.id === "CVE-2021-35049"));

        // Local ignores survive disabling the triage verdicts.
        env.vm.triageEnabled = false;
        compare(env.vm.totalCount, 12);
        compare(env.vm.hiddenCount, 1);

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_unverified_rows_are_marked_for_review() {
        const env = testCase.makeVm();
        env.store.triage = Triage.parseTriageText(JSON.stringify({
            findings: [{
                id: "CVE-2026-111497",
                package: "brotli",
                version: "1.2.1",
                verdict: "unverified",
                reasons: ["product-only-match"],
                vendor: "Google",
                product: "Brotli"
            }]
        }));
        env.store.triageRevision += 1;

        // The "Unverified findings" setting is on by default.
        compare(env.vm.hideUnverified, true);
        compare(env.vm.totalCount, 12);
        compare(env.vm.hiddenCount, 1);
        compare(env.vm.triageColumnVisible, true);

        env.vm.hideUnverified = false;
        compare(env.vm.totalCount, 13);
        compare(env.vm.hiddenCount, 0);
        compare(env.vm.triageColumnVisible, true);

        const marked = env.vm.rows.find(row => row.id === "CVE-2026-111497");
        compare(marked.needsReview, true);
        compare(marked.triageVendor, "Google");
        compare(marked.triageProduct, "Brotli");
        compare(marked.triageReasons[0], "product-only-match");

        const plain = env.vm.rows.find(row => row.id === "CVE-2021-35049");
        compare(plain.needsReview, false);

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_embedded_verdicts_are_used() {
        const env = testCase.makeVm();
        const raw = testCase.loadFixture("status-v7.json");
        raw.vulnerabilities[0].verdict = "unverified";
        raw.vulnerabilities[0].verdict_reasons = ["product-only-match"];
        raw.vulnerabilities[0].verdict_vendor = "Mozilla";
        raw.vulnerabilities[0].verdict_product = "Focus for Android";
        env.store.report = Status.normalizeReport(raw);

        compare(env.vm.triageAvailable, true);
        compare(env.vm.totalCount, 12);
        env.vm.hideUnverified = false;
        const row = env.vm.rows.find(r => r.id === "CVE-2026-111497");
        compare(row.needsReview, true);
        compare(row.triageVendor, "Mozilla");
        compare(row.triageProduct, "Focus for Android");

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }

    function test_triage_hides_suppressed_findings() {
        const env = testCase.makeVm();
        env.store.triage = Triage.parseTriageText(JSON.stringify({
            findings: [{
                id: "CVE-2021-35049",
                package: "network",
                version: "3.2.8.0",
                verdict: "suppressed",
                reasons: ["version-not-affected"]
            }]
        }));
        env.store.triageRevision += 1;

        compare(env.vm.totalCount, 12);
        compare(env.vm.hiddenCount, 1);
        compare(env.vm.maxSeverity, 9.8);
        compare(env.vm.affectedPackages, 12);
        compare(env.vm.rows.length, 12);
        verify(!env.vm.rows.some(row => row.id === "CVE-2021-35049"));
        compare(env.vm.severityBands[1].count, 4);
        compare(env.vm.triageColumnVisible, true);

        env.vm.triageEnabled = false;
        compare(env.vm.totalCount, 13);
        compare(env.vm.hiddenCount, 0);
        compare(env.vm.maxSeverity, 9.9);
        compare(env.vm.triageColumnVisible, true);
        verify(env.vm.rows.some(row => row.id === "CVE-2021-35049"));

        env.vm.destroy();
        env.store.destroy();
        env.labels.destroy();
        env.clock.destroy();
    }
}
