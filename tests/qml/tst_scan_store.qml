import QtQuick
import QtTest
import "../../contents/ui/domain/status.mjs" as Status

TestCase {
    id: testCase
    name: "ScanStore"

    function spy(target, signalName) {
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.signalName = signalName;
        spy.target = target;
        return spy;
    }

    function loadText(name) {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", Qt.resolvedUrl("../fixtures/" + name), false);
        xhr.send();
        return xhr.responseText;
    }

    function makeStore() {
        const source = Qt.createComponent(Qt.resolvedUrl("FakeStatusSource.qml")).createObject(testCase);
        const service = Qt.createComponent(Qt.resolvedUrl("FakeScanService.qml")).createObject(testCase);
        const client = Qt.createComponent(Qt.resolvedUrl("FakeTrackerClient.qml")).createObject(testCase);
        const clock = Qt.createQmlObject("import QtQml; QtObject { property double now: 1795360000000 }", testCase);
        const store = Qt.createComponent(Qt.resolvedUrl("../../contents/ui/state/ScanStore.qml"))
            .createObject(testCase, {
                source: source,
                scanService: service,
                trackerClient: client,
                clock: clock,
                reportFile: "/tmp/report.csv",
                logFile: "/tmp/last.log"
            });
        store.refreshTimer.running = false;
        store.serviceTimer.running = false;
        store.scanTimeoutTimer.stop();
        return { store: store, source: source, service: service, client: client, clock: clock };
    }

    function test_loads_a_report_and_tracker_progress() {
        const env = testCase.makeStore();
        const started = testCase.spy(env.store, "scanStarted");
        env.store.refresh();
        compare(env.source.readCount, 1);
        verify(env.service.queryCount >= 1);

        env.source.deliver(testCase.loadText("status-v7.json"), "");
        compare(env.store.hasReport, true);
        compare(env.store.report.vulnerabilities.length, 13);
        compare(env.store.systemChannel, "nixos-unstable");
        compare(env.store.trackerBusy, false);
        compare(env.store.loadError, "");
        compare(env.store.schemaNewer, false);
        compare(env.store.trackerProgressTotal, 14);
        compare(env.store.trackerProgressDone, 14);
        compare(started.count, 0);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_load_errors_and_newer_schema() {
        const env = testCase.makeStore();
        env.source.deliver("", "permission");
        compare(env.store.loadError, "permission");
        env.source.deliver("{ broken", "");
        compare(env.store.loadError, "invalid-json");
        env.source.deliver('{"schema_version":99,"state":"secure"}', "");
        compare(env.store.schemaNewer, true);
        compare(env.store.hasReport, true);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_hold_defers_a_changed_report() {
        const env = testCase.makeStore();
        env.source.deliver(testCase.loadText("status-v7.json"), "");
        const before = env.store.report;
        const raw = JSON.parse(testCase.loadText("status-v7.json"));
        raw.state = "secure";
        raw.findings = 1;
        env.store.setHoldUpdates(true);
        env.source.deliver(JSON.stringify(raw), "");
        compare(env.store.report, before);
        verify(env.store.deferredReport !== null);
        env.store.setHoldUpdates(false);
        verify(env.store.report !== before);
        compare(env.store.report.state, "secure");
        verify(env.store.deferredReport === null);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_scan_start_and_finish() {
        const env = testCase.makeStore();
        const started = testCase.spy(env.store, "scanStarted");
        const finished = testCase.spy(env.store, "scanFinished");
        env.store.startScan();
        compare(env.store.scanning, true);
        compare(started.count, 1);
        compare(env.service.startCount, 1);
        env.service.respondStart(true);
        env.store.checkScanService();
        env.service.respondActive(false);
        compare(env.store.scanning, false);
        compare(finished.count, 1);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_failed_scan_reports_an_error() {
        const env = testCase.makeStore();
        env.store.startScan();
        env.service.respondStart(false);
        compare(env.store.phase, "failed");
        compare(env.store.scanError, "start-failed");
        compare(env.store.scanning, false);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_adopts_a_running_service() {
        const env = testCase.makeStore();
        const started = testCase.spy(env.store, "scanStarted");
        env.store.refresh();
        env.service.respondActive(true);
        compare(env.store.scanning, true);
        compare(started.count, 1);
        env.service.respondActive(false);
        compare(env.store.scanning, false);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_tracker_actions_and_hints() {
        const env = testCase.makeStore();
        env.source.deliver(testCase.loadText("status-v7.json"), "");
        const opened = testCase.spy(env.store, "openExternal");
        const copied = testCase.spy(env.store, "copyRequested");
        const found = env.store.report.vulnerabilities.find(v => v.id === "CVE-2026-111497");
        const missing = env.store.report.vulnerabilities.find(v => v.id === "CVE-2021-35049");
        const unknown = { id: "CVE-2099-9999", tracker: null };

        env.store.openTracker(found);
        compare(opened.count, 1);
        verify(opened.signalArguments[0][0].indexOf("tracker.security.nixos.org") > 0);

        env.store.openTracker(missing);
        compare(env.store.trackerHintCode, "missing");
        compare(env.store.trackerHintArg, "CVE-2021-35049");

        env.store.openTracker(unknown);
        compare(env.store.trackerHintCode, "checking");
        compare(env.client.checkCount, 1);
        env.client.respond("CVE-2099-9999", "found", "200");
        compare(env.store.checked["CVE-2099-9999"], true);
        compare(env.store.checkedRevision, 1);
        compare(opened.count, 2);

        env.store.copyText("CVE-2026-111497");
        compare(copied.count, 1);
        compare(env.store.trackerHintCode, "copied");
        env.store.clearHint();
        compare(env.store.trackerHintCode, "");

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }

    function test_open_report_log_and_search() {
        const env = testCase.makeStore();
        const local = testCase.spy(env.store, "openLocalFile");
        const external = testCase.spy(env.store, "openExternal");
        env.store.openReport();
        compare(local.count, 1);
        compare(local.signalArguments[0][0], "/tmp/report.csv");
        env.store.openLog();
        compare(local.count, 2);
        env.store.openNixpkgsSearch("zlib");
        compare(external.count, 1);
        verify(external.signalArguments[0][0].indexOf("search.nixos.org") > 0);

        env.store.destroy();
        env.source.destroy();
        env.service.destroy();
        env.client.destroy();
        env.clock.destroy();
    }
}
