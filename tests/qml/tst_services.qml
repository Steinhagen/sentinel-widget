import QtQuick
import QtTest

TestCase {
    id: testCase
    name: "Services"

    function spy(target, signalName) {
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.signalName = signalName;
        spy.target = target;
        return spy;
    }

    function createFake() {
        return Qt.createComponent(Qt.resolvedUrl("FakeRunner.qml")).createObject(testCase);
    }

    function createService(file, properties) {
        const component = Qt.createComponent(Qt.resolvedUrl("../../contents/ui/services/" + file));
        return component.createObject(testCase, properties);
    }

    function test_status_source_reads_only_when_changed() {
        const fake = testCase.createFake();
        const source = testCase.createService("StatusFileSource.qml", {
            runner: fake,
            path: "/tmp/sentinel-status.json"
        });
        const loaded = testCase.spy(source, "loaded");
        const unchanged = testCase.spy(source, "notModified");

        source.read();
        compare(fake.count(), 1);
        verify(fake.commandAt(0).indexOf("stat -c") === 0);

        fake.respond(0, 0, "2026-11-22 17:05:35.000000000 +0200:100", "");
        compare(fake.count(), 2);
        verify(fake.commandAt(1).indexOf("cat --") === 0);
        fake.respond(1, 0, '{"state":"secure"}', "");
        compare(loaded.count, 1);
        compare(loaded.signalArguments[0][0], '{"state":"secure"}');
        compare(loaded.signalArguments[0][1], "");

        source.read();
        compare(fake.count(), 3);
        fake.respond(2, 0, "2026-11-22 17:05:35.000000000 +0200:100", "");
        compare(fake.count(), 3);
        compare(unchanged.count, 1);
        compare(loaded.count, 1);

        source.destroy();
        fake.destroy();
    }

    function test_status_source_classifies_errors() {
        const fake = testCase.createFake();
        const source = testCase.createService("StatusFileSource.qml", {
            runner: fake,
            path: "/tmp/missing.json"
        });
        const loaded = testCase.spy(source, "loaded");

        source.read();
        fake.respond(0, 1, "", "No such file or directory");
        fake.respond(1, 1, "", "No such file or directory");
        compare(loaded.count, 1);
        compare(loaded.signalArguments[0][1], "missing");

        source.read();
        fake.respond(2, 1, "", "Permission denied");
        fake.respond(3, 1, "", "Permission denied");
        compare(loaded.signalArguments[1][1], "permission");

        source.destroy();
        fake.destroy();
    }

    function test_scan_service_state_and_start() {
        const fake = testCase.createFake();
        const service = testCase.createService("ScanService.qml", { runner: fake });
        const activeChanged = testCase.spy(service, "activeChanged");
        let started = null;

        service.queryActive(function (active) { started = active; });
        verify(fake.commandAt(0).indexOf("systemctl is-active") === 0);
        fake.respond(0, 0, "active\n", "");
        compare(service.active, true);
        compare(started, true);
        compare(activeChanged.count, 1);

        service.start(function (ok) { started = ok; });
        verify(fake.commandAt(1).indexOf("systemctl start --no-block") === 0);
        fake.respond(1, 0, "", "");
        compare(started, true);

        service.destroy();
        fake.destroy();
    }

    function test_tracker_client_http_codes() {
        const fake = testCase.createFake();
        const client = testCase.createService("TrackerClient.qml", { runner: fake });
        const result = testCase.spy(client, "result");

        client.check("CVE-2026-1234");
        verify(fake.commandAt(0).indexOf("curl -sS") === 0);
        fake.respond(0, 0, "200", "");
        compare(result.count, 1);
        compare(result.signalArguments[0][0], "CVE-2026-1234");
        compare(result.signalArguments[0][1], "found");

        client.check("CVE-2026-1234");
        fake.respond(1, 0, "404", "");
        compare(result.signalArguments[1][1], "missing");

        client.check("CVE-2026-1234");
        fake.respond(2, 0, "429", "");
        compare(result.signalArguments[2][1], "rate-limited");

        const before = fake.count();
        client.check("OSV-2026-1");
        compare(fake.count(), before);
        compare(result.signalArguments[3][1], "failed");
        compare(result.signalArguments[3][2], "invalid-cve");

        client.destroy();
        fake.destroy();
    }

    function test_settings_and_clock() {
        const settings = testCase.createService("AppSettings.qml", { badgeMode: "dot" });
        compare(settings.effectiveBadgeMode, "dot");
        settings.badgeMode = "wat";
        compare(settings.effectiveBadgeMode, "count");
        settings.destroy();

        const ignores = testCase.createService("AppSettings.qml", {
            triageIgnore: '[{"cve":"CVE-2021-24028","package":"thrift"}]'
        });
        compare(ignores.ignoredPairs.length, 1);
        compare(ignores.ignoredPairs[0].package, "thrift");
        compare(JSON.parse(ignores.withIgnoredPair("CVE-2021-24028", "thrift")).length, 1);
        compare(JSON.parse(ignores.withIgnoredPair("CVE-2026-1", "ffmpeg")).length, 2);
        ignores.destroy();

        const versioned = testCase.createService("AppSettings.qml", {
            triageIgnore: "[]"
        });
        const first = JSON.parse(versioned.withIgnoredPair(
            "CVE-2026-1", "ffmpeg", "6.1.6"));
        compare(first.length, 1);
        compare(first[0].version, "6.1.6");
        versioned.triageIgnore = JSON.stringify(first);
        const second = JSON.parse(versioned.withIgnoredPair(
            "CVE-2026-1", "ffmpeg", "6.1.7"));
        compare(second.length, 2);
        compare(second[1].version, "6.1.7");
        versioned.destroy();

        const restored = testCase.createService("AppSettings.qml", { triageShow: "[]" });
        const forced = JSON.parse(restored.withForcedVisible(
            "CVE-2026-1", "ffmpeg", "6.1.6"));
        compare(forced.length, 1);
        compare(forced[0].version, "6.1.6");
        restored.triageShow = JSON.stringify(forced);
        compare(JSON.parse(restored.withoutForcedVisible(
            "CVE-2026-1", "ffmpeg", "6.1.6")).length, 0);
        restored.destroy();

        const clock = testCase.createService("Clock.qml", { running: false });
        clock.now = 42;
        compare(clock.now, 42);
        clock.tick();
        verify(clock.now > 42);
        clock.destroy();
    }
}
