import QtQml
import QtQuick
import "../domain/status.mjs" as Status
import "../domain/tracker.mjs" as Tracker
import "../domain/triage.mjs" as Triage
import "../domain/urls.mjs" as Urls

// Owns the latest scan, tracker progress, the scan lifecycle and load errors.
//
// No translated text is stored here. The UI maps error/hint codes and model
// tokens through Labels.qml.
QtObject {
    id: store

    required property var source
    required property var scanService
    required property var trackerClient
    required property var clock

    // Optional sidecar written by tools/triage.mjs.
    property var triageSource: null
    property string triageFile: ""

    property string reportFile: ""
    property string logFile: ""
    property string trackerBase: Urls.TRACKER_BASE

    property var report: null
    property var tracker: null
    property var triage: null
    property string phase: "idle"
    property bool serviceActive: false
    property string loadError: ""
    property string scanError: ""
    property bool schemaNewer: false
    property string reportFingerprint: ""
    property string trackerFingerprint: ""
    property string triageFingerprint: ""
    property int triageRevision: 0
    property string preScanStamp: ""

    // Set by FindingsList while a tooltip is open; rows are not replaced until
    // the pointer leaves.
    property bool holdUpdates: false
    property var deferredReport: null

    // On-demand tracker verdicts for CVEs that have no scan-time annotation.
    property var checked: ({})
    property int checkedRevision: 0

    property string trackerHintCode: ""
    property string trackerHintArg: ""

    readonly property bool hasReport: report !== null
    readonly property bool scanning: phase === "starting" || phase === "scanning"
    readonly property bool trackerBusy: tracker !== null && tracker.complete === false
    readonly property var progress: Tracker.progressOf(tracker)
    readonly property int trackerProgressTotal: progress ? progress.total : 0
    readonly property int trackerProgressDone: progress ? progress.done : 0
    readonly property string systemChannel: (tracker && tracker.system_channel)
        || (report && report.tracker && report.tracker.system_channel)
        || ""
    readonly property int refreshInterval: trackerBusy
        ? 3000
        : (scanning ? 10000 : 60000)

    signal openExternal(string url)
    signal openLocalFile(string path)
    signal copyRequested(string text)
    signal scanStarted()
    signal scanFinished()

    property Connections sourceConnection: Connections {
        target: store.source
        function onLoaded(text, errorCode) {
            store.onStatusLoaded(text, errorCode);
        }
    }

    property Connections triageConnection: Connections {
        target: store.triageSource
        function onLoaded(text, errorCode) {
            store.onTriageLoaded(text, errorCode);
        }
    }

    property Connections trackerConnection: Connections {
        target: store.trackerClient
        function onResult(cve, state, detail) {
            store.onTrackerResult(cve, state, detail);
        }
    }

    property Timer refreshTimer: Timer {
        interval: store.refreshInterval
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: store.refresh()
    }

    property Timer serviceTimer: Timer {
        interval: 3000
        running: store.scanning
        repeat: true
        onTriggered: store.checkScanService()
    }

    property Timer scanTimeoutTimer: Timer {
        interval: 150 * 60 * 1000
        onTriggered: store.onScanTimeout()
    }

    property Timer hintTimer: Timer {
        interval: 10000
        onTriggered: store.clearHint()
    }

    function refresh() {
        store.source.read();
        store.readTriage();
        store.checkScanService();
    }

    function readTriage() {
        if (store.triageSource) {
            store.triageSource.read();
        }
    }

    function onTriageLoaded(text, errorCode) {
        if (errorCode) {
            store.clearTriage();
            return;
        }
        const parsed = Triage.parseTriageText(text);
        if (!parsed.ok) {
            store.clearTriage();
            return;
        }
        if (parsed.fingerprint === store.triageFingerprint) {
            return;
        }
        store.triage = parsed;
        store.triageFingerprint = parsed.fingerprint;
        store.triageRevision += 1;
    }

    function clearTriage() {
        if (store.triage === null && store.triageFingerprint === "") {
            return;
        }
        store.triage = null;
        store.triageFingerprint = "";
        store.triageRevision += 1;
    }

    function checkScanService() {
        store.scanService.queryActive(function (active) {
            store.onServiceState(active);
        });
    }

    function onServiceState(active) {
        store.serviceActive = active;
        if (active && !store.scanning) {
            // Adopt a scan that started before the applet/plasmashell restarted.
            store.preScanStamp = store.report ? store.report.stamp : "";
            store.phase = "scanning";
            store.scanError = "";
            store.scanTimeoutTimer.restart();
            store.scanStarted();
        } else if (!active && store.scanning) {
            store.finishScan();
        }
    }

    function startScan() {
        if (store.scanning) {
            return;
        }
        store.preScanStamp = store.report ? store.report.stamp : "";
        store.phase = "scanning";
        store.serviceActive = true;
        store.scanError = "";
        store.scanTimeoutTimer.restart();
        store.scanStarted();
        store.source.read();
        store.scanService.start(function (ok, exitCode, stderr) {
            if (!ok) {
                store.onScanStartFailed(exitCode, stderr);
            }
        });
    }

    function onScanStartFailed(exitCode, stderr) {
        store.scanError = "start-failed";
        store.phase = "failed";
        store.serviceActive = false;
        store.scanTimeoutTimer.stop();
        store.scanFinished();
    }

    function onScanTimeout() {
        store.scanError = "timeout";
        store.phase = "failed";
        store.serviceActive = false;
        store.scanFinished();
    }

    function finishScan() {
        const wasScanning = store.scanning;
        store.phase = "idle";
        store.serviceActive = false;
        store.scanTimeoutTimer.stop();
        if (wasScanning) {
            // The service writes status.json before it exits. Read it now
            // instead of waiting for the idle refresh timer (up to 60 s); the
            // pending tracker marker then shortens the next intervals to 3 s.
            store.source.read();
            store.scanFinished();
        }
    }

    function onStatusLoaded(text, errorCode) {
        if (errorCode) {
            store.loadError = errorCode;
            return;
        }
        const parsed = Status.parseStatusText(text);
        if (!parsed.ok) {
            store.loadError = parsed.error;
            return;
        }
        const next = parsed.report;
        store.loadError = "";
        store.scanError = "";
        store.schemaNewer = next.schemaNewer;

        if (next.trackerFingerprint !== store.trackerFingerprint) {
            store.tracker = next.tracker;
            store.trackerFingerprint = next.trackerFingerprint;
        }

        if (next.fingerprint !== store.reportFingerprint) {
            if (store.holdUpdates && store.hasReport) {
                store.deferredReport = next;
            } else {
                store.commit(next);
            }
        }
        store.maybeFinishScan(next);
    }

    function commit(next) {
        store.report = next;
        store.reportFingerprint = next.fingerprint;
    }

    function maybeFinishScan(next) {
        if (store.scanning
                && !store.serviceActive
                && next.stamp.length > 0
                && next.stamp !== store.preScanStamp) {
            store.finishScan();
        }
    }

    function applyDeferred() {
        const pending = store.deferredReport;
        store.deferredReport = null;
        if (pending) {
            store.commit(pending);
        }
    }

    function setHoldUpdates(value) {
        store.holdUpdates = value;
        if (!value) {
            store.applyDeferred();
        }
    }

    function setTrackerHint(code, arg) {
        store.trackerHintCode = code;
        store.trackerHintArg = arg || "";
        if (code.length > 0) {
            store.hintTimer.restart();
        } else {
            store.hintTimer.stop();
        }
    }

    function clearHint() {
        store.trackerHintCode = "";
        store.trackerHintArg = "";
    }

    function openTracker(finding) {
        const state = Tracker.stateOf(finding, store.checked);
        if (state === Tracker.TrackerState.NONE) {
            return;
        }
        if (state === Tracker.TrackerState.MISSING) {
            store.setTrackerHint("missing", finding.id);
            return;
        }
        if (state === Tracker.TrackerState.FOUND) {
            const url = Tracker.urlFor(store.trackerBase, finding, store.checked);
            if (url.length > 0) {
                store.openExternal(url);
            }
            return;
        }
        if (store.trackerBusy) {
            store.setTrackerHint("tracker-running", finding.id);
            return;
        }
        store.setTrackerHint("checking", finding.id);
        store.trackerClient.check(finding.id);
    }

    function onTrackerResult(cve, state, detail) {
        if (state === "found") {
            store.checked[cve] = true;
            store.checkedRevision += 1;
            store.setTrackerHint("", "");
            store.openExternal(Urls.trackerPage(store.trackerBase, cve));
        } else if (state === "missing") {
            store.checked[cve] = false;
            store.checkedRevision += 1;
            store.setTrackerHint("missing", cve);
        } else if (state === "rate-limited") {
            store.setTrackerHint("rate-limit", cve);
        } else {
            store.setTrackerHint("failed", cve);
        }
    }

    function copyText(text) {
        const value = String(text || "");
        if (value.length === 0) {
            return;
        }
        store.copyRequested(value);
        store.setTrackerHint("copied", value);
    }

    function openReport() {
        if (store.reportFile.length > 0) {
            store.openLocalFile(store.reportFile);
        }
    }

    function openLog() {
        if (store.logFile.length > 0) {
            store.openLocalFile(store.logFile);
        }
    }

    function openUrl(url) {
        if (url) {
            store.openExternal(String(url));
        }
    }

    function openNixpkgsSearch(packageName) {
        if (packageName) {
            store.openExternal(Urls.nixpkgsSearch(packageName));
        }
    }
}
