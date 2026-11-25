import QtQuick

import org.kde.plasma.plasmoid
import org.kde.plasma.core as PlasmaCore

import "components"
import "services"
import "state"

PlasmoidItem {
    id: applet

    // Written by the Sentinel scan service.
    readonly property string statusFile: "/var/lib/sentinel/status.json"
    readonly property string triageFile: "/var/lib/sentinel/triage.json"
    readonly property string reportFile: "/var/lib/sentinel/report.csv"
    readonly property string logFile: "/var/lib/sentinel/last.log"

    // Services are the only place with side effects.
    AppSettings {
        id: appletSettings
        badgeMode: Plasmoid.configuration.badgeMode || "count"
        trackerToken: Plasmoid.configuration.sentinelTrackerToken || ""
        triageIgnore: Plasmoid.configuration.triageIgnore || "[]"
        triageEnabled: Plasmoid.configuration.triageEnabled !== false
        hideUnverified: Plasmoid.configuration.hideUnverified !== false
        hideOsv: Plasmoid.configuration.hideOsv !== false
    }

    CommandRunner { id: commandRunner }
    StatusFileSource {
        id: statusFileSource
        runner: commandRunner
        path: applet.statusFile
    }
    StatusFileSource {
        id: triageFileSource
        runner: commandRunner
        path: applet.triageFile
    }
    ScanService {
        id: sentinelService
        runner: commandRunner
    }
    TrackerClient {
        id: trackerClientService
        runner: commandRunner
    }
    Clock { id: appletClock }
    UrlService { id: urlService }
    ClipboardService { id: clipboardService }

    // State is per applet instance. Do not make these QML singletons: two
    // Sentinel applets on the same desktop must not share data or filters.
    ScanStore {
        id: scanStore
        source: statusFileSource
        triageSource: triageFileSource
        scanService: sentinelService
        trackerClient: trackerClientService
        clock: appletClock
        triageFile: applet.triageFile
        reportFile: applet.reportFile
        logFile: applet.logFile
    }

    SentinelTheme { id: sentinelTheme }
    Labels { id: sentinelLabels }

    FindingsViewModel {
        id: viewModel
        store: scanStore
        labels: sentinelLabels
        triageEnabled: appletSettings.triageEnabled
        hideUnverified: appletSettings.hideUnverified
        hideOsv: appletSettings.hideOsv
        ignoredPairs: appletSettings.ignoredPairs
    }

    Plasmoid.title: i18n("Sentinel")
    Plasmoid.icon: sentinelLabels.stateIcon(viewModel.state,
        scanStore.hasReport, viewModel.maxSeverity)
    Plasmoid.busy: scanStore.scanning

    // The shell's default compact representation uses this badge.
    badgeText: sentinelLabels.badgeText(scanStore.report,
        appletSettings.effectiveBadgeMode, viewModel.totalCount)

    toolTipMainText: i18n("Sentinel")
    toolTipSubText: sentinelLabels.toolTipSubText(scanStore, viewModel)

    Plasmoid.contextualActions: [
        PlasmaCore.Action {
            text: i18n("Scan for Vulnerabilities Now")
            icon.name: "view-refresh"
            enabled: !scanStore.scanning
            onTriggered: scanStore.startScan()
        },
        PlasmaCore.Action {
            text: i18n("Open Vulnerability Report")
            icon.name: "document-open"
            enabled: scanStore.hasReport
            onTriggered: scanStore.openReport()
        },
        PlasmaCore.Action {
            text: i18n("Open Scan Log")
            icon.name: "text-x-generic"
            onTriggered: scanStore.openLog()
        },
        PlasmaCore.Action {
            text: i18n("Open Nixpkgs Security Tracker")
            icon.name: "internet-services"
            onTriggered: scanStore.openUrl(scanStore.trackerBase)
        }
    ]

    Connections {
        target: scanStore

        function onOpenExternal(url) {
            urlService.open(url);
        }

        function onOpenLocalFile(path) {
            urlService.openLocalFile(path);
        }

        function onCopyRequested(text) {
            clipboardService.copy(text);
        }
    }

    // The ignore list lives in the applet configuration, so the row menu can
    // build it without touching the root-owned triage files.
    function ignoreFinding(finding) {
        if (!finding || !finding.id || !finding.package) {
            return;
        }
        const config = Plasmoid.configuration;
        config.triageIgnore = appletSettings.withIgnoredPair(
            String(finding.id), String(finding.package), String(finding.version || ""));
        if (typeof config.writeConfig === "function") {
            config.writeConfig();
        }
    }

    fullRepresentation: SentinelPopup {
        store: scanStore
        vm: viewModel
        theme: sentinelTheme
        labels: sentinelLabels

        onScanRequested: scanStore.startScan()
        onIgnoreFindingRequested: (finding) => applet.ignoreFinding(finding)
        onSettingsRequested: {
            const action = Plasmoid.internalAction("configure");
            if (action) {
                action.trigger();
            }
        }
    }
}
