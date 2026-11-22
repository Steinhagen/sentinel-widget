import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.extras as PlasmaExtras

PlasmaExtras.Representation {
    id: root

    property var store: null
    property var vm: null
    property var theme: null
    property var labels: null

    signal scanRequested()
    signal settingsRequested()

    readonly property bool compactLayout: height < Kirigami.Units.gridUnit * 22
    readonly property real cardsWidth: Kirigami.Units.gridUnit * (15.5 + 9.0 + 9.0)
        + Kirigami.Units.gridUnit * 0.55 * 2
    readonly property real lowerWidth: root.vm && root.vm.hasFindings
        && !root.compactLayout ? root.cardsWidth : width
    readonly property string hintText: {
        if (!root.store || !root.vm) {
            return "";
        }
        if (root.vm.loadError.length > 0 && root.store.hasReport) {
            return root.labels.loadErrorText(root.vm.loadError);
        }
        if (root.store.scanError.length > 0) {
            return root.labels.scanErrorText(root.store.scanError);
        }
        if (root.store.trackerHintCode.length > 0) {
            return root.labels.trackerHint(root.store.trackerHintCode,
                root.store.trackerHintArg);
        }
        if (root.vm.schemaNewer) {
            return root.labels.schemaNewerText();
        }
        return "";
    }

    onVisibleChanged: {
        if (!visible && root.store) {
            root.store.setHoldUpdates(false);
        }
    }

    Layout.minimumWidth: Kirigami.Units.gridUnit * 36
    Layout.preferredWidth: Kirigami.Units.gridUnit * 36
    Layout.minimumHeight: Kirigami.Units.gridUnit * 18
    Layout.preferredHeight: root.vm && root.vm.hasFindings
        ? Kirigami.Units.gridUnit * 46
        : Kirigami.Units.gridUnit * 30

    Connections {
        target: root.vm
        function onRowsReset(preserveScroll) {
            findingsList.handleRowsReset(preserveScroll);
        }
    }

    Connections {
        target: root.store
        function onScanStarted() {
            Qt.callLater(function () {
                findingsList.positionViewAtBeginning();
            });
        }
        function onScanFinished() {
            Qt.callLater(function () {
                findingsList.positionViewAtBeginning();
            });
        }
    }

    header: HeaderBar {
        horizontalInset: (root.store && root.store.hasReport && !root.compactLayout)
            ? Math.max(0, (root.width - root.cardsWidth) / 2)
            : Kirigami.Units.smallSpacing
        postureLabel: root.labels.postureLabel(root.vm.state, root.store.hasReport)
        stateSummary: root.labels.stateSummary(root.store.report,
            root.store.scanning, root.vm.affectedPackages, root.vm.maxSeverity)
        stateIcon: root.labels.stateIcon(root.vm.state, root.store.hasReport)
        stateColor: root.theme.stateColor(root.vm.state, root.store.hasReport)
        lastScanLabel: root.labels.lastScanLabel(root.vm.lastScanAge)
        lastScanTooltip: root.labels.lastScanTooltip(root.store.report
            ? root.store.report.scannedAtMs : null)
        detailTooltip: {
            const parts = [];
            if (root.vm.state === "unknown" && root.vm.scanError) {
                parts.push(root.vm.scanError);
            }
            parts.push(root.labels.resultInfoText(root.vm, root.store));
            return parts.join("\n\n");
        }
        scanning: root.store.scanning
        trackerBusy: root.store.trackerBusy
        serviceActive: root.store.serviceActive
        progress: root.store.progress
        trackerWarningText: root.labels.trackerWarningText(root.store)
        labels: root.labels
        theme: root.theme
        onScanRequested: root.scanRequested()
        onSettingsRequested: root.settingsRequested()
    }

    contentItem: Item {
        ColumnLayout {
            id: content

            anchors.fill: parent
            anchors.margins: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.smallSpacing

            SummaryCards {
                Layout.fillWidth: false
                Layout.preferredWidth: root.cardsWidth
                Layout.alignment: Qt.AlignHCenter
                visible: root.vm.hasFindings && !root.compactLayout
                maxSeverity: root.vm.maxSeverity
                findings: root.vm.totalCount
                affectedPackages: root.vm.affectedPackages
                trackedCves: root.vm.trackedCves
                severityBands: root.vm.severityBands
                fixBands: root.vm.fixBands
                fixTotal: root.vm.fixStateTotal
                selectedSeverity: root.vm.severityBand
                selectedFixState: root.vm.fixState
                theme: root.theme
                labels: root.labels
                onSeveritySelected: (band) => root.vm.setSeverityBand(band)
                onFixStateSelected: (band) => root.vm.setFixState(band)
            }

            FindingsToolbar {
                Layout.preferredWidth: root.lowerWidth
                Layout.maximumWidth: root.lowerWidth
                Layout.alignment: Qt.AlignHCenter
                visible: root.vm.hasFindings
                searchText: root.vm.searchText
                severityBand: root.vm.severityBand
                fixState: root.vm.fixState
                anyFilterActive: root.vm.anyFilterActive
                visibleCount: root.vm.visibleCount
                totalCount: root.vm.totalCount
                groupByOrigin: root.vm.groupByOrigin
                labels: root.labels
                onSearchChanged: (text) => root.vm.setSearchText(text)
                onSeveritySelected: (band) => root.vm.setSeverityBand(band)
                onFixStateSelected: (band) => root.vm.setFixState(band)
                onClearFiltersRequested: root.vm.clearFilters()
                onGroupToggled: root.vm.toggleGroupByOrigin()
            }

            FindingsList {
                id: findingsList

                Layout.preferredWidth: root.lowerWidth
                Layout.maximumWidth: root.lowerWidth
                Layout.alignment: Qt.AlignHCenter
                Layout.fillHeight: true
                Layout.minimumHeight: 0
                visible: root.vm.hasFindings
                rows: root.vm.rows
                theme: root.theme
                labels: root.labels
                systemChannel: root.store.systemChannel
                sortKey: root.vm.sortKey
                sortDescending: root.vm.sortDescending
                onSortRequested: (key) => root.vm.toggleSort(key)
                onOpenFinding: (url) => root.store.openUrl(url)
                onFilterPackageRequested: (name) => root.vm.showPackage(name)
                onFilterOriginRequested: (name) => root.vm.showOrigin(name)
                onOpenFixRequested: (url) => root.store.openUrl(url)
                onTrackerRequested: (finding) => root.store.openTracker(finding)
                onCopyRequested: (text) => root.store.copyText(text)
                onOpenMasterSourceRequested: (url) => root.store.openUrl(url)
                onNixpkgsSearchRequested: (name) => root.store.openNixpkgsSearch(name)
                onHoldUpdatesChanged: (held) => root.store.setHoldUpdates(held)
            }

            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 0
                visible: !root.vm.hasFindings

                EmptyState {
                    anchors.fill: parent
                    emptyIcon: root.labels.emptyIcon(root.vm.state, root.store.hasReport)
                    emptyTitle: root.labels.emptyTitle(root.vm.state, root.store.hasReport)
                    emptyExplanation: root.labels.emptyExplanation(root.vm.state,
                        root.store.hasReport, root.store.scanning,
                        root.vm.scanError, root.vm.loadError)
                }
            }

            TrackerHint {
                text: root.hintText
            }
        }
    }
}
