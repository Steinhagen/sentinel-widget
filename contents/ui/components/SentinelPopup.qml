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
    property var originPreview: null
    property var originPreviewAnchor: null

    signal scanRequested()
    signal settingsRequested()
    signal ignoreFindingRequested(var finding)

    readonly property bool compactLayout: height < Kirigami.Units.gridUnit * 22
    readonly property real cardsWidth: Kirigami.Units.gridUnit * (15.5 + 9.0 + 9.0)
        + Kirigami.Units.gridUnit * 0.55 * 2
    readonly property real usableWidth: Math.max(0, width - Kirigami.Units.largeSpacing * 2)
    // Keep the table at the card width in every layout. Previously it expanded
    // to the full popup width when the cards were hidden, which overflowed the
    // content margins and made the table jump between layouts.
    readonly property real lowerWidth: root.vm && root.vm.hasFindings
        ? Math.min(root.cardsWidth, root.usableWidth) : root.usableWidth
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
        alignedWidth: root.lowerWidth
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
                cveFilter: root.vm.cveFilter
                packageFilter: root.vm.packageFilter
                originFilter: root.vm.originFilter
                visibleCount: root.vm.visibleCount
                totalCount: root.vm.totalCount
                hiddenCount: root.vm.hiddenCount
                groupBy: root.vm.groupBy
                cardsVisible: root.vm.hasFindings && !root.compactLayout
                labels: root.labels
                onSearchChanged: (text) => root.vm.setSearchText(text)
                onFiltersApplied: (cve, packageName, origin, severity, fix) =>
                    root.vm.applyFilters(cve, packageName, origin, severity, fix)
                onClearFiltersRequested: root.vm.clearFilters()
                onGroupBySelected: (mode) => root.vm.setGroupBy(mode)
            }

            ActiveFiltersBar {
                Layout.preferredWidth: root.lowerWidth
                Layout.maximumWidth: root.lowerWidth
                Layout.alignment: Qt.AlignHCenter
                searchText: root.vm.searchText
                severityBand: root.vm.severityBand
                fixState: root.vm.fixState
                cveFilter: root.vm.cveFilter
                packageFilter: root.vm.packageFilter
                originFilter: root.vm.originFilter
                theme: root.theme
                labels: root.labels
                onRemoveFilter: (key) => root.vm.clearFilter(key)
                onClearAllRequested: root.vm.clearFilters()
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
                triageColumnVisible: root.vm.triageColumnVisible
                sortKey: root.vm.sortKey
                sortDescending: root.vm.sortDescending
                groupBy: root.vm.groupBy
                groupsExpanded: root.vm.groupsExpanded
                groupSortKey: root.vm.groupSortKey
                groupSortDescending: root.vm.groupSortDescending
                onSortRequested: (key) => root.vm.toggleSort(key)
                onToggleGroupsExpandedRequested: root.vm.toggleGroupsExpanded()
                onGroupSortRequested: (key) => root.vm.toggleGroupSort(key)
                onGroupToggleRequested: (key) => root.vm.toggleGroup(key)
                onOpenFinding: (url) => root.store.openUrl(url)
                onFilterPackageRequested: (name) => root.vm.showPackage(name)
                onFilterOriginRequested: (name) => root.vm.showOrigin(name)
                onOriginPreviewRequested: (origin, anchor) => {
                    originPreviewTimer.stop();
                    root.originPreview = origin;
                    root.originPreviewAnchor = anchor;
                }
                onOpenFixRequested: (url) => root.store.openUrl(url)
                onTrackerRequested: (finding) => root.store.openTracker(finding)
                onCopyRequested: (text) => root.store.copyText(text)
                onOpenMasterSourceRequested: (url) => root.store.openUrl(url)
                onNixpkgsSearchRequested: (name) => root.store.openNixpkgsSearch(name)
                onIgnoreRequested: (finding) => root.ignoreFindingRequested(finding)
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

        Timer {
            id: originPreviewTimer

            interval: 160
            onTriggered: root.originPreview = null
        }

        Item {
            id: originOverlay

            readonly property var anchorPoint: root.originPreviewAnchor
                ? originOverlay.mapFromItem(null,
                    root.originPreviewAnchor.x, root.originPreviewAnchor.y)
                : Qt.point(0, 0)
            readonly property var anchorSize: root.originPreviewAnchor || {
                width: 0,
                height: 0
            }

            anchors.fill: parent
            z: 1000
            visible: root.originPreview !== null

            Rectangle {
                anchors.fill: parent
                color: Qt.rgba(0, 0, 0, 0.45)

                HoverHandler {
                    onHoveredChanged: {
                        if (hovered) {
                            originPreviewTimer.restart();
                        }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        originPreviewTimer.stop();
                        root.originPreview = null;
                    }
                }
            }

            OriginPopover {
                id: originPreviewCard

                x: {
                    const margin = 12;
                    const point = originOverlay.anchorPoint;
                    return Math.max(margin, Math.min(
                        point.x + (originOverlay.anchorSize.width - width) / 2,
                        originOverlay.width - width - margin));
                }
                y: {
                    const margin = 12;
                    const point = originOverlay.anchorPoint;
                    return Math.max(margin, Math.min(
                        point.y + originOverlay.anchorSize.height / 2
                            - height / 2,
                        originOverlay.height - height - margin));
                }
                width: Math.min(implicitWidth, originOverlay.width - 24)
                height: implicitHeight
                origin: root.originPreview
                theme: root.theme
                labels: root.labels

                HoverHandler {
                    onHoveredChanged: {
                        if (hovered) {
                            originPreviewTimer.stop();
                        } else {
                            originPreviewTimer.restart();
                        }
                    }
                }
            }
        }
    }
}
