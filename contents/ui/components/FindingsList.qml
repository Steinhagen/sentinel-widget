pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Rectangle {
    id: root

    property var rows: []
    property var theme: null
    property var labels: null
    property string systemChannel: ""
    property string sortKey: "severity"
    property bool sortDescending: true
    property string groupBy: "none"
    property bool groupsExpanded: true
    property string groupSortKey: ""
    property bool groupSortDescending: false
    property bool triageColumnVisible: false

    signal openFinding(string url)
    signal filterPackageRequested(string packageName)
    signal filterOriginRequested(string originName)
    signal openFixRequested(string url)
    signal trackerRequested(var finding)
    signal copyRequested(string text)
    signal openMasterSourceRequested(string url)
    signal nixpkgsSearchRequested(string packageName)
    signal ignoreRequested(var finding)
    signal holdUpdatesChanged(bool held)
    signal sortRequested(string key)
    signal groupToggleRequested(string groupKey)
    signal toggleGroupsExpandedRequested()
    signal groupSortRequested(string key)

    color: root.theme ? root.theme.cardColor : "transparent"
    radius: 12
    border.width: 1
    border.color: root.theme ? root.theme.cardBorder : "transparent"

    TextMetrics {
        id: metricFixed
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "fixed" }) : "fixed"
    }
    TextMetrics {
        id: metricStaging
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "staging" }) : "staging"
    }
    TextMetrics {
        id: metricMaster
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "master" }) : "master"
    }
    TextMetrics {
        id: metricIssue
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "issue" }) : "issue"
    }
    TextMetrics {
        id: metricNoFix
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "no fix" }) : "no fix"
    }
    TextMetrics {
        id: metricUnknown
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "unknown" }) : "unknown"
    }
    TextMetrics {
        id: metricNa
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "n/a" }) : "n/a"
    }
    TextMetrics {
        id: metricUnstable
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.fixText({ labelKey: "release", labelArg: "unstable" }) : "unstable"
    }
    TextMetrics {
        id: metricTriage
        font: Kirigami.Theme.smallFont
        text: root.labels ? root.labels.triageHeaderText() : "Triage"
    }

    readonly property real fixPillWidth: Math.max(
        metricFixed.width,
        metricStaging.width,
        metricMaster.width,
        metricIssue.width,
        metricNoFix.width,
        metricUnknown.width,
        metricNa.width,
        metricUnstable.width) + Kirigami.Units.smallSpacing * 2.2

    // The triage state is an icon, so the column only has to fit the header
    // and the 18 px badge. This gives the package and source the width the
    // old text chip used to reserve.
    readonly property real triageColumnWidth: root.triageColumnVisible
        ? Math.max(Kirigami.Units.gridUnit * 2.8,
            metricTriage.width + Kirigami.Units.smallSpacing * 5)
        : 0

    // The CVE column also carries the package source on the second line, so
    // it is wider than the CVE id alone; 10.5 grid units keeps the channel
    // and revision readable, and leaves the package column the rest. The full
    // "nixpkgs/nixos-unstable (2786a2a)" label is in the source tooltip.
    readonly property real cveColumnWidth: Kirigami.Units.gridUnit * 11

    readonly property var headerColumns: [
        { key: "severity", width: Kirigami.Units.gridUnit * 2, fill: false, align: "center" },
        { key: "cve", width: root.cveColumnWidth, fill: false, align: "left" },
        { key: "package", width: 0, fill: true, align: "left" },
        { key: "review", width: root.triageColumnWidth, fill: false, align: "center" },
        { key: "master", width: root.fixPillWidth, fill: false, align: "center" }
    ]

    function sortArrow(key) {
        if (root.sortKey !== key) {
            return "↕";
        }
        return root.sortDescending ? "↓" : "↑";
    }

    function headerLabelFor(key) {
        if (key === "review") {
            return root.labels ? root.labels.triageHeaderText() : "Triage";
        }
        return root.labels ? root.labels.headerLabel(key) : key;
    }

    function headerText(key) {
        return root.headerLabelFor(key) + " " + root.sortArrow(key);
    }

    function headerTooltip(key) {
        if (!root.labels) {
            return "";
        }
        return root.labels.sortTooltip(key, root.sortKey === key,
            root.sortDescending, root.headerLabelFor(key));
    }

    function positionViewAtBeginning() {
        findingsList.positionViewAtBeginning();
    }

    function handleRowsReset(preserveScroll) {
        if (preserveScroll) {
            const saved = findingsList.contentY;
            Qt.callLater(function () {
                findingsList.contentY = saved;
            });
        } else {
            Qt.callLater(function () {
                findingsList.contentY = 0;
            });
        }
    }

    HoverHandler {
        id: listHover
        onHoveredChanged: root.holdUpdatesChanged(hovered)
    }

    GroupHeaderBar {
        id: groupBar

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: visible ? Kirigami.Units.gridUnit * 2.1 : 0
        visible: root.groupBy !== "none"
        groupBy: root.groupBy
        groupsExpanded: root.groupsExpanded
        groupSortKey: root.groupSortKey
        groupSortDescending: root.groupSortDescending
        theme: root.theme
        labels: root.labels
        onToggleGroupsExpandedRequested: root.toggleGroupsExpandedRequested()
        onGroupSortRequested: (key) => root.groupSortRequested(key)
    }

    RowLayout {
        id: listHeader

        anchors.top: groupBar.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: Math.max(Kirigami.Units.gridUnit * 1.3,
            Kirigami.Theme.smallFont.pointSize + Kirigami.Units.smallSpacing * 2)
        spacing: Kirigami.Units.smallSpacing

        Item {
            Layout.preferredWidth: Kirigami.Units.smallSpacing + 3
        }

        Repeater {
            model: root.headerColumns

            delegate: Item {
                required property var modelData

                Layout.preferredWidth: modelData.fill ? 0 : modelData.width
                Layout.minimumWidth: modelData.fill ? 0 : modelData.width
                Layout.fillWidth: modelData.fill
                implicitHeight: headerTitle.implicitHeight

                PlasmaComponents3.Label {
                    id: headerTitle

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    horizontalAlignment: modelData.align === "center"
                        ? Text.AlignHCenter : Text.AlignLeft
                    text: root.headerText(modelData.key)
                    color: root.sortKey === modelData.key
                        ? Kirigami.Theme.textColor
                        : (root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor)
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(6,
                        Kirigami.Theme.smallFont.pointSize - 1)
                    font.bold: root.sortKey === modelData.key
                    elide: Text.ElideRight
                }

                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.sortRequested(modelData.key)

                    QQC2.ToolTip.text: root.headerTooltip(modelData.key)
                    QQC2.ToolTip.visible: containsMouse
                }
            }
        }

        Item {
            Layout.preferredWidth: findingsList.rightMargin
        }
    }

    Rectangle {
        id: listHeaderRule

        anchors.top: listHeader.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 1
        color: root.theme ? root.theme.hairline : "transparent"
    }

    Component {
        id: groupComponent

        GroupHeader {
            theme: root.theme
            labels: root.labels
            onToggleRequested: (key) => root.groupToggleRequested(key)
        }
    }

    Component {
        id: findingComponent

        FindingRow {
            theme: root.theme
            labels: root.labels
            systemChannel: root.systemChannel
            cveWidth: root.cveColumnWidth
            fixPillWidth: root.fixPillWidth
            triageWidth: root.triageColumnWidth

            onOpenFinding: (url) => root.openFinding(url)
            onFilterPackageRequested: (name) => root.filterPackageRequested(name)
            onFilterOriginRequested: (name) => root.filterOriginRequested(name)
            onOpenFixRequested: (url) => root.openFixRequested(url)
            onTrackerRequested: (finding) => root.trackerRequested(finding)
            onCopyRequested: (text) => root.copyRequested(text)
            onOpenMasterSourceRequested: (url) => root.openMasterSourceRequested(url)
            onNixpkgsSearchRequested: (name) => root.nixpkgsSearchRequested(name)
            onIgnoreRequested: (finding) => root.ignoreRequested(finding)
        }
    }

    ListView {
        id: findingsList
        objectName: "findingsListView"
        Accessible.role: Accessible.List
        Accessible.name: root.labels ? root.labels.appTitle() : "Sentinel"

        anchors.top: listHeaderRule.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        clip: true
        spacing: 0
        boundsBehavior: Flickable.StopAtBounds
        focus: false
        activeFocusOnTab: false
        model: root.rows
        rightMargin: scrollBar.visible
            ? scrollBar.width + Kirigami.Units.smallSpacing * 2 : 0

        QQC2.ScrollBar.vertical: PlasmaComponents3.ScrollBar {
            id: scrollBar
            policy: QQC2.ScrollBar.AlwaysOn
        }

        delegate: Loader {
            id: rowLoader

            required property var modelData

            width: ListView.view.width - ListView.view.rightMargin
            sourceComponent: modelData.rowType === "group"
                ? groupComponent : findingComponent

            onLoaded: {
                if (modelData.rowType === "group") {
                    item.groupBy = modelData.groupBy;
                    item.groupKey = modelData.key;
                    item.groupCount = modelData.count;
                    item.expanded = modelData.expanded;
                } else {
                    item.rowData = modelData;
                }
                item.width = rowLoader.width;
            }

            height: item ? item.height : 0
        }

        PlasmaComponents3.Label {
            anchors.centerIn: parent
            width: parent.width - Kirigami.Units.gridUnit * 2
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            visible: root.rows.length === 0
            text: root.labels ? root.labels.noMatchesText() : "No matches"
            opacity: 0.7
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
    }
}
