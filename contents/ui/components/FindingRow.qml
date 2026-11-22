pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

PlasmaComponents3.ItemDelegate {
    id: root

    property var rowData: null
    property var theme: null
    property var labels: null
    property string systemChannel: ""
    property real fixPillWidth: Kirigami.Units.gridUnit * 4
    signal openFinding(string url)
    signal filterPackageRequested(string packageName)
    signal filterOriginRequested(string originName)
    signal openFixRequested(string url)
    signal trackerRequested(var finding)
    signal copyRequested(string text)
    signal openMasterSourceRequested(string url)
    signal nixpkgsSearchRequested(string packageName)

    readonly property var fix: root.rowData ? root.rowData.fix : null
    readonly property string fixText: root.rowData && root.labels
        ? root.labels.fixText(root.rowData.fix) : ""
    readonly property string originChain: root.rowData && root.rowData.origin
        ? root.rowData.origin.chainText : ""
    readonly property string originPrimary: root.rowData && root.rowData.origin
        ? root.rowData.origin.primary : ""
    readonly property string fixUrl: root.fix ? root.fix.url : ""

    width: parent ? parent.width : implicitWidth
    height: Math.max(contentItem.implicitHeight + topPadding + bottomPadding,
        Kirigami.Units.gridUnit * 2.4)
    leftPadding: Kirigami.Units.smallSpacing + 3
    rightPadding: Kirigami.Units.smallSpacing
    topPadding: Kirigami.Units.smallSpacing
    bottomPadding: Kirigami.Units.smallSpacing
    hoverEnabled: true
    activeFocusOnTab: true

    Keys.onReturnPressed: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    Keys.onSpacePressed: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    Keys.onMenuPressed: rowMenu.popup()

    onClicked: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    background: Rectangle {
        color: root.hovered && root.theme ? root.theme.rowHover : "transparent"

        Rectangle {
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            width: 3
            color: root.theme && root.rowData
                ? root.theme.severityColor(root.rowData.severityValue)
                : "transparent"
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 1
            color: root.theme ? root.theme.hairline : "transparent"
        }
    }

    Accessible.name: root.rowData && root.labels
        ? root.labels.rowAccessibleName(root.rowData.id, root.rowData.package, root.rowData.severityText)
        : ""
    Accessible.description: root.originChain

    contentItem: ColumnLayout {
        spacing: 1

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Label {
                Layout.preferredWidth: Kirigami.Units.gridUnit * 2
                Layout.minimumWidth: Kirigami.Units.gridUnit * 2
                Layout.maximumWidth: Kirigami.Units.gridUnit * 2
                horizontalAlignment: Text.AlignHCenter
                text: root.rowData ? root.rowData.severityText : "—"
                color: root.theme && root.rowData
                    ? root.theme.severityColor(root.rowData.severityValue)
                    : Kirigami.Theme.textColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                font.bold: root.rowData ? root.rowData.severityBold : false
            }

            PlasmaComponents3.Label {
                id: cveLabel

                Layout.preferredWidth: Kirigami.Units.gridUnit * 8.5
                Layout.minimumWidth: Kirigami.Units.gridUnit * 8.5
                Layout.maximumWidth: Kirigami.Units.gridUnit * 8.5
                text: root.rowData ? (root.rowData.id || "—") : "—"
                color: root.rowData && root.rowData.url
                    ? Kirigami.Theme.linkColor : Kirigami.Theme.textColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                font.underline: cveHover.hovered && root.rowData && !!root.rowData.url
                elide: Text.ElideRight

                HoverHandler {
                    id: cveHover
                    cursorShape: root.rowData && root.rowData.url
                        ? Qt.PointingHandCursor : Qt.ArrowCursor
                }

                QQC2.ToolTip.text: root.labels && root.rowData
                    ? root.labels.cveTooltip(root.rowData.id, !!(root.rowData.url))
                    : ""
                QQC2.ToolTip.visible: cveHover.hovered
                    && QQC2.ToolTip.text.length > 0
            }

            Item {
                Layout.fillWidth: true
                implicitHeight: packageRow.implicitHeight

                RowLayout {
                    id: packageRow

                    anchors.fill: parent
                    spacing: Kirigami.Units.smallSpacing

                    PlasmaComponents3.Label {
                        text: root.rowData ? (root.rowData.package || "—") : "—"
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        font.bold: true
                        elide: Text.ElideRight
                    }

                    PlasmaComponents3.Label {
                        text: root.rowData ? (root.rowData.version || "") : ""
                        visible: text.length > 0
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        elide: Text.ElideRight
                    }

                    Item {
                        Layout.fillWidth: true
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        if (root.rowData && root.rowData.package) {
                            root.filterPackageRequested(root.rowData.package);
                        }
                    }

                    QQC2.ToolTip.text: root.labels && root.rowData
                        ? root.labels.filterPackageTooltip(root.rowData.package)
                        : ""
                    QQC2.ToolTip.visible: containsMouse
                        && QQC2.ToolTip.text.length > 0
                }
            }

            Rectangle {
                id: fixPill

                readonly property color tone: root.theme && root.fix
                    ? root.theme.fixColor(root.fix.bucket)
                    : Kirigami.Theme.disabledTextColor

                visible: root.fixText.length > 0
                Layout.preferredHeight: fixPillLabel.implicitHeight
                    + Kirigami.Units.smallSpacing
                Layout.preferredWidth: root.fixPillWidth
                Layout.minimumWidth: root.fixPillWidth
                Layout.maximumWidth: root.fixPillWidth
                radius: 99
                color: root.theme && root.fix
                    ? root.theme.fixPillBackground(root.fix.bucket)
                    : "transparent"
                border.width: 1
                border.color: root.theme && root.fix
                    ? root.theme.fixPillBorder(root.fix.bucket)
                    : "transparent"

                PlasmaComponents3.Label {
                    id: fixPillLabel

                    anchors.centerIn: parent
                    text: root.fixText
                    color: fixPill.tone
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: root.fixUrl ? Qt.PointingHandCursor : Qt.ArrowCursor
                    onClicked: {
                        if (root.fixUrl) {
                            root.openFixRequested(root.fixUrl);
                        }
                    }

                    QQC2.ToolTip.text: root.labels && root.rowData
                        ? root.labels.fixTooltip(root.rowData, root.systemChannel)
                        : ""
                    QQC2.ToolTip.visible: containsMouse
                        && QQC2.ToolTip.text.length > 0
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: Kirigami.Units.gridUnit * 2
                + Kirigami.Units.smallSpacing
            spacing: Kirigami.Units.smallSpacing
            visible: root.originChain.length > 0

            PlasmaComponents3.Label {
                text: "↳"
                color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Item {
                Layout.fillWidth: true
                implicitHeight: chainLabel.implicitHeight

                PlasmaComponents3.Label {
                    id: chainLabel

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.originChain
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    elide: Text.ElideRight
                }

                HoverHandler {
                    id: chainHover
                    cursorShape: Qt.PointingHandCursor
                }

                QQC2.ToolTip.text: root.labels && root.rowData
                    ? root.labels.originTooltip(root.rowData.origin)
                    : ""
                QQC2.ToolTip.visible: chainHover.hovered
                    && QQC2.ToolTip.text.length > 0

                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (root.originPrimary) {
                            root.filterOriginRequested(root.originPrimary);
                        }
                    }
                }
            }
        }
    }

    TapHandler {
        acceptedButtons: Qt.RightButton
        onTapped: rowMenu.popup()
    }

    RowContextMenu {
        id: rowMenu
        rowData: root.rowData
        labels: root.labels

        onFilterPackageRequested: (packageName) => root.filterPackageRequested(packageName)
        onFilterOriginRequested: (originName) => root.filterOriginRequested(originName)
        onTrackerRequested: (finding) => root.trackerRequested(finding)
        onOpenFixRequested: (url) => root.openFixRequested(url)
        onOpenMasterSourceRequested: (url) => root.openMasterSourceRequested(url)
        onCopyRequested: (text) => root.copyRequested(text)
        onNixpkgsSearchRequested: (packageName) => root.nixpkgsSearchRequested(packageName)
    }
}
