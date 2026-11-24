import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.extras as PlasmaExtras

PlasmaExtras.PlasmoidHeading {
    id: root

    property string postureLabel: ""
    property string stateSummary: ""
    property string brandIcon: "sentinel-shield"
    property color stateColor: Kirigami.Theme.disabledTextColor
    property string lastScanLabel: ""
    property string lastScanTooltip: ""
    property string detailTooltip: ""
    property bool scanning: false
    property bool trackerBusy: false
    property bool serviceActive: false
    property var progress: null
    property string trackerWarningText: ""
    property var labels: null
    property var theme: null
    property real alignedWidth: 0

    signal scanRequested()
    signal settingsRequested()

    leftPadding: 0
    rightPadding: 0

    contentItem: Item {
        id: headerContent

        implicitHeight: headerRow.implicitHeight

        RowLayout {
            id: headerRow

            anchors.horizontalCenter: parent.horizontalCenter
            anchors.verticalCenter: parent.verticalCenter
            width: root.alignedWidth > 0
                ? Math.min(root.alignedWidth, parent.width) : parent.width
            height: implicitHeight
            spacing: Kirigami.Units.smallSpacing

            Rectangle {
                Layout.preferredWidth: Kirigami.Units.gridUnit * 2
                Layout.preferredHeight: Kirigami.Units.gridUnit * 2
                radius: 10
                color: root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor

                Kirigami.Icon {
                    anchors.centerIn: parent
                    width: Math.round(parent.width * 0.55)
                    height: width
                    source: root.brandIcon
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1

                RowLayout {
                    spacing: Kirigami.Units.smallSpacing

                    PlasmaComponents3.Label {
                        text: root.labels ? root.labels.appTitle() : "Sentinel"
                        color: Kirigami.Theme.textColor
                        font.bold: true
                        font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.15)
                    }

                    Rectangle {
                        Layout.preferredWidth: headerPostureLabel.implicitWidth
                            + Kirigami.Units.smallSpacing * 2
                        Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 0.95)
                        radius: 99
                        color: Qt.rgba(root.stateColor.r, root.stateColor.g,
                            root.stateColor.b, 0.13)

                        PlasmaComponents3.Label {
                            id: headerPostureLabel

                            anchors.centerIn: parent
                            text: root.postureLabel
                            color: root.stateColor
                            font.family: Kirigami.Theme.smallFont.family
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                            font.bold: true
                        }
                    }
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: root.stateSummary
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    elide: Text.ElideRight

                    HoverHandler {
                        id: detailHover
                    }

                    QQC2.ToolTip.text: root.detailTooltip
                    QQC2.ToolTip.visible: detailHover.hovered
                        && root.detailTooltip.length > 0
                }
            }

            PlasmaComponents3.Label {
                text: root.lastScanLabel
                visible: text.length > 0
                color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize

                HoverHandler {
                    id: lastScanHover
                }

                QQC2.ToolTip.text: root.lastScanTooltip
                QQC2.ToolTip.visible: lastScanHover.hovered
                    && root.lastScanTooltip.length > 0
            }

            ScanProgress {
                id: headerProgress

                active: root.scanning || (root.trackerBusy && root.serviceActive)
                indeterminate: (root.scanning && !root.trackerBusy)
                    || (root.trackerBusy && (!root.progress || root.progress.total <= 0))
                ratio: root.progress
                    ? root.progress.done / Math.max(1, root.progress.total) : 0
                tooltipText: root.scanning
                    ? (root.labels ? root.labels.scanningForVulnerabilities() : "")
                    : (root.labels ? root.labels.trackerProgressText(root.progress) : "")
                theme: root.theme
            }

            Kirigami.Icon {
                visible: !root.scanning
                    && !(root.trackerBusy && root.serviceActive)
                    && root.trackerWarningText.length > 0
                source: "dialog-warning"
                Layout.preferredWidth: Kirigami.Units.iconSizes.small
                Layout.preferredHeight: Kirigami.Units.iconSizes.small
                color: Kirigami.Theme.neutralTextColor

                HoverHandler {
                    id: trackerWarningHover
                }

                QQC2.ToolTip.text: root.trackerWarningText
                QQC2.ToolTip.visible: trackerWarningHover.hovered
                    && root.trackerWarningText.length > 0
            }

            QQC2.Button {
                id: scanButton

                text: root.labels
                    ? root.labels.scanButtonText(root.scanning
                        || (root.trackerBusy && root.serviceActive))
                    : ""
                enabled: !root.scanning && !(root.trackerBusy && root.serviceActive)
                Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 1.65)
                leftPadding: Kirigami.Units.gridUnit * 0.7
                rightPadding: Kirigami.Units.gridUnit * 0.7
                topPadding: 0
                bottomPadding: 0
                onClicked: root.scanRequested()

                contentItem: PlasmaComponents3.Label {
                    text: scanButton.text
                    color: root.theme ? root.theme.primaryText : Kirigami.Theme.highlightedTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                background: Rectangle {
                    radius: 8
                    color: scanButton.down
                        ? Qt.darker(root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor, 1.08)
                        : (root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor)
                    opacity: scanButton.enabled ? 1 : 0.55
                }
            }

            PlasmaComponents3.ToolButton {
                icon.name: "configure"
                text: root.labels ? root.labels.settingsTooltip() : ""
                display: QQC2.AbstractButton.IconOnly
                onClicked: root.settingsRequested()

                QQC2.ToolTip.text: root.labels ? root.labels.settingsTooltip() : ""
                QQC2.ToolTip.visible: hovered
            }
        }
    }
}
