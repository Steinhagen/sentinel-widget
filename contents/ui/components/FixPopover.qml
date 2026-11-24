pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Rectangle {
    id: root

    property var row: null
    property var theme: null
    property var labels: null
    property string systemChannel: ""

    signal openTrackerRequested(string url)
    signal openFixRequested(string url)

    readonly property var fix: row ? row.fix : null
    readonly property var branches: fix && fix.rows ? fix.rows : []
    readonly property string stateText: fix && labels ? labels.fixText(fix) : ""
    readonly property string subText: {
        const parts = [];
        if (root.labels) {
            const tracker = root.labels.fixTrackerPackage(root.fix);
            if (tracker.length > 0) {
                parts.push(tracker);
            }
            const channel = root.labels.fixChannel(root.systemChannel);
            if (channel.length > 0) {
                parts.push(channel);
            }
        }
        return parts.join(" · ");
    }
    readonly property color stateTone: root.theme && root.fix
        ? root.theme.fixColor(root.fix.bucket) : Kirigami.Theme.disabledTextColor
    readonly property color stateSurface: root.theme && root.fix
        ? root.theme.fixPillBackground(root.fix.bucket) : "transparent"
    readonly property color stateBorder: root.theme && root.fix
        ? root.theme.fixPillBorder(root.fix.bucket) : "transparent"
    readonly property bool hasTracker: root.row && root.row.url
    readonly property bool hasFix: root.fix && root.fix.url

    implicitWidth: Kirigami.Units.gridUnit * 18
    implicitHeight: layout.implicitHeight
    radius: 14
    color: root.theme ? root.theme.tooltipBackground : Kirigami.Theme.backgroundColor
    border.width: 1
    border.color: root.theme ? root.theme.tooltipBorder : Kirigami.Theme.disabledTextColor
    clip: true

    // Consume clicks on the card so they cannot reach the list behind it.
    MouseArea {
        anchors.fill: parent
        onClicked: {}
    }

    ColumnLayout {
        id: layout

        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.gridUnit * 0.55
            spacing: 4

            PlasmaComponents3.Label {
                text: root.labels ? root.labels.fixPopoverTitle() : "Fix"
                color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize - 1)
                font.letterSpacing: 0.8
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: root.row ? (root.row.package || "—") : "—"
                    color: root.theme ? root.theme.textColor : Kirigami.Theme.textColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize + 2
                    font.bold: true
                    elide: Text.ElideRight
                }

                PlasmaComponents3.Label {
                    visible: text.length > 0
                    text: root.row ? (root.row.version || "") : ""
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

                Rectangle {
                    visible: root.stateText.length > 0
                    Layout.preferredHeight: stateLabel.implicitHeight + 4
                    Layout.preferredWidth: stateLabel.implicitWidth + 14
                    radius: 99
                    color: root.stateSurface
                    border.width: 1
                    border.color: root.stateBorder

                    PlasmaComponents3.Label {
                        id: stateLabel

                        anchors.centerIn: parent
                        text: root.stateText
                        color: root.stateTone
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        font.bold: true
                    }
                }
            }

            PlasmaComponents3.Label {
                Layout.fillWidth: true
                visible: text.length > 0
                text: root.subText
                color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                elide: Text.ElideRight
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: root.theme ? root.theme.hairline : "transparent"
            visible: root.branches.length > 0
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.gridUnit * 0.55
            spacing: 1
            visible: root.branches.length > 0

            RowLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                PlasmaComponents3.Label {
                    text: root.labels ? root.labels.fixBranchesTitle() : "Nixpkgs branches"
                    color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize - 1)
                    font.letterSpacing: 0.6
                }

                Item {
                    Layout.fillWidth: true
                }

                PlasmaComponents3.Label {
                    text: root.labels
                        ? root.labels.fixBranchCount(root.branches.length) : ""
                    color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize - 1)
                }
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: 6
                rowSpacing: 1

                Repeater {
                    model: root.branches

                    delegate: Rectangle {
                        id: branchRow

                        required property var modelData

                        readonly property bool current: modelData.name === root.systemChannel

                        Layout.fillWidth: true
                        Layout.preferredHeight: 22
                        radius: 5
                        color: current && root.theme
                            ? Qt.rgba(root.theme.primaryColor.r, root.theme.primaryColor.g,
                                root.theme.primaryColor.b, 0.10)
                            : "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 4
                            anchors.rightMargin: 4
                            spacing: 4

                            PlasmaComponents3.Label {
                                Layout.preferredWidth: 12
                                horizontalAlignment: Text.AlignHCenter
                                text: modelData.state === "unaffected" ? "✓"
                                    : (modelData.state === "affected" ? "✗" : "?")
                                color: modelData.state === "unaffected"
                                    ? (root.theme ? root.theme.fixColor("fixed")
                                        : Kirigami.Theme.positiveTextColor)
                                    : (modelData.state === "affected"
                                        ? (root.theme ? root.theme.fixColor("none")
                                            : Kirigami.Theme.negativeTextColor)
                                        : (root.theme ? root.theme.faintText
                                            : Kirigami.Theme.disabledTextColor))
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                font.bold: true
                            }

                            PlasmaComponents3.Label {
                                Layout.fillWidth: true
                                text: modelData.name
                                color: current
                                    ? (root.theme ? root.theme.textColor : Kirigami.Theme.textColor)
                                    : (root.theme ? root.theme.mutedText
                                        : Kirigami.Theme.disabledTextColor)
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                font.bold: current
                                elide: Text.ElideRight
                            }

                            PlasmaComponents3.Label {
                                text: modelData.version || ""
                                color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                            }

                            PlasmaComponents3.Label {
                                visible: branchRow.current
                                text: "←"
                                color: root.theme ? root.theme.textColor : Kirigami.Theme.textColor
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                            }
                        }
                    }
                }
            }

            PlasmaComponents3.Label {
                Layout.fillWidth: true
                Layout.topMargin: 5
                visible: text.length > 0
                text: root.labels ? root.labels.fixSummary(root.fix) : ""
                color: root.stateTone
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                elide: Text.ElideRight
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: root.theme ? root.theme.hairline : "transparent"
            visible: root.hasTracker || root.hasFix
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.gridUnit * 0.5
            spacing: Kirigami.Units.gridUnit * 0.6

            PlasmaComponents3.Label {
                visible: root.hasTracker
                text: (root.labels ? root.labels.fixOpenTracker() : "Open tracker") + " ↗"
                color: root.theme ? root.theme.highColor : Kirigami.Theme.linkColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.openTrackerRequested(root.row.url)
                }
            }

            PlasmaComponents3.Label {
                visible: root.hasFix
                text: (root.labels ? root.labels.fixOpenFix() : "Open fix") + " ↗"
                color: root.theme ? root.theme.highColor : Kirigami.Theme.linkColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.openFixRequested(root.fix.url)
                }
            }

            Item {
                Layout.fillWidth: true
            }
        }
    }
}
