pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Rectangle {
    id: root

    property var bands: []
    property int total: 0
    property string selected: ""
    property var theme: null
    property var labels: null

    signal bandSelected(string band)

    radius: 16
    color: root.theme ? root.theme.severitySurface : "transparent"
    border.width: 1
    border.color: root.theme ? root.theme.cardBorder : "transparent"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.gridUnit * 0.4
        spacing: 4

        PlasmaComponents3.Label {
            text: root.labels ? root.labels.severityTitle() : "SEVERITY"
            color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
            font.bold: true
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
            font.letterSpacing: 0.6
        }

        Row {
            id: severityBar

            Layout.fillWidth: true
            Layout.preferredHeight: 9
            spacing: 2

            Repeater {
                model: root.bands.slice(1)

                Rectangle {
                    required property var modelData

                    width: Math.max(2, (severityBar.width - 8)
                        * modelData.count / Math.max(1, root.total))
                    height: 9
                    radius: 2
                    color: root.theme
                        ? root.theme.severityBandColor(modelData.key)
                        : "transparent"
                }
            }
        }

        GridLayout {
            Layout.fillWidth: true
            columns: 1
            columnSpacing: Kirigami.Units.smallSpacing
            rowSpacing: 2

            Repeater {
                model: root.bands.slice(1)

                Rectangle {
                    required property var modelData

                    Layout.fillWidth: true
                    Layout.preferredHeight: 16
                    radius: 4
                    activeFocusOnTab: true

                    Accessible.role: Accessible.Button
                    Accessible.name: root.labels
                        ? root.labels.severityBandLabel(modelData.key) : modelData.key
                    Accessible.onPressAction: root.bandSelected(modelData.key)

                    Keys.onReturnPressed: root.bandSelected(modelData.key)
                    Keys.onSpacePressed: root.bandSelected(modelData.key)

                    color: root.selected === modelData.key
                        ? (root.theme ? root.theme.rowHover : "transparent")
                        : "transparent"

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 3
                        anchors.rightMargin: 3
                        spacing: 4

                        Rectangle {
                            Layout.preferredWidth: 7
                            Layout.preferredHeight: 7
                            radius: 2
                            color: root.theme
                                ? root.theme.severityBandColor(modelData.key)
                                : "transparent"
                        }

                        PlasmaComponents3.Label {
                            Layout.fillWidth: true
                            text: root.labels
                                ? root.labels.severityBandLabel(modelData.key)
                                : modelData.key
                            color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                            font.family: Kirigami.Theme.smallFont.family
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                            elide: Text.ElideRight
                        }

                        PlasmaComponents3.Label {
                            text: modelData.count
                            color: Kirigami.Theme.textColor
                            font.bold: true
                            font.family: Kirigami.Theme.smallFont.family
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.bandSelected(modelData.key)
                    }
                }
            }
        }
    }
}
