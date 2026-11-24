import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

import "../domain/origins.mjs" as Origins

// One package/version chip in an origin trail. The vulnerable last step is
// outlined in the critical colour so the destination of the trail stands out.
Rectangle {
    id: root

    property string node: ""
    property bool last: false
    property var theme: null

    signal selected(string name)

    readonly property var parts: Origins.splitNode(root.node)

    implicitWidth: stepRow.implicitWidth + 12
    implicitHeight: stepRow.implicitHeight + 6
    width: implicitWidth
    height: implicitHeight
    radius: 6
    color: root.last
        ? (root.theme
            ? Qt.rgba(root.theme.criticalColor.r,
                root.theme.criticalColor.g,
                root.theme.criticalColor.b, 0.10)
            : "transparent")
        : (root.theme ? root.theme.chipBackground : "transparent")
    border.width: 1
    border.color: root.last
        ? (root.theme
            ? Qt.rgba(root.theme.criticalColor.r,
                root.theme.criticalColor.g,
                root.theme.criticalColor.b, 0.45)
            : "transparent")
        : (root.theme ? root.theme.chipBorder : "transparent")

    RowLayout {
        id: stepRow

        anchors.centerIn: parent
        spacing: 4

        PlasmaComponents3.Label {
            text: root.parts.name
            color: root.last && root.theme
                ? root.theme.criticalColor
                : (root.theme ? root.theme.textColor : Kirigami.Theme.textColor)
            font.bold: true
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
        }

        PlasmaComponents3.Label {
            visible: text.length > 0
            text: root.parts.version
            color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: root.selected(root.node)
    }
}
