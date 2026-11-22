import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Item {
    id: root

    property string groupBy: "origin"
    property string groupKey: ""
    property int groupCount: 0
    property bool expanded: true
    property var theme
    property var labels

    signal toggleRequested(string groupKey)

    width: parent ? parent.width : implicitWidth
    height: Math.max(Kirigami.Units.gridUnit * 2.2,
        sectionHeader.implicitHeight + Kirigami.Units.smallSpacing * 3)

    Rectangle {
        anchors.fill: parent
        anchors.topMargin: Kirigami.Units.smallSpacing
        anchors.bottomMargin: Kirigami.Units.smallSpacing
        radius: 8
        color: headerMouse.containsMouse && root.theme
            ? root.theme.rowHover
            : (root.theme ? root.theme.inputBackground : "transparent")
        border.width: headerMouse.containsMouse ? 1 : 0
        border.color: root.theme ? root.theme.hairline : "transparent"
    }

    RowLayout {
        id: sectionHeader

        anchors.fill: parent
        anchors.leftMargin: Kirigami.Units.smallSpacing * 2
        anchors.rightMargin: Kirigami.Units.smallSpacing * 2
        anchors.topMargin: Kirigami.Units.smallSpacing
        anchors.bottomMargin: Kirigami.Units.smallSpacing
        spacing: Kirigami.Units.smallSpacing

        PlasmaComponents3.Label {
            text: root.expanded ? "▾" : "▸"
            color: root.theme ? root.theme.primaryColor : Kirigami.Theme.textColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Math.round(Kirigami.Theme.smallFont.pointSize * 1.15)
        }

        PlasmaComponents3.Label {
            Layout.fillWidth: true
            text: root.labels ? root.labels.groupTitle(root.groupBy, root.groupKey) : root.groupKey
            color: Kirigami.Theme.textColor
            font.bold: true
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
            elide: Text.ElideRight
        }

        PlasmaComponents3.Label {
            text: root.labels ? root.labels.groupCountText(root.groupCount) : root.groupCount
            color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
    }

    MouseArea {
        id: headerMouse

        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.toggleRequested(root.groupKey)

        QQC2.ToolTip.text: root.labels
            ? root.labels.groupToggleTooltip(root.expanded)
            : ""
        QQC2.ToolTip.visible: containsMouse
            && QQC2.ToolTip.text.length > 0
    }

    activeFocusOnTab: true
    Accessible.role: Accessible.Button
    Accessible.name: root.labels
        ? root.labels.groupTitle(root.groupBy, root.groupKey)
            + ", " + root.labels.groupCountText(root.groupCount)
        : root.groupKey
    Accessible.onPressAction: root.toggleRequested(root.groupKey)
    Keys.onReturnPressed: root.toggleRequested(root.groupKey)
    Keys.onSpacePressed: root.toggleRequested(root.groupKey)
}
