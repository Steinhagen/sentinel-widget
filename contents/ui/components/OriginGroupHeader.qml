import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Item {
    id: root

    property string groupName: ""
    property int groupCount: 0
    property var theme
    property var labels

    width: parent ? parent.width : implicitWidth
    height: sectionHeader.implicitHeight + Kirigami.Units.smallSpacing * 2

    Rectangle {
        anchors.fill: parent
        anchors.topMargin: Kirigami.Units.smallSpacing
        radius: 6
        color: root.theme ? root.theme.inputBackground : "transparent"
    }

    RowLayout {
        id: sectionHeader

        anchors.fill: parent
        anchors.leftMargin: Kirigami.Units.smallSpacing * 2
        anchors.rightMargin: Kirigami.Units.smallSpacing * 2
        spacing: Kirigami.Units.smallSpacing

        PlasmaComponents3.Label {
            text: "◈"
            color: root.theme ? root.theme.primaryColor : Kirigami.Theme.textColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }

        PlasmaComponents3.Label {
            Layout.fillWidth: true
            text: root.labels ? root.labels.groupLabel(root.groupName) : root.groupName
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
}
