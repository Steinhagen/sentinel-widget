import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

Item {
    id: root

    property bool active: false
    property bool indeterminate: false
    property real ratio: 0
    property string tooltipText: ""
    property var theme: null

    clip: true
    visible: root.active
    Layout.preferredWidth: Kirigami.Units.gridUnit * 4
    Layout.minimumWidth: Kirigami.Units.gridUnit * 4
    Layout.maximumWidth: Kirigami.Units.gridUnit * 4
    Layout.preferredHeight: Math.max(5, Math.round(Kirigami.Units.gridUnit * 0.4))

    property real sweepX: -width * 0.3

    Rectangle {
        anchors.fill: parent
        radius: height / 2
        color: root.theme ? root.theme.hairline : "transparent"
    }

    Rectangle {
        x: root.indeterminate ? root.sweepX : 0
        width: root.indeterminate
            ? Math.max(12, root.width * 0.3)
            : Math.max(2, root.width * Math.min(1, Math.max(0, root.ratio)))
        height: parent.height
        radius: height / 2
        color: root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor
    }

    NumberAnimation on sweepX {
        running: root.indeterminate
        loops: Animation.Infinite
        from: -root.width * 0.3
        to: root.width
        duration: 1400
        easing.type: Easing.InOutSine
    }

    HoverHandler {
        id: progressHover
    }

    QQC2.ToolTip.text: root.tooltipText
    QQC2.ToolTip.visible: progressHover.hovered && root.tooltipText.length > 0
}
