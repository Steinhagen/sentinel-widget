import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Item {
    id: root

    property string groupBy: "none"
    property bool groupsExpanded: true
    property string groupSortKey: ""
    property bool groupSortDescending: false
    property var theme: null
    property var labels: null

    signal toggleGroupsExpandedRequested()
    signal groupSortRequested(string key)

    height: Kirigami.Units.gridUnit * 2.1

    function sortArrow(key) {
        if (root.groupSortKey !== key) {
            return "↕";
        }
        return root.groupSortDescending ? "↓" : "↑";
    }

    Rectangle {
        anchors.fill: parent
        anchors.topMargin: Kirigami.Units.smallSpacing
        anchors.bottomMargin: Kirigami.Units.smallSpacing
        radius: 6
        color: root.theme ? root.theme.inputBackground : "transparent"
        border.width: 1
        border.color: root.theme ? root.theme.hairline : "transparent"
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Kirigami.Units.smallSpacing * 2
        anchors.rightMargin: Kirigami.Units.smallSpacing * 2
        spacing: Kirigami.Units.smallSpacing

        PlasmaComponents3.ToolButton {
            id: expandButton

            text: root.groupsExpanded ? "−" : "+"
            display: QQC2.AbstractButton.TextOnly
            flat: false
            font.bold: true
            font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.2)
            Layout.preferredWidth: Kirigami.Units.gridUnit * 1.8
            Accessible.name: root.labels
                ? (root.groupsExpanded
                    ? root.labels.collapseAllGroups()
                    : root.labels.expandAllGroups())
                : ""
            onClicked: root.toggleGroupsExpandedRequested()

            QQC2.ToolTip.text: root.labels
                ? (root.groupsExpanded
                    ? root.labels.collapseAllGroups()
                    : root.labels.expandAllGroups())
                : ""
            QQC2.ToolTip.visible: hovered
        }

        Item {
            Layout.fillWidth: true
            implicitHeight: groupTitle.implicitHeight
            activeFocusOnTab: true
            Accessible.role: Accessible.Button
            Accessible.name: root.labels
                ? root.labels.groupColumnLabel(root.groupBy)
                : ""
            Accessible.onPressAction: root.groupSortRequested("name")
            Keys.onReturnPressed: root.groupSortRequested("name")
            Keys.onSpacePressed: root.groupSortRequested("name")

            PlasmaComponents3.Label {
                id: groupTitle

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: (root.labels
                    ? root.labels.groupColumnLabel(root.groupBy)
                    : "Group") + " " + root.sortArrow("name")
                color: root.groupSortKey === "name"
                    ? Kirigami.Theme.textColor
                    : (root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor)
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                font.bold: root.groupSortKey === "name"
                elide: Text.ElideRight
            }

            MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.groupSortRequested("name")

                QQC2.ToolTip.text: root.labels
                    ? root.labels.groupSortTooltip(root.groupBy, "name",
                        root.groupSortKey === "name", root.groupSortDescending)
                    : ""
                QQC2.ToolTip.visible: containsMouse
                    && QQC2.ToolTip.text.length > 0
            }
        }

        Item {
            Layout.preferredWidth: Kirigami.Units.gridUnit * 9
            implicitHeight: countTitle.implicitHeight
            activeFocusOnTab: true
            Accessible.role: Accessible.Button
            Accessible.name: root.labels ? root.labels.groupCountColumnLabel() : ""
            Accessible.onPressAction: root.groupSortRequested("count")
            Keys.onReturnPressed: root.groupSortRequested("count")
            Keys.onSpacePressed: root.groupSortRequested("count")

            PlasmaComponents3.Label {
                id: countTitle

                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                horizontalAlignment: Text.AlignRight
                text: (root.labels
                    ? root.labels.groupCountColumnLabel()
                    : "Findings") + " " + root.sortArrow("count")
                color: root.groupSortKey === "count"
                    ? Kirigami.Theme.textColor
                    : (root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor)
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                font.bold: root.groupSortKey === "count"
            }

            MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.groupSortRequested("count")

                QQC2.ToolTip.text: root.labels
                    ? root.labels.groupSortTooltip(root.groupBy, "count",
                        root.groupSortKey === "count", root.groupSortDescending)
                    : ""
                QQC2.ToolTip.visible: containsMouse
                    && QQC2.ToolTip.text.length > 0
            }
        }
    }
}
