import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

RowLayout {
    id: root

    property string searchText: ""
    property string severityBand: ""
    property string fixState: ""
    property string cveFilter: ""
    property string packageFilter: ""
    property string originFilter: ""
    property int visibleCount: 0
    property int totalCount: 0
    property int hiddenCount: 0
    property string groupBy: "none"
    property bool cardsVisible: false
    property var labels: null

    signal searchChanged(string text)
    signal filtersApplied(string cve, string packageName, string origin,
        string severity, string fixState)
    signal clearFiltersRequested()
    signal groupBySelected(string groupBy)

    onSearchTextChanged: {
        if (searchField.text !== searchText && !searchField.activeFocus) {
            searchField.text = searchText;
        }
    }

    Layout.fillWidth: false
    spacing: Kirigami.Units.smallSpacing

    Kirigami.SearchField {
        id: searchField
        objectName: "searchField"

        Layout.fillWidth: true
        Layout.minimumWidth: Kirigami.Units.gridUnit * 7
        placeholderText: root.labels ? root.labels.searchPlaceholder() : "Search…"
        // Filtering is live via onTextChanged; do not let SearchField's
        // autoAccept timer emit accepted() and blur the field after a pause.
        autoAccept: false

        Component.onCompleted: searchField.text = root.searchText

        onTextChanged: {
            if (text !== root.searchText) {
                root.searchChanged(text);
            }
        }
    }

    PlasmaComponents3.ToolButton {
        id: filtersButton

        text: root.labels ? root.labels.filtersButton() : "Filter"
        icon.name: "view-filter"
        display: QQC2.AbstractButton.TextBesideIcon
        onClicked: filterPopup.open()

        QQC2.ToolTip.text: root.labels ? root.labels.filtersTooltip() : ""
        QQC2.ToolTip.visible: hovered
    }

    FilterPopup {
        id: filterPopup

        parent: root
        x: Math.max(0, filtersButton.x + filtersButton.width - width)
        y: filtersButton.y + filtersButton.height + Kirigami.Units.smallSpacing
        cveFilter: root.cveFilter
        packageFilter: root.packageFilter
        originFilter: root.originFilter
        severityBand: root.severityBand
        fixState: root.fixState
        showCommon: !root.cardsVisible
        labels: root.labels
        onFiltersApplied: (cve, packageName, origin, severity, fix) =>
            root.filtersApplied(cve, packageName, origin, severity, fix)
        onClearAllRequested: root.clearFiltersRequested()
    }

    PlasmaComponents3.ToolButton {
        id: groupByButton

        // Toolbar-style menu button: the mode label names the current state
        // and the chevron indicates that it opens a menu.
        flat: true
        display: QQC2.AbstractButton.IconOnly
        text: root.labels ? root.labels.groupByStateLabel(root.groupBy) : "Flat"
        Accessible.name: root.labels ? root.labels.groupByButton(root.groupBy) : ""
        Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 1.65)
        onClicked: groupByMenu.popup(groupByButton, 0, groupByButton.height)

        contentItem: RowLayout {
            spacing: Kirigami.Units.smallSpacing

            Kirigami.Icon {
                Layout.preferredWidth: Kirigami.Units.iconSizes.small
                Layout.preferredHeight: Kirigami.Units.iconSizes.small
                source: root.groupBy === "none" ? "view-list-details" : "view-list-tree"
            }

            PlasmaComponents3.Label {
                text: root.labels
                    ? root.labels.groupByStateLabel(root.groupBy) : "Flat"
                color: Kirigami.Theme.textColor
                font.family: Kirigami.Theme.defaultFont.family
                font.pointSize: Kirigami.Theme.defaultFont.pointSize
            }

            PlasmaComponents3.Label {
                text: "▾"
                color: Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
            }
        }

        QQC2.ToolTip.text: root.labels ? root.labels.groupByTooltip(root.groupBy) : ""
        QQC2.ToolTip.visible: hovered
    }

    QQC2.Menu {
        id: groupByMenu

        QQC2.MenuItem {
            text: root.labels ? root.labels.groupNone() : ""
            checkable: true
            checked: root.groupBy === "none"
            onTriggered: root.groupBySelected("none")
        }

        QQC2.MenuSeparator {}

        QQC2.MenuItem {
            text: root.labels ? root.labels.groupPriority() : ""
            checkable: true
            checked: root.groupBy === "priority"
            onTriggered: root.groupBySelected("priority")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.groupPackage() : ""
            checkable: true
            checked: root.groupBy === "package"
            onTriggered: root.groupBySelected("package")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.groupOrigin() : ""
            checkable: true
            checked: root.groupBy === "origin"
            onTriggered: root.groupBySelected("origin")
        }
    }

    PlasmaComponents3.Label {
        text: root.labels ? root.labels.countLabel(root.visibleCount, root.totalCount) : ""
        opacity: 0.7
        font.family: Kirigami.Theme.smallFont.family
        font.pointSize: Kirigami.Theme.smallFont.pointSize
    }

    PlasmaComponents3.Label {
        visible: root.hiddenCount > 0
        text: root.labels ? root.labels.triageHiddenLabel(root.hiddenCount) : ""
        opacity: 0.7
        font.family: Kirigami.Theme.smallFont.family
        font.pointSize: Kirigami.Theme.smallFont.pointSize

        QQC2.ToolTip.text: root.labels ? root.labels.triageHiddenTooltip() : ""
        QQC2.ToolTip.visible: hiddenCountArea.containsMouse

        MouseArea {
            id: hiddenCountArea
            anchors.fill: parent
            hoverEnabled: true
            acceptedButtons: Qt.NoButton
        }
    }
}
