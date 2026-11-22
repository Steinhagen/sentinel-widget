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

        // A split button: the left side names the current state; the chevron
        // opens the mode menu. Both halves share one accessible button.
        flat: false
        display: QQC2.AbstractButton.IconOnly
        text: root.labels ? root.labels.groupByStateLabel(root.groupBy) : "Flat"
        Accessible.name: root.labels ? root.labels.groupByButton(root.groupBy) : ""
        leftPadding: Kirigami.Units.gridUnit * 0.55
        rightPadding: Kirigami.Units.gridUnit * 0.45
        Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 1.65)
        onClicked: groupByMenu.popup(groupByButton, 0, groupByButton.height)

        contentItem: RowLayout {
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Label {
                text: root.labels
                    ? root.labels.groupByStateLabel(root.groupBy) : "Flat"
                color: Kirigami.Theme.textColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            Rectangle {
                Layout.preferredWidth: 1
                Layout.preferredHeight: Kirigami.Units.gridUnit * 0.9
                color: Kirigami.Theme.disabledTextColor
                opacity: 0.55
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
}
