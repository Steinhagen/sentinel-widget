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
    property bool anyFilterActive: false
    property int visibleCount: 0
    property int totalCount: 0
    property bool groupByOrigin: false
    property var labels: null

    signal searchChanged(string text)
    signal severitySelected(string band)
    signal fixStateSelected(string band)
    signal clearFiltersRequested()
    signal groupToggled()

    Layout.fillWidth: false
    spacing: Kirigami.Units.smallSpacing

    Kirigami.SearchField {
        id: searchField

        Layout.fillWidth: true
        Layout.minimumWidth: Kirigami.Units.gridUnit * 7
        placeholderText: root.labels ? root.labels.searchPlaceholder() : "Search…"

        Binding on text {
            value: root.searchText
            when: !searchField.activeFocus
            restoreMode: Binding.RestoreNone
        }

        onTextChanged: {
            if (text !== root.searchText) {
                root.searchChanged(text);
            }
        }

        onAccepted: searchField.focus = false
    }

    PlasmaComponents3.ToolButton {
        id: filtersButton

        text: root.labels ? root.labels.filtersButton() : "Filters"
        icon.name: "view-filter"
        display: QQC2.AbstractButton.TextBesideIcon
        onClicked: filtersMenu.popup(filtersButton, 0, filtersButton.height)

        QQC2.ToolTip.text: root.labels ? root.labels.filtersTooltip() : ""
        QQC2.ToolTip.visible: hovered
    }

    QQC2.Menu {
        id: filtersMenu

        QQC2.MenuItem {
            text: root.labels ? root.labels.allSeverities() : ""
            checkable: true
            checked: root.severityBand === ""
            onTriggered: root.severitySelected("")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.severityBandLabel("critical") : ""
            checkable: true
            checked: root.severityBand === "critical"
            onTriggered: root.severitySelected("critical")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.severityBandLabel("high") : ""
            checkable: true
            checked: root.severityBand === "high"
            onTriggered: root.severitySelected("high")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.severityBandLabel("medium") : ""
            checkable: true
            checked: root.severityBand === "medium"
            onTriggered: root.severitySelected("medium")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.severityBandLabel("low") : ""
            checkable: true
            checked: root.severityBand === "low"
            onTriggered: root.severitySelected("low")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.unknownSeverity() : ""
            checkable: true
            checked: root.severityBand === "unknown"
            onTriggered: root.severitySelected("unknown")
        }

        QQC2.MenuSeparator {}

        QQC2.MenuItem {
            text: root.labels ? root.labels.allFixStates() : ""
            checkable: true
            checked: root.fixState === ""
            onTriggered: root.fixStateSelected("")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.fixFilterLabel("fixed") : ""
            checkable: true
            checked: root.fixState === "fixed"
            onTriggered: root.fixStateSelected("fixed")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.fixFilterLabel("progress") : ""
            checkable: true
            checked: root.fixState === "progress"
            onTriggered: root.fixStateSelected("progress")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.fixFilterLabel("none") : ""
            checkable: true
            checked: root.fixState === "none"
            onTriggered: root.fixStateSelected("none")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.fixFilterLabel("unknown") : ""
            checkable: true
            checked: root.fixState === "unknown"
            onTriggered: root.fixStateSelected("unknown")
        }
        QQC2.MenuItem {
            text: root.labels ? root.labels.fixFilterLabel("n/a") : ""
            checkable: true
            checked: root.fixState === "n/a"
            onTriggered: root.fixStateSelected("n/a")
        }

        QQC2.MenuSeparator {}

        QQC2.MenuItem {
            text: root.labels ? root.labels.clearFiltersText() : ""
            icon.name: "edit-clear-all"
            enabled: root.anyFilterActive
            onTriggered: root.clearFiltersRequested()
        }
    }

    PlasmaComponents3.ToolButton {
        id: groupByButton

        icon.name: root.groupByOrigin ? "view-list-tree" : "view-list-details"
        text: root.labels ? root.labels.groupByText(root.groupByOrigin) : ""
        display: QQC2.AbstractButton.IconOnly
        onClicked: root.groupToggled()

        QQC2.ToolTip.text: root.labels ? root.labels.groupByTooltip(root.groupByOrigin) : ""
        QQC2.ToolTip.visible: hovered
    }

    PlasmaComponents3.ToolButton {
        icon.name: "edit-clear-all"
        text: root.labels ? root.labels.clearFiltersText() : ""
        display: QQC2.AbstractButton.IconOnly
        visible: root.anyFilterActive
        onClicked: root.clearFiltersRequested()

        QQC2.ToolTip.text: root.labels ? root.labels.clearFiltersTooltip() : ""
        QQC2.ToolTip.visible: hovered
    }

    PlasmaComponents3.Label {
        text: root.labels ? root.labels.countLabel(root.visibleCount, root.totalCount) : ""
        opacity: 0.7
        font.family: Kirigami.Theme.smallFont.family
        font.pointSize: Kirigami.Theme.smallFont.pointSize
    }
}
