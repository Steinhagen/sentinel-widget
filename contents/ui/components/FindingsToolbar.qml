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
    property string groupBy: "none"
    property bool cardsVisible: false
    property var labels: null

    signal searchChanged(string text)
    signal severitySelected(string band)
    signal fixStateSelected(string band)
    signal clearFiltersRequested()
    signal groupBySelected(string groupBy)

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

        visible: !root.cardsVisible
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
