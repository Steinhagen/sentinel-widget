pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

Flow {
    id: root

    property string searchText: ""
    property string excludeText: ""
    property string severityBand: ""
    property string fixState: ""
    property string packageFilter: ""
    property string originFilter: ""
    property string cveFilter: ""
    property var labels: null
    property var theme: null

    signal removeFilter(string key)
    signal clearAllRequested()

    readonly property var items: {
        const result = [];
        if (root.searchText.length > 0) {
            result.push({ key: "text", label: root.filterLabel("text", root.searchText) });
        }
        if (root.excludeText.length > 0) {
            result.push({ key: "exclude", label: root.filterLabel("exclude", root.excludeText) });
        }
        if (root.cveFilter.length > 0) {
            result.push({ key: "cve", label: root.filterLabel("cve", root.cveFilter) });
        }
        if (root.packageFilter.length > 0) {
            result.push({ key: "package", label: root.filterLabel("package", root.packageFilter) });
        }
        if (root.originFilter.length > 0) {
            result.push({ key: "origin", label: root.filterLabel("origin", root.originFilter) });
        }
        if (root.severityBand.length > 0) {
            result.push({ key: "severity", label: root.filterLabel("severity", root.severityBand) });
        }
        if (root.fixState.length > 0) {
            result.push({ key: "fixState", label: root.filterLabel("fixState", root.fixState) });
        }
        return result;
    }

    function filterLabel(key, value) {
        if (root.labels && root.labels.filterChipText) {
            return root.labels.filterChipText(key, value);
        }
        return key + ": " + value;
    }

    function removeTooltip(key) {
        if (root.labels && root.labels.removeFilterTooltip) {
            return root.labels.removeFilterTooltip(key);
        }
        return "";
    }

    Layout.fillWidth: true
    visible: root.items.length > 0
    spacing: Kirigami.Units.smallSpacing * 0.75

    Repeater {
        model: root.items

        delegate: Rectangle {
            required property var modelData

            height: Math.round(Kirigami.Units.gridUnit * 1.35)
            width: chipRow.implicitWidth + Kirigami.Units.smallSpacing * 2
            radius: height / 2
            color: root.theme ? root.theme.inputBackground : "transparent"
            border.width: 1
            border.color: root.theme ? root.theme.cardBorder : "transparent"

            RowLayout {
                id: chipRow

                anchors.fill: parent
                anchors.leftMargin: Kirigami.Units.smallSpacing
                anchors.rightMargin: 0
                spacing: 1

                PlasmaComponents3.Label {
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 26
                    text: modelData.label
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.textColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                    elide: Text.ElideRight
                }

                PlasmaComponents3.ToolButton {
                    text: "×"
                    display: QQC2.AbstractButton.TextOnly
                    flat: true
                    Layout.preferredWidth: Math.round(Kirigami.Units.gridUnit * 0.95)
                    Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 1.1)
                    Accessible.name: root.removeTooltip(modelData.key)
                    onClicked: root.removeFilter(modelData.key)

                    QQC2.ToolTip.text: root.removeTooltip(modelData.key)
                    QQC2.ToolTip.visible: hovered
                }
            }
        }
    }

    PlasmaComponents3.ToolButton {
        text: root.labels ? root.labels.clearFiltersText() : "Clear all"
        display: QQC2.AbstractButton.TextOnly
        flat: true
        height: Math.round(Kirigami.Units.gridUnit * 1.35)
        onClicked: root.clearAllRequested()

        QQC2.ToolTip.text: root.labels
            ? root.labels.clearFiltersTooltip() : ""
        QQC2.ToolTip.visible: hovered
    }
}
