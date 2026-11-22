import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

RowLayout {
    id: root

    property real maxSeverity: 0
    property int findings: 0
    property int affectedPackages: 0
    property int trackedCves: 0
    property var severityBands: []
    property var fixBands: []
    property int fixTotal: 0
    property string selectedSeverity: ""
    property string selectedFixState: ""
    property var theme: null
    property var labels: null

    signal severitySelected(string band)
    signal fixStateSelected(string band)

    Layout.fillWidth: false
    Layout.preferredWidth: Kirigami.Units.gridUnit * (15.5 + 9.0 + 9.0)
        + Kirigami.Units.gridUnit * 0.55 * 2
    Layout.preferredHeight: Kirigami.Units.gridUnit * 8.2
    Layout.maximumHeight: Kirigami.Units.gridUnit * 8.2
    spacing: Kirigami.Units.gridUnit * 0.55

    RiskCard {
        Layout.fillWidth: false
        Layout.fillHeight: true
        Layout.preferredWidth: Kirigami.Units.gridUnit * 15.5
        maxSeverity: root.maxSeverity
        findings: root.findings
        affectedPackages: root.affectedPackages
        trackedCves: root.trackedCves
        theme: root.theme
        labels: root.labels
    }

    SeverityCard {
        Layout.fillWidth: false
        Layout.fillHeight: true
        Layout.preferredWidth: Kirigami.Units.gridUnit * 9.0
        bands: root.severityBands
        total: root.findings
        selected: root.selectedSeverity
        theme: root.theme
        labels: root.labels
        onBandSelected: (band) => root.severitySelected(band)
    }

    FixesCard {
        Layout.fillWidth: false
        Layout.fillHeight: true
        Layout.preferredWidth: Kirigami.Units.gridUnit * 9.0
        bands: root.fixBands
        total: root.fixTotal
        selected: root.selectedFixState
        theme: root.theme
        labels: root.labels
        onBandSelected: (band) => root.fixStateSelected(band)
    }
}
