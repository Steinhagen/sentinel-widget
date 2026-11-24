import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

import "../domain/severity.mjs" as Severity

Rectangle {
    id: root

    property real maxSeverity: 0
    property int findings: 0
    property int affectedPackages: 0
    property int uniqueCves: 0
    property var theme: null
    property var labels: null

    readonly property real severityRatio: Math.max(0, Math.min(1, root.maxSeverity / 10))
    readonly property string severityBand: Severity.bandOf(root.maxSeverity)

    radius: 16
    color: root.theme ? root.theme.cardColor : "transparent"
    border.width: 1
    border.color: root.theme ? root.theme.cardBorder : "transparent"

    RowLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.gridUnit * 0.4
        spacing: Kirigami.Units.gridUnit * 0.5

        Item {
            Layout.preferredWidth: Kirigami.Units.gridUnit * 5.2
            Layout.preferredHeight: Layout.preferredWidth

            Shape {
                anchors.fill: parent

                ShapePath {
                    strokeColor: root.theme ? root.theme.hairline : "transparent"
                    strokeWidth: 8
                    fillColor: "transparent"
                    PathAngleArc {
                        centerX: Kirigami.Units.gridUnit * 2.6
                        centerY: centerX
                        radiusX: Kirigami.Units.gridUnit * 2.05
                        radiusY: radiusX
                        startAngle: -90
                        sweepAngle: 360
                    }
                }

                ShapePath {
                    strokeColor: root.maxSeverity > 0 && root.theme
                        ? root.theme.severityBandColor(root.severityBand) : "transparent"
                    strokeWidth: 8
                    fillColor: "transparent"
                    capStyle: ShapePath.RoundCap
                    PathAngleArc {
                        centerX: Kirigami.Units.gridUnit * 2.6
                        centerY: centerX
                        radiusX: Kirigami.Units.gridUnit * 2.05
                        radiusY: radiusX
                        startAngle: -90
                        sweepAngle: 360 * root.severityRatio
                    }
                }
            }

            Column {
                anchors.centerIn: parent
                spacing: 1

                PlasmaComponents3.Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: root.maxSeverity > 0 ? root.maxSeverity.toFixed(1) : "—"
                    color: Kirigami.Theme.textColor
                    font.bold: true
                    font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.35)
                }

                PlasmaComponents3.Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: root.labels ? root.labels.cvssLabel() : "CVSS"
                    color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 2)
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 1

            PlasmaComponents3.Label {
                objectName: "exposureTitle"
                text: root.labels
                    ? root.labels.exposureTitle(root.severityBand)
                    : root.severityBand
                color: root.theme
                    ? root.theme.severityBandColor(root.severityBand)
                    : Kirigami.Theme.disabledTextColor
                font.bold: true
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                font.letterSpacing: 0.6
            }

            PlasmaComponents3.Label {
                text: root.findings
                color: Kirigami.Theme.textColor
                font.bold: true
                font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.65)
            }

            PlasmaComponents3.Label {
                text: root.labels ? root.labels.potentialVulnerabilities() : "potential vulnerabilities"
                color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
            }

            RowLayout {
                spacing: Kirigami.Units.smallSpacing * 1.5

                PlasmaComponents3.Label {
                    text: root.labels ? root.labels.packagesText(root.affectedPackages) : ""
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

                PlasmaComponents3.Label {
                    text: root.labels ? root.labels.cvesText(root.uniqueCves) : ""
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
            }
        }
    }
}
