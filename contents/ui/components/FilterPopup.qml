import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

QQC2.Popup {
    id: popup

    property string cveFilter: ""
    property string packageFilter: ""
    property string originFilter: ""
    property string severityBand: ""
    property string fixState: ""
    property bool showCommon: true
    property var labels: null

    signal filtersApplied(string cve, string packageName, string origin,
        string severity, string fix)
    signal clearAllRequested()

    width: Kirigami.Units.gridUnit * 23
    padding: Kirigami.Units.largeSpacing
    modal: false
    closePolicy: QQC2.Popup.CloseOnEscape | QQC2.Popup.CloseOnPressOutside

    function optionIndex(options, value) {
        for (let i = 0; i < options.length; ++i) {
            if (options[i].value === value) {
                return i;
            }
        }
        return 0;
    }

    function apply() {
        popup.filtersApplied(
            cveField.text,
            packageField.text,
            originField.text,
            severityBox.currentValue || "",
            fixBox.currentValue || "");
        popup.close();
    }

    onOpened: {
        cveField.text = popup.cveFilter;
        packageField.text = popup.packageFilter;
        originField.text = popup.originFilter;
        severityBox.currentIndex = popup.optionIndex(severityBox.model, popup.severityBand);
        fixBox.currentIndex = popup.optionIndex(fixBox.model, popup.fixState);
        cveField.forceActiveFocus();
    }

    contentItem: ColumnLayout {
        spacing: Kirigami.Units.smallSpacing

        PlasmaComponents3.Label {
            text: popup.labels ? popup.labels.advancedFilterTitle() : "Filter findings"
            font.bold: true
            font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.05)
        }

        PlasmaComponents3.Label {
            text: popup.labels ? popup.labels.cvePlaceholder() : "CVE ID"
            color: Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.TextField {
            id: cveField
            Layout.fillWidth: true
            placeholderText: popup.labels ? popup.labels.cvePlaceholder() : "CVE ID"
            onAccepted: popup.apply()
        }

        PlasmaComponents3.Label {
            text: popup.labels ? popup.labels.packagePlaceholder() : "Package"
            color: Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.TextField {
            id: packageField
            Layout.fillWidth: true
            placeholderText: popup.labels ? popup.labels.packagePlaceholder() : "Package"
            onAccepted: popup.apply()
        }

        PlasmaComponents3.Label {
            text: popup.labels ? popup.labels.originPlaceholder() : "Origin"
            color: Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.TextField {
            id: originField
            Layout.fillWidth: true
            placeholderText: popup.labels ? popup.labels.originPlaceholder() : "Origin"
            onAccepted: popup.apply()
        }

        PlasmaComponents3.Label {
            visible: popup.showCommon
            text: popup.labels ? popup.labels.severityLabel() : "Severity"
            color: Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.ComboBox {
            id: severityBox
            Layout.fillWidth: true
            visible: popup.showCommon
            textRole: "text"
            valueRole: "value"
            model: [
                { text: popup.labels ? popup.labels.allSeverities() : "All severities", value: "" },
                { text: popup.labels ? popup.labels.severityBandLabel("critical") : "Critical", value: "critical" },
                { text: popup.labels ? popup.labels.severityBandLabel("high") : "High", value: "high" },
                { text: popup.labels ? popup.labels.severityBandLabel("medium") : "Medium", value: "medium" },
                { text: popup.labels ? popup.labels.severityBandLabel("low") : "Low", value: "low" },
                { text: popup.labels ? popup.labels.unknownSeverity() : "Unknown", value: "unknown" }
            ]
        }

        PlasmaComponents3.Label {
            visible: popup.showCommon
            text: popup.labels ? popup.labels.fixStateLabel() : "Fix state"
            color: Kirigami.Theme.disabledTextColor
            font.family: Kirigami.Theme.smallFont.family
            font.pointSize: Kirigami.Theme.smallFont.pointSize
        }
        QQC2.ComboBox {
            id: fixBox
            Layout.fillWidth: true
            visible: popup.showCommon
            textRole: "text"
            valueRole: "value"
            model: [
                { text: popup.labels ? popup.labels.allFixStates() : "All fix states", value: "" },
                { text: popup.labels ? popup.labels.fixFilterLabel("fixed") : "Fix available", value: "fixed" },
                { text: popup.labels ? popup.labels.fixFilterLabel("progress") : "Fix pending", value: "progress" },
                { text: popup.labels ? popup.labels.fixFilterLabel("none") : "No fix", value: "none" },
                { text: popup.labels ? popup.labels.fixFilterLabel("unknown") : "Unknown fix state", value: "unknown" },
                { text: popup.labels ? popup.labels.fixFilterLabel("n/a") : "n/a", value: "n/a" }
            ]
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Button {
                Layout.fillWidth: true
                text: popup.labels ? popup.labels.applyFiltersText() : "Apply"
                onClicked: popup.apply()
            }

            PlasmaComponents3.ToolButton {
                text: popup.labels ? popup.labels.clearFiltersText() : "Clear"
                onClicked: {
                    popup.clearAllRequested();
                    popup.close();
                }
            }
        }
    }
}
