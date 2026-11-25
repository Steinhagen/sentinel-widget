import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts

import org.kde.kcmutils as KCM
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

KCM.SimpleKCM {
    id: page

    property alias cfg_badgeMode: badgeModeCombo.currentValue
    property alias cfg_sentinelTrackerToken: tokenField.text
    property alias cfg_triageEnabled: triageCheck.checked
    property alias cfg_hideUnverified: hideReviewCheck.checked
    property alias cfg_hideOsv: hideOsvCheck.checked
    Kirigami.FormLayout {
        QQC2.ComboBox {
            id: badgeModeCombo

            Kirigami.FormData.label: i18n("Panel badge:")

            model: [
                { text: i18n("Show the number of findings"), value: "count" },
                { text: i18n("Show a dot"), value: "dot" },
                { text: i18n("Hide the badge"), value: "none" }
            ]
            textRole: "text"
            valueRole: "value"
        }

        QQC2.CheckBox {
            id: triageCheck

            Kirigami.FormData.label: i18n("Triage verdicts:")

            text: i18n("Hide findings classified as false positives")
        }

        QQC2.CheckBox {
            id: hideReviewCheck

            Kirigami.FormData.label: i18n("Unverified findings:")

            text: i18n("Hide findings the triage pass could not confirm")
        }

        QQC2.CheckBox {
            id: hideOsvCheck

            Kirigami.FormData.label: i18n("OSV advisories:")

            text: i18n("Hide all OSV findings")
        }

        PlasmaComponents3.Label {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            wrapMode: Text.WordWrap
            opacity: 0.7
            font: Kirigami.Theme.smallFont
            text: i18n("Findings whose CVE does not describe the installed package are hidden by “Triage verdicts”; findings the triage pass could not confirm are hidden by “Unverified findings”; OSV advisories are hidden by “OSV advisories”. The verdicts come from the triage pass (tools/triage.mjs) or from the scan service. The Triage column remains visible so a restored finding keeps its verdict.")
        }

        RowLayout {
            Kirigami.FormData.label: i18n("Tracker API token:")

            QQC2.TextField {
                id: tokenField

                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: i18n("Paste a token from the tracker")
            }

            PlasmaComponents3.ToolButton {
                icon.name: "edit-clear"
                enabled: tokenField.text.length > 0
                onClicked: tokenField.text = ""

                QQC2.ToolTip.text: i18n("Clear the token")
                QQC2.ToolTip.visible: hovered
            }
        }

        PlasmaComponents3.Button {
            text: i18n("Open the token settings page")
            icon.name: "internet-services"
            onClicked: Qt.openUrlExternally("https://tracker.security.nixos.org/user/tokens")
        }

        PlasmaComponents3.Label {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            wrapMode: Text.WordWrap
            opacity: 0.7
            font: Kirigami.Theme.smallFont
            text: i18n("The token is stored in this applet's configuration (only readable by you) and is used by the root scan service on its next run. It is optional: without it, every CVE still links to the Nixpkgs security tracker. Leave this empty to use a token installed at /var/lib/sentinel/tracker-token, if any.")
        }
    }
}
