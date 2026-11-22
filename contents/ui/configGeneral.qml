import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts

import org.kde.kcmutils as KCM
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

KCM.SimpleKCM {
    id: page

    property alias cfg_badgeMode: badgeModeCombo.currentValue
    property alias cfg_vulnscanTrackerToken: tokenField.text

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
            text: i18n("The token is stored in this applet's configuration (only readable by you) and is used by the root scan service on its next run. It is optional: without it, every CVE still links to the Nixpkgs security tracker. Leave this empty to use a token installed at /var/lib/vulnscan/tracker-token, if any.")
        }
    }
}
