import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts

import org.kde.kcmutils as KCM
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

KCM.SimpleKCM {
    id: page

    property alias cfg_triageIgnore: ignoreState.value

    // Non-visual holder so the page can edit the ignore list.
    QtObject {
        id: ignoreState
        property string value: "[]"
    }

    function ignoredEntries() {
        try {
            const list = JSON.parse(ignoreState.value || "[]");
            return Array.isArray(list) ? list : [];
        } catch (error) {
            return [];
        }
    }

    function ignoredCount() {
        return ignoredEntries().length;
    }

    function ignoredLabel(entry) {
        const version = entry && entry.version
            ? String(entry.version)
            : i18n("all versions");
        return [entry ? String(entry.cve) : "",
            entry ? String(entry.package) : "",
            version].filter((part) => part.length > 0).join(" · ");
    }

    function removeIgnored(index) {
        const list = ignoredEntries();
        list.splice(index, 1);
        const value = JSON.stringify(list);
        // Do not destroy the delegate inside its own click handler; layout
        // polish can otherwise touch a deleted Layout attached object.
        Qt.callLater(function () {
            ignoreState.value = value;
        });
    }

    readonly property alias restoreAllButton: restoreAllButton

    Kirigami.FormLayout {
        PlasmaComponents3.Label {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 34
            wrapMode: Text.WordWrap
            opacity: 0.7
            font: Kirigami.Theme.smallFont
            text: i18n("Use “Ignore this finding” in a row's context menu or the crossed-eye action to hide a finding the scanners matched to the wrong package. A version-scoped ignore only hides that exact version; it reappears after a package bump so it can be reviewed again.")
        }

        RowLayout {
            Kirigami.FormData.label: i18n("Ignored findings:")

            PlasmaComponents3.Label {
                text: page.ignoredCount() === 0
                    ? i18n("None")
                    : i18np("%1 finding", "%1 findings", page.ignoredCount())
            }

            PlasmaComponents3.Button {
                id: restoreAllButton

                text: i18n("Restore all")
                icon.name: "edit-undo"
                enabled: page.ignoredCount() > 0
                onClicked: Qt.callLater(function () {
                    ignoreState.value = "[]";
                })
            }
        }

        // Plain Column/Item delegates: clearing the Repeater must not destroy
        // QQuickLayout attached objects while the FormLayout is polishing.
        Column {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 34
            spacing: 0

            Repeater {
                model: page.ignoredEntries()

                delegate: Item {
                    required property var modelData
                    required property int index

                    width: parent ? parent.width : 0
                    height: 28

                    PlasmaComponents3.Label {
                        anchors.left: parent.left
                        anchors.right: removeButton.left
                        anchors.rightMargin: Kirigami.Units.smallSpacing
                        anchors.verticalCenter: parent.verticalCenter
                        text: page.ignoredLabel(modelData)
                        elide: Text.ElideRight
                        font: Kirigami.Theme.smallFont
                    }

                    PlasmaComponents3.ToolButton {
                        id: removeButton

                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        width: 24
                        height: 24
                        icon.name: "edit-delete"
                        Accessible.name: i18n("Restore this finding")
                        onClicked: page.removeIgnored(index)

                        QQC2.ToolTip.text: i18n("Restore this finding")
                        QQC2.ToolTip.visible: hovered
                    }

                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: 1
                        color: Kirigami.Theme.disabledTextColor
                        opacity: 0.2
                    }
                }
            }
        }

        PlasmaComponents3.Label {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 34
            visible: page.ignoredCount() === 0
            text: i18n("No ignored findings.")
            opacity: 0.7
            font: Kirigami.Theme.smallFont
        }
    }
}
