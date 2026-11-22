import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.extras as PlasmaExtras

Item {
    id: root

    property string emptyIcon: "security-medium"
    property string emptyTitle: ""
    property string emptyExplanation: ""

    PlasmaExtras.PlaceholderMessage {
        anchors.centerIn: parent
        width: parent.width - Kirigami.Units.gridUnit * 4
        iconName: root.emptyIcon
        text: root.emptyTitle
        explanation: root.emptyExplanation
    }
}
