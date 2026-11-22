import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

PlasmaComponents3.Label {
    id: root

    Layout.fillWidth: true
    visible: text.length > 0
    color: Kirigami.Theme.neutralTextColor
    wrapMode: Text.WordWrap
    font.family: Kirigami.Theme.smallFont.family
    font.pointSize: Kirigami.Theme.smallFont.pointSize
}
