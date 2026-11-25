import QtQuick

import org.kde.plasma.configuration

ConfigModel {
    ConfigCategory {
        name: i18n("General")
        icon: "configure"
        source: "configGeneral.qml"
    }
    ConfigCategory {
        name: i18n("Ignored findings")
        icon: "view-hidden"
        source: "configIgnored.qml"
    }
}
