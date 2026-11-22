import QtQml

// The runtime view of the applet configuration. main.qml binds these values
// from Plasmoid.configuration; tests can set them directly.
QtObject {
    id: settings

    property string badgeMode: "count"
    property string trackerToken: ""
    property bool triageEnabled: true

    readonly property string effectiveBadgeMode: {
        switch (settings.badgeMode) {
        case "none":
        case "dot":
        case "count":
            return settings.badgeMode;
        default:
            return "count";
        }
    }
}
