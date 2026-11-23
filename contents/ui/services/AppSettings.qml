import QtQml

// The runtime view of the applet configuration. main.qml binds these values
// from Plasmoid.configuration; tests can set them directly.
QtObject {
    id: settings

    property string badgeMode: "count"
    property string trackerToken: ""
    property bool triageEnabled: true
    property bool hideUnverified: true
    property bool hideOsv: true
    // JSON array of { cve, package } pairs ignored from the applet.
    property string triageIgnore: "[]"

    readonly property var ignoredPairs: {
        const text = settings.triageIgnore || "[]";
        try {
            const list = JSON.parse(text);
            return Array.isArray(list) ? list : [];
        } catch (error) {
            return [];
        }
    }

    /** The ignore list with one pair appended, or the unchanged list. */
    function withIgnoredPair(cve, packageName) {
        const list = settings.ignoredPairs.slice();
        for (let i = 0; i < list.length; ++i) {
            if (list[i] && list[i].cve === cve && list[i].package === packageName) {
                return settings.triageIgnore || "[]";
            }
        }
        list.push({ cve: cve, package: packageName });
        return JSON.stringify(list);
    }

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
