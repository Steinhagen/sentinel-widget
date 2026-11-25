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
    // JSON array of { cve, package, version } entries ignored from the
    // applet. Entries without a version are package-wide (old format).
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

    /** The ignore list with one versioned entry appended, or unchanged. */
    function withIgnoredPair(cve, packageName, version) {
        const list = settings.ignoredPairs.slice();
        const wantedVersion = String(version || "");
        for (let i = 0; i < list.length; ++i) {
            const entry = list[i];
            if (!entry || entry.cve !== cve || entry.package !== packageName) {
                continue;
            }
            // An old package-wide entry already covers every version.
            if (!entry.version || entry.version === wantedVersion) {
                return settings.triageIgnore || "[]";
            }
        }
        const entry = { cve: cve, package: packageName };
        if (wantedVersion.length > 0) {
            entry.version = wantedVersion;
        }
        list.push(entry);
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
