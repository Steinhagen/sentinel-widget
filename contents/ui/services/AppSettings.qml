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
    // JSON array of { cve, package, version } entries the user explicitly
    // restored from the hidden view.
    property string triageShow: "[]"

    readonly property var forcedVisible: {
        const text = settings.triageShow || "[]";
        try {
            const list = JSON.parse(text);
            return Array.isArray(list) ? list : [];
        } catch (error) {
            return [];
        }
    }

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

    /** The ignore list without the entries covering this exact row. */
    function withoutIgnored(cve, packageName, version) {
        const wantedVersion = String(version || "");
        const list = settings.ignoredPairs.filter((entry) => {
            if (!entry || entry.cve !== cve || entry.package !== packageName) {
                return true;
            }
            const entryVersion = String(entry.version || "");
            return entryVersion.length > 0 && entryVersion !== wantedVersion;
        });
        return JSON.stringify(list);
    }

    /** The forced-visible list with one exact version appended. */
    function withForcedVisible(cve, packageName, version) {
        const list = settings.forcedVisible.slice();
        const wantedVersion = String(version || "");
        for (let i = 0; i < list.length; ++i) {
            const entry = list[i];
            if (!entry || entry.cve !== cve || entry.package !== packageName) {
                continue;
            }
            if (!entry.version || entry.version === wantedVersion) {
                return settings.triageShow || "[]";
            }
        }
        const entry = { cve: cve, package: packageName };
        if (wantedVersion.length > 0) {
            entry.version = wantedVersion;
        }
        list.push(entry);
        return JSON.stringify(list);
    }

    /** The forced-visible list without the entries covering this exact row. */
    function withoutForcedVisible(cve, packageName, version) {
        const wantedVersion = String(version || "");
        const list = settings.forcedVisible.filter((entry) => {
            if (!entry || entry.cve !== cve || entry.package !== packageName) {
                return true;
            }
            const entryVersion = String(entry.version || "");
            return entryVersion.length > 0 && entryVersion !== wantedVersion;
        });
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
