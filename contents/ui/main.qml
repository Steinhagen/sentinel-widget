import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import QtQuick.Shapes

import org.kde.plasma.plasmoid
import org.kde.plasma.plasma5support as Plasma5Support
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.extras as PlasmaExtras
import org.kde.plasma.core as PlasmaCore
import org.kde.kirigami as Kirigami

PlasmoidItem {
    id: root

    // Written by systemd service "vulnscan"; see system/vulnscan.nix.
    readonly property string statusFile: "/var/lib/vulnscan/status.json"
    readonly property string reportFile: "/var/lib/vulnscan/report.csv"
    readonly property string logFile: "/var/lib/vulnscan/last.log"

    property var status: ({
        state: "unknown",
        findings: 0,
        max_severity: 0,
        packages_affected: 0,
        severity_counts: ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }),
        scanned_at: "",
        vulnerabilities: []
    })
    property bool haveStatus: false
    property bool scanning: false
    // Authoritative systemd state, so a plasmashell restart does not lose a
    // scan that is still running.
    property bool scanServiceActive: false
    property string preScanStamp: ""
    // Raw status.json of the last read: polling an unchanged file must not
    // rebuild the list.
    property string statusRaw: ""
    // Tracker summary and progress, kept apart from `status`: the tracker
    // rewrites it every few seconds during a pass, while the findings
    // themselves stay unchanged.
    property var trackerData: null
    // True while the pointer is over the findings list. Row updates are held
    // back then, because replacing the model destroys the delegates and closes
    // an open tooltip.
    property bool listHovered: false
    property var deferredStatus: null
    // The finding whose Fix tooltip is showing, and where it is anchored.
    // The tooltip is owned by the list, not by the row: rebuilding the rows
    // would destroy a row-owned tooltip mid-hover.
    property var fixTipItem: null
    property real fixTipX: 0
    property real fixTipYBelow: 0
    property real fixTipYAbove: 0

    // Ticking clock so "scanned 5 minutes ago" stays honest while the popup is
    // open without re-reading status.json.
    property double clock: Date.now()

    readonly property string state: root.haveStatus ? (root.status.state || "unknown") : "unknown"
    readonly property int findings: root.haveStatus ? (root.status.findings || 0) : 0
    readonly property real maxSeverity: root.haveStatus ? Number(root.status.max_severity || 0) : 0
    readonly property var vulnerabilities: root.haveStatus ? (root.status.vulnerabilities || root.status.top || []) : []
    readonly property bool hasFindings: root.vulnerabilities.length > 0

    // Kirigami follows the system color scheme; every surface below is derived
    // from the theme so the applet switches light/dark on its own.
    readonly property bool darkMode: Kirigami.Theme.backgroundColor.hsvValue < 0.5
    readonly property color cardColor: root.darkMode
        ? Qt.rgba(1, 1, 1, 0.06)
        : Qt.rgba(1, 1, 1, 0.86)
    readonly property color cardBorder: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b,
        root.darkMode ? 0.16 : 0.10)
    readonly property color mutedText: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.62)
    readonly property color faintText: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.42)
    readonly property color hairline: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.10)
    readonly property color rowHover: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.055)
    readonly property color inputBackground: root.darkMode
        ? Qt.rgba(1, 1, 1, 0.055)
        : Qt.rgba(0, 0, 0, 0.025)
    readonly property color primaryColor: Kirigami.Theme.highlightColor
    readonly property color primaryText: Kirigami.Theme.highlightedTextColor
    readonly property color criticalColor: root.darkMode ? "#fb7185" : "#e11d48"
    readonly property color highColor: root.darkMode ? "#fbbf24" : "#f97316"
    readonly property color mediumColor: root.darkMode ? "#facc15" : "#f59e0b"
    readonly property color lowColor: root.darkMode ? "#4ade80" : "#22c55e"
    readonly property color unknownColor: root.darkMode ? "#94a3b8" : "#cbd5e1"
    readonly property color severitySurface: root.darkMode
        ? Qt.rgba(0.45, 0.38, 0.95, 0.22)
        : Qt.rgba(0.45, 0.38, 0.95, 0.10)
    readonly property color fixesSurface: root.darkMode
        ? Qt.rgba(0.05, 0.72, 0.50, 0.22)
        : Qt.rgba(0.05, 0.72, 0.50, 0.10)

    readonly property string postureLabel: {
        switch (root.state) {
        case "secure": return i18n("Secure");
        case "vulnerable": return i18n("Vulnerable");
        case "warn": return i18n("Review");
        default: return i18n("Unknown");
        }
    }
    readonly property int fixedCount: root.filterBandCount(root.masterFilterBands, "fixed")
    // Denominator for the fix-state bar; it covers exactly the states listed
    // in the Ready to fix card (including n/a).
    readonly property int fixStateTotal: root.fixedCount
        + root.filterBandCount(root.masterFilterBands, "progress")
        + root.filterBandCount(root.masterFilterBands, "none")
        + root.filterBandCount(root.masterFilterBands, "unknown")
        + root.filterBandCount(root.masterFilterBands, "n/a")
    readonly property int trackedCves: root.trackerSummary && root.trackerSummary.cves ? Number(root.trackerSummary.cves) : 0

    readonly property int affectedPackages: {
        if (root.haveStatus && typeof root.status.packages_affected === "number") {
            return root.status.packages_affected;
        }
        var seen = {};
        for (var i = 0; i < root.vulnerabilities.length; ++i) {
            var packageName = root.vulnerabilities[i].package;
            if (packageName) {
                seen[packageName] = true;
            }
        }
        return Object.keys(seen).length;
    }

    readonly property var severityCounts: {
        var counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
        if (root.haveStatus && root.status.severity_counts) {
            var stored = root.status.severity_counts;
            for (var band in counts) {
                counts[band] = Number(stored[band] || 0);
            }
            return counts;
        }
        // Older status files only carry the vulnerability list.
        for (var i = 0; i < root.vulnerabilities.length; ++i) {
            counts[root.severityBandOf(root.vulnerabilities[i])] += 1;
        }
        return counts;
    }

    readonly property var severityBands: [
        { key: "", label: i18n("All"), count: root.vulnerabilities.length },
        { key: "critical", label: i18n("Critical"), count: root.severityCounts.critical },
        { key: "high", label: i18n("High"), count: root.severityCounts.high },
        { key: "medium", label: i18n("Medium"), count: root.severityCounts.medium },
        { key: "low", label: i18n("Low"), count: root.severityCounts.low },
        { key: "unknown", label: i18n("Unknown"), count: root.severityCounts.unknown }
    ]

    readonly property var masterFilterBands: {
        var fixed = 0;
        var progress = 0;
        var none = 0;
        var unknown = 0;
        var na = 0;
        for (var i = 0; i < root.vulnerabilities.length; ++i) {
            switch (root.fixBucket(root.vulnerabilities[i])) {
            case "fixed":
                fixed++;
                break;
            case "progress":
                progress++;
                break;
            case "none":
                none++;
                break;
            case "unknown":
                unknown++;
                break;
            case "na":
                na++;
                break;
            }
        }
        return [
            { key: "", label: i18n("All"), count: root.vulnerabilities.length },
            { key: "fixed", label: i18n("Fix available"), count: fixed },
            { key: "progress", label: i18n("Fix pending"), count: progress },
            { key: "none", label: i18n("No fix"), count: none },
            { key: "unknown", label: i18n("Unknown"), count: unknown },
            { key: "n/a", label: i18n("n/a"), count: na }
        ];
    }

    readonly property var trackerFilterBands: {
        var linked = 0;
        var pending = 0;
        var missing = 0;
        var unchecked = 0;
        for (var i = 0; i < root.vulnerabilities.length; ++i) {
            var item = root.vulnerabilities[i];
            var tracker = item.tracker;
            if (tracker && tracker.found === true) {
                linked++;
                if (tracker.status === "pending") {
                    pending++;
                }
            } else if (root.trackerState(item) === "missing") {
                missing++;
            } else {
                unchecked++;
            }
        }
        return [
            { key: "", label: i18n("All"), count: root.vulnerabilities.length },
            { key: "linked", label: i18n("In tracker"), count: linked },
            { key: "pending", label: i18n("Pending"), count: pending },
            { key: "missing", label: i18n("Missing"), count: missing },
            { key: "unchecked", label: i18n("Not checked"), count: unchecked }
        ];
    }

    readonly property var priorityFilterOptions: {
        var result = [];
        for (var i = 0; i < root.severityBands.length; ++i) {
            var band = root.severityBands[i];
            result.push({
                text: i18n("%1 (%2)", band.label, band.count),
                value: band.key
            });
        }
        return result;
    }

    readonly property var masterFilterOptions: {
        var result = [];
        for (var i = 0; i < root.masterFilterBands.length; ++i) {
            var band = root.masterFilterBands[i];
            result.push({
                text: i18n("%1 (%2)", band.label, band.count),
                value: band.key
            });
        }
        return result;
    }

    readonly property var trackerFilterOptions: {
        var result = [];
        for (var i = 0; i < root.trackerFilterBands.length; ++i) {
            var band = root.trackerFilterBands[i];
            result.push({
                text: i18n("%1 (%2)", band.label, band.count),
                value: band.key
            });
        }
        return result;
    }

    readonly property var lastScanDate: {
        if (!root.haveStatus) {
            return null;
        }
        var epoch = root.status.scanned_at_epoch;
        if (typeof epoch === "number" && epoch > 0) {
            return new Date(epoch * 1000);
        }
        var raw = root.status.scanned_at_iso || root.status.scanned_at || "";
        if (!raw) {
            return null;
        }
        var parsed = Date.parse(raw);
        if (!isNaN(parsed)) {
            return new Date(parsed);
        }
        // Older status files used a "%Y-%m-%d %H:%M %Z" string that JavaScript
        // does not reliably parse; the date and time part is local time.
        var match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/.exec(raw);
        if (match) {
            return new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5]);
        }
        return null;
    }

    readonly property real lastScanAge: root.lastScanDate
        ? Math.max(0, (root.clock - root.lastScanDate.getTime()) / 1000)
        : -1

    readonly property string lastScanRelative: {
        if (root.lastScanAge < 0) {
            return "";
        }
        if (root.lastScanAge < 60) {
            return i18n("just now");
        }
        if (root.lastScanAge < 3600) {
            return i18np("%1 minute ago", "%1 minutes ago", Math.floor(root.lastScanAge / 60));
        }
        if (root.lastScanAge < 86400) {
            return i18np("%1 hour ago", "%1 hours ago", Math.floor(root.lastScanAge / 3600));
        }
        return i18np("%1 day ago", "%1 days ago", Math.floor(root.lastScanAge / 86400));
    }

    readonly property string lastScanExact: root.lastScanDate ? Qt.formatDateTime(root.lastScanDate, "yyyy-MM-dd HH:mm") : ""

    // The scan timestamp is shown in exactly one place: the header label next
    // to "Scan now". Relative time stays visible; hovering reveals the exact
    // local time. The summary line and the (now removed) footer used to repeat
    // it in two more forms.
    readonly property string lastScanLabel: root.lastScanRelative
        ? i18n("Last scan %1", root.lastScanRelative)
        : ""
    readonly property string lastScanTooltip: root.lastScanExact
        ? i18n("Last scan: %1", root.lastScanExact)
        : ""

    // Optional data from the Nixpkgs security tracker; see system/vulnscan.nix.
    readonly property string trackerBase: "https://tracker.security.nixos.org"
    readonly property var trackerSummary: root.trackerData
    // The channel this system updates from (from the scan service).
    readonly property string systemChannel: (root.trackerSummary
        && root.trackerSummary.system_channel) || ""
    readonly property bool hasTrackerData: !!root.trackerSummary && root.trackerSummary.available === true
    readonly property var trackerProgress: root.trackerData
    readonly property bool trackerBusy: !!root.trackerProgress && root.trackerProgress.complete === false
    readonly property int trackerProgressTotal: {
        var tracker = root.trackerProgress;
        if (!tracker) {
            return 0;
        }
        if (tracker.phase === "packages") {
            return Number(tracker.total_packages || 0);
        }
        if (tracker.phase === "cves") {
            return Number(tracker.fallback_total || 0);
        }
        if (tracker.phase === "issues") {
            return Number(tracker.total_issues || 0);
        }
        if (tracker.phase === "probes") {
            return Number(tracker.total_probes || 0);
        }
        return Number(tracker.total_cves || tracker.cves || 0);
    }
    readonly property int trackerProgressDone: {
        var tracker = root.trackerProgress;
        if (!tracker) {
            return 0;
        }
        if (tracker.phase === "packages") {
            return Number(tracker.packages_checked || 0) + Number(tracker.package_failed || 0);
        }
        if (tracker.phase === "cves") {
            return Number(tracker.fallback_done || 0) + Number(tracker.fallback_failed || 0);
        }
        if (tracker.phase === "issues") {
            return Number(tracker.issues_checked || 0) + Number(tracker.issue_failed || 0);
        }
        if (tracker.phase === "probes") {
            return Number(tracker.probes_checked || 0) + Number(tracker.probes_failed || 0);
        }
        return Number(tracker.queried || 0) + Number(tracker.failed || 0);
    }

    // Results of on-demand tracker checks (CVE -> true/false) for when no
    // scan-time tracker data is available, plus a transient message.
    property var trackerChecked: ({})
    property int trackerRevision: 0
    property string trackerHint: ""

    readonly property string trackerProgressText: {
        var tracker = root.trackerProgress;
        if (!tracker) {
            return "";
        }
        if (tracker.auth_failed) {
            return i18n("The tracker rejected the API token; check the token in the applet settings.");
        }
        if (tracker.complete !== false) {
            var failedDone = Number(tracker.failed || 0);
            if (tracker.throttled) {
                return i18n("Tracker rate limit reached; %1 CVEs will be retried in the next run.", failedDone);
            }
            if (failedDone > 0) {
                return i18n("Tracker check finished with %1 failures.", failedDone);
            }
            return "";
        }
        if (tracker.phase === "pending") {
            return i18n("Tracker check queued…");
        }
        if (tracker.phase === "waiting") {
            return i18n("Tracker rate limit reached; waiting to retry…");
        }
        if (tracker.phase === "packages") {
            var packagesDone = Number(tracker.packages_checked || 0) + Number(tracker.package_failed || 0);
            var packageText = i18n("Checking tracker packages: %1/%2",
                packagesDone, Number(tracker.total_packages || 0));
            if (Number(tracker.package_failed || 0) > 0) {
                packageText += i18n(" (%1 failed)", Number(tracker.package_failed || 0));
            }
            if (tracker.throttled) {
                packageText += i18n(" — rate limit reached");
            }
            return packageText;
        }
        if (tracker.phase === "cves") {
            var cvesDone = Number(tracker.fallback_done || 0) + Number(tracker.fallback_failed || 0);
            var cveText = i18n("Checking remaining CVEs: %1/%2",
                cvesDone, Number(tracker.fallback_total || 0));
            if (Number(tracker.fallback_failed || 0) > 0) {
                cveText += i18n(" (%1 failed)", Number(tracker.fallback_failed || 0));
            }
            if (tracker.throttled) {
                cveText += i18n(" — rate limit reached");
            }
            return cveText;
        }
        if (tracker.phase === "issues") {
            var issuesDone = Number(tracker.issues_checked || 0) + Number(tracker.issue_failed || 0);
            var issueText = i18n("Checking fix links: %1/%2", issuesDone, Number(tracker.total_issues || 0));
            if (Number(tracker.issue_failed || 0) > 0) {
                issueText += i18n(" (%1 failed)", Number(tracker.issue_failed || 0));
            }
            if (tracker.throttled) {
                issueText += i18n(" — rate limit reached");
            }
            return issueText;
        }
        if (tracker.phase === "probes") {
            var probeDone = Number(tracker.probes_checked || 0)
                + Number(tracker.probes_failed || 0);
            var probeText = i18n("Checking nixpkgs branches: %1/%2",
                probeDone, Number(tracker.total_probes || 0));
            if (Number(tracker.probes_failed || 0) > 0) {
                probeText += i18n(" (%1 failed)", Number(tracker.probes_failed || 0));
            }
            return probeText;
        }
        var failed = Number(tracker.failed || 0);
        var text = i18n("Checking security tracker: %1/%2 CVEs",
            Number(tracker.queried || 0) + failed, Number(tracker.total_cves || tracker.cves || 0));
        if (failed > 0) {
            text += i18n(" (%1 failed)", failed);
        }
        if (tracker.throttled) {
            text += i18n(" — rate limit reached");
        }
        return text;
    }

    readonly property string trackerSummaryText: {
        var tracker = root.trackerSummary;
        if (!tracker) {
            return "";
        }
        if (tracker.available !== true && tracker.complete !== false) {
            return "";
        }
        var missing = root.filterBandCount(root.trackerFilterBands, "missing");
        var linked = root.filterBandCount(root.trackerFilterBands, "linked");
        var pending = root.filterBandCount(root.trackerFilterBands, "pending");
        var unchecked = root.filterBandCount(root.trackerFilterBands, "unchecked");
        var fixed = root.filterBandCount(root.masterFilterBands, "fixed");
        var pending = root.filterBandCount(root.masterFilterBands, "progress");
        var parts = [];
        if (missing > 0) {
            parts.push(i18np("%1 finding untracked", "%1 findings untracked", missing));
        }
        if (linked > 0) {
            parts.push(i18np("%1 finding in tracker", "%1 findings in tracker", linked));
        }
        if (pending > 0) {
            parts.push(i18n("%1 pending review", pending));
        }
        if (fixed > 0) {
            parts.push(i18n("%1 with a fix available", fixed));
        }
        if (pending > 0) {
            parts.push(i18n("%1 with a fix pending", pending));
        }
        if (unchecked > 0) {
            parts.push(i18np("%1 finding not checked", "%1 findings not checked", unchecked));
        }
        if (tracker.failed > 0) {
            parts.push(i18np("%1 CVE failed", "%1 CVEs failed", tracker.failed));
        }
        var text = parts.length > 0
            ? parts.join(" · ")
            : (tracker.complete === false ? i18n("checking…") : i18n("no matching issues"));
        return i18n("Nixpkgs security tracker: %1.", text);
    }

    readonly property string resultInfoText: {
        var parts = [];
        if (root.trackerSummaryText.length > 0) {
            parts.push(root.trackerSummaryText);
        }
        parts.push(i18n("Scores and versions come from the scanned system; NixOS may already carry a backported fix."));
        parts.push(i18n("The second line shows the dependency chain that introduced the finding. Click it to filter to that origin, or use “Group by origin” to group the list by the package that pulled each finding in. Right-click a row for tracker, fix and copy actions. Origin data is written by the scan service."));
        parts.push(root.masterHelpText);
        parts.push(i18n("The CSV report and scan log are available from the widget's context menu."));
        return parts.join("\n\n");
    }

    readonly property color stateColor: {
        switch (root.state) {
        case "secure":
            return Kirigami.Theme.positiveTextColor;
        case "vulnerable":
            return Kirigami.Theme.negativeTextColor;
        case "warn":
            return Kirigami.Theme.neutralTextColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    readonly property string stateIcon: {
        switch (root.state) {
        case "secure":
            return "security-high";
        case "vulnerable":
            return "security-low";
        default:
            return "security-medium";
        }
    }

    readonly property string stateLabel: {
        if (!root.haveStatus) {
            return i18n("Not scanned yet");
        }
        switch (root.state) {
        case "secure":
            return i18n("System is secure");
        case "vulnerable":
        case "warn":
            return i18np("%1 potential vulnerability", "%1 potential vulnerabilities", root.findings);
        case "unknown":
            return i18n("Vulnerability status unknown");
        default:
            return i18n("Not scanned yet");
        }
    }

    // Header summary: what the scan found, without the timestamp. The panel
    // tooltip keeps the fuller sentence below.
    readonly property string stateSummary: {
        if (!root.haveStatus) {
            return root.scanning ? i18n("The first scan is running…") : i18n("No scan has run yet.");
        }
        if (root.state === "unknown") {
            return i18n("The last scan failed — see the scan log for details.");
        }

        var parts = [];
        if (root.state !== "secure") {
            parts.push(i18np("%1 package affected", "%1 packages affected", root.affectedPackages));
            parts.push(i18n("highest CVSS %1", root.maxSeverity.toFixed(1)));
        }
        return parts.join(" · ");
    }

    readonly property string stateDetail: {
        if (!root.haveStatus || root.state === "unknown") {
            return root.stateSummary;
        }

        var parts = [];
        if (root.stateSummary) {
            parts.push(root.stateSummary);
        }
        if (root.lastScanRelative) {
            parts.push(i18n("scanned %1", root.lastScanRelative));
        }
        return parts.join(" · ");
    }

    readonly property string emptyIcon: root.stateIcon

    readonly property string emptyTitle: {
        if (!root.haveStatus) {
            return i18n("Not scanned yet");
        }
        switch (root.state) {
        case "secure":
            return i18n("No known vulnerabilities");
        case "unknown":
            return i18n("The last scan failed");
        default:
            return i18n("No findings to show");
        }
    }

    readonly property string emptyExplanation: {
        if (!root.haveStatus) {
            return root.scanning
                ? i18n("The first scan can take a while: it has to download the vulnerability databases.")
                : i18n("The scan runs automatically once a day and can also be started manually.");
        }
        switch (root.state) {
        case "secure":
            return i18n("The last scan found no known vulnerabilities.");
        case "unknown":
            return root.status.error || i18n("Open the scan log for details.");
        default:
            return "";
        }
    }

    // Table state: global search, per-column filters, severity bands and sorting.
    property string searchText: ""
    // Preserve the list scroll position across status/tracker refreshes;
    // only explicit filter/sort/search/new-scan changes jump to the top.
    property int scrollToTopRequest: 0
    property real listContentY: 0
    property real restoreListY: 0
    property int restoreListRequest: 0
    onSearchTextChanged: root.scrollToTopRequest += 1
    property bool filterRowVisible: true
    property string sortKey: "severity"
    property bool sortDescending: true
    property string filterSeverity: ""
    property string filterCve: ""
    property string filterPackage: ""
    property string filterOrigin: ""
    property string filterVersion: ""
    property string filterVia: ""
    property string filterMaster: ""
    property string filterMasterState: ""
    property string filterTracker: ""
    property string severityBand: ""
    // 02 (flat two-line rows) is the default; 04 groups by the package that
    // introduced each finding.
    property bool groupByOrigin: false

    // Column widths are stored in grid units so they survive theme/DPI
    // changes. The header drag handles write columnWidths; columnPixels turns
    // them into pixels for the table, filter row and header.
    readonly property var columnDefaults: ({
        severity: 2.4,
        cve: 6.4,
        package: 6.4,
        version: 4.0,
        master: 4.4,
        via: 6.0,
        origin: 12.0
    })
    readonly property var columnMinimums: ({
        severity: 2.0,
        cve: 4.0,
        package: 3.0,
        version: 3.0,
        master: 3.0,
        via: 3.0,
        origin: 4.0
    })
    property var columnWidths: ({})
    readonly property var columnPixels: {
        var result = {};
        for (var key in root.columnDefaults) {
            var units = Number(root.columnWidths[key]);
            if (!isFinite(units) || units < root.columnMinimums[key]) {
                units = root.columnDefaults[key];
            }
            result[key] = units * Kirigami.Units.gridUnit;
        }
        return result;
    }

    readonly property real sevColumnWidth: root.columnPixels["severity"] || 0
    readonly property real cveColumnWidth: root.columnPixels["cve"] || 0
    readonly property real packageColumnWidth: root.columnPixels["package"] || 0
    readonly property real originColumnWidth: root.columnPixels["origin"] || 0
    readonly property real versionColumnWidth: root.columnPixels["version"] || 0
    readonly property real masterColumnWidth: root.columnPixels["master"] || 0
    readonly property real viaColumnWidth: root.columnPixels["via"] || 0
    readonly property real actionColumnWidth: Kirigami.Units.gridUnit * 1.6

    // All fix pills share one width. Measure the longest label the current
    // locale can produce and centre the text inside that width.
    TextMetrics { id: fixMetricFixed; font: Kirigami.Theme.smallFont; text: i18n("fixed") }
    TextMetrics { id: fixMetricStaging; font: Kirigami.Theme.smallFont; text: i18n("staging") }
    TextMetrics { id: fixMetricMaster; font: Kirigami.Theme.smallFont; text: i18n("master") }
    TextMetrics { id: fixMetricIssue; font: Kirigami.Theme.smallFont; text: i18n("issue") }
    TextMetrics { id: fixMetricNoFix; font: Kirigami.Theme.smallFont; text: i18n("no fix") }
    TextMetrics { id: fixMetricUnknown; font: Kirigami.Theme.smallFont; text: i18n("unknown") }
    TextMetrics { id: fixMetricNa; font: Kirigami.Theme.smallFont; text: i18n("n/a") }
    TextMetrics { id: fixMetricUnstable; font: Kirigami.Theme.smallFont; text: i18n("unstable") }

    readonly property real fixPillWidth: Math.max(
        fixMetricFixed.width,
        fixMetricStaging.width,
        fixMetricMaster.width,
        fixMetricIssue.width,
        fixMetricNoFix.width,
        fixMetricUnknown.width,
        fixMetricNa.width,
        fixMetricUnstable.width) + Kirigami.Units.smallSpacing * 2.2

    Component.onCompleted: root.columnWidths = root.loadColumnWidths()

    readonly property var listHeaderColumns: [
        { key: "severity", label: i18n("CVSS"), width: Kirigami.Units.gridUnit * 2, fill: false, align: "center" },
        { key: "cve", label: i18n("CVE"), width: Kirigami.Units.gridUnit * 8.5, fill: false, align: "left" },
        { key: "package", label: i18n("Package"), width: 0, fill: true, align: "left" },
        { key: "master", label: i18n("Fix"), width: root.fixPillWidth, fill: false, align: "center" }
    ]

    readonly property var filteredVulnerabilities: {
        var source = root.vulnerabilities;
        var query = root.searchText.trim().toLowerCase();
        var band = root.severityBand;
        var keys = ["severity", "cve", "package", "origin", "version", "master", "via"];
        var result = [];

        for (var i = 0; i < source.length; ++i) {
            var item = source[i];
            var haystack = [
                item.id,
                item.package,
                item.version,
                root.severityText(item.severity),
                root.scannersLabel(item.scanners),
                root.confidenceLabel(item.confidence),
                root.masterText(item),
                root.originNames(item).join(" "),
                root.originChainText(item),
                item.tracker ? [
                    item.tracker.issue,
                    item.tracker.status,
                    item.tracker.master_status,
                    item.tracker.master_version,
                    item.tracker.issue_state
                ].join(" ") : ""
            ].join(" ").toLowerCase();

            if (query.length > 0 && haystack.indexOf(query) === -1) {
                continue;
            }
            if (band.length > 0 && root.severityBandOf(item) !== band) {
                continue;
            }

            var keep = true;
            for (var k = 0; k < keys.length; ++k) {
                var needle = root.filterFor(keys[k]).trim().toLowerCase();
                if (needle.length > 0
                        && root.columnValue(item, keys[k]).toString().toLowerCase().indexOf(needle) === -1) {
                    keep = false;
                    break;
                }
            }
            if (keep && !root.masterStateMatches(item)) {
                keep = false;
            }
            if (keep && !root.trackerFilterMatches(item)) {
                keep = false;
            }
            if (keep) {
                result.push(item);
            }
        }

        var key = root.sortKey;
        var descending = root.sortDescending;
        result.sort(function (a, b) {
            var av = root.columnValue(a, key);
            var bv = root.columnValue(b, key);
            if (typeof av === "number" && typeof bv === "number") {
                if (av === bv) {
                    return 0;
                }
                return descending ? bv - av : av - bv;
            }
            av = av.toString().toLowerCase();
            bv = bv.toString().toLowerCase();
            if (av === bv) {
                return 0;
            }
            var cmp = av < bv ? -1 : 1;
            return descending ? -cmp : cmp;
        });
        return result;
    }

    function originGroupKey(item) {
        var name = root.originName(item);
        return name.length > 0 ? name : i18n("Unknown origin");
    }

    function originGroupCount(name) {
        var count = 0;
        for (var i = 0; i < root.filteredVulnerabilities.length; ++i) {
            if (root.originGroupKey(root.filteredVulnerabilities[i]) === name) {
                count++;
            }
        }
        return count;
    }

    // 04: order findings by origin group, with the highest-severity group
    // first, and by severity inside each group. ListView's section support
    // uses the originKey added to each copy.
    readonly property var groupedVulnerabilities: {
        var source = root.filteredVulnerabilities;
        var groups = {};
        var order = [];
        for (var i = 0; i < source.length; ++i) {
            var item = source[i];
            var key = root.originGroupKey(item);
            if (!groups[key]) {
                groups[key] = { items: [], maxSeverity: -1 };
                order.push(key);
            }
            groups[key].items.push(item);
            var severity = root.hasSeverityScore(item.severity) ? Number(item.severity) : -1;
            if (severity > groups[key].maxSeverity) {
                groups[key].maxSeverity = severity;
            }
        }
        order.sort(function (a, b) {
            if (groups[a].maxSeverity !== groups[b].maxSeverity) {
                return groups[b].maxSeverity - groups[a].maxSeverity;
            }
            if (groups[a].items.length !== groups[b].items.length) {
                return groups[b].items.length - groups[a].items.length;
            }
            return a.localeCompare(b);
        });
        var result = [];
        for (var g = 0; g < order.length; ++g) {
            var name = order[g];
            var group = groups[name];
            for (var j = 0; j < group.items.length; ++j) {
                var copy = {};
                for (var prop in group.items[j]) {
                    copy[prop] = group.items[j][prop];
                }
                copy.originKey = name;
                copy.originCount = group.items.length;
                result.push(copy);
            }
        }
        return result;
    }

    readonly property var displayedVulnerabilities: root.groupByOrigin
        ? root.groupedVulnerabilities
        : root.filteredVulnerabilities

    readonly property bool anyFilterActive: root.searchText.length > 0
        || root.severityBand.length > 0
        || root.filterSeverity.length > 0
        || root.filterCve.length > 0
        || root.filterPackage.length > 0
        || root.filterOrigin.length > 0
        || root.filterVersion.length > 0
        || root.filterVia.length > 0
        || root.filterMaster.length > 0
        || root.filterMasterState.length > 0
        || root.filterTracker.length > 0

    // Older status files wrote 0.0 when no CVSS score was available.
    function hasSeverityScore(severity) {
        return severity !== null && severity !== undefined && Number(severity) > 0;
    }

    function isCve(id) {
        return /^CVE-\d{4}-\d+$/.test(id || "");
    }

    function trackerApiUrl(item) {
        return root.trackerBase + "/api/v1/suggestions/by-cve/" + encodeURIComponent(item.id);
    }

    // "found" = tracker has a suggestion, "missing" = it answered but has no
    // linkage for this CVE, "unknown" = no scan-time tracker data (no token),
    // "none" = not a CVE (e.g. an OSV id).
    function trackerState(item) {
        // Read the revision so on-demand check results refresh row bindings.
        if (root.trackerRevision < 0) {
            return "none";
        }
        if (!item || !root.isCve(item.id)) {
            return "none";
        }
        if (item.tracker) {
            return item.tracker.found === false ? "missing" : "found";
        }
        if (root.trackerChecked[item.id] === true) {
            return "found";
        }
        if (root.trackerChecked[item.id] === false) {
            return "missing";
        }
        return "unknown";
    }

    function showTrackerHint(text) {
        root.trackerHint = text;
        trackerHintTimer.restart();
    }

    function openTracker(item) {
        var state = root.trackerState(item);
        if (state === "none") {
            return;
        }
        if (state === "missing") {
            root.showTrackerHint(i18n("%1 is not in the Nixpkgs security tracker; this finding may be a false positive.", item.id));
            return;
        }
        if (state === "found") {
            Qt.openUrlExternally(root.trackerUrl(item));
            return;
        }
        // A background post-scan check is already working through the CVEs;
        // avoid competing with it from the applet.
        if (root.trackerSummary && root.trackerSummary.complete === false) {
            root.showTrackerHint(i18n("The tracker check is still running; %1 will be checked shortly.", item.id));
            return;
        }
        // No scan-time tracker data (no API token): ask the public API once,
        // so a CVE without a tracker page does not open an empty page.
        root.showTrackerHint(i18n("Checking the Nixpkgs security tracker for %1…", item.id));
        executable.exec("curl -sS -o /dev/null -w '%{http_code}' --max-time 6 " + root.trackerApiUrl(item));
    }

    // Prefer the API-provided permalink (issue or suggestion page), but always
    // have the by-CVE tracker page as a fallback.
    function trackerUrl(item) {
        var state = root.trackerState(item);
        if (state === "none" || state === "missing") {
            return "";
        }
        if (item.tracker && item.tracker.url) {
            return item.tracker.url;
        }
        return root.trackerBase + "/suggestions/by-cve/" + encodeURIComponent(item.id);
    }

    function trackerStatusText(status) {
        switch (status) {
        case "published":
            return i18n("published");
        case "accepted":
            return i18n("accepted");
        case "pending":
            return i18n("pending review");
        case "rejected":
            return i18n("match rejected");
        default:
            return "";
        }
    }

    function trackerStatusColor(status) {
        switch (status) {
        case "published":
        case "accepted":
            return Kirigami.Theme.positiveTextColor;
        case "pending":
            return Kirigami.Theme.neutralTextColor;
        case "rejected":
            return Kirigami.Theme.disabledTextColor;
        default:
            return "transparent";
        }
    }

    function trackerTooltip(item) {
        var state = root.trackerState(item);
        if (!item || state === "none") {
            return "";
        }
        if (state === "missing") {
            return i18n("%1 is not in the Nixpkgs security tracker; this finding may be a false positive.", item.id);
        }
        if (state === "unknown") {
            return i18n("Check %1 in the Nixpkgs security tracker", item.id);
        }
        var tracker = item.tracker;
        var lines = [];
        if (tracker && tracker.issue) {
            lines.push(i18n("Nixpkgs security issue %1 (%2)",
                tracker.issue, root.trackerStatusText(tracker.status)));
        } else if (tracker && tracker.status) {
            lines.push(i18n("Nixpkgs security tracker: %1", root.trackerStatusText(tracker.status)));
        } else {
            lines.push(i18n("Open %1 in the Nixpkgs security tracker", item ? item.id : ""));
        }
        if (tracker && tracker.master_status === "unaffected") {
            lines.push(tracker.master_version
                ? i18n("nixpkgs master is unaffected (version %1)", tracker.master_version)
                : i18n("nixpkgs master is unaffected"));
        } else if (tracker && tracker.master_status === "affected") {
            lines.push(i18n("nixpkgs master is still affected"));
        }
        var fixLines = root.fixTooltipLines(item);
        for (var i = 0; i < fixLines.length; ++i) {
            lines.push(fixLines[i]);
        }
        if (tracker && tracker.status) {
            lines.push(i18n("Click to open the tracker"));
        }
        return lines.join("\n");
    }

    function severityBandOf(item) {
        var severity = item.severity;
        if (!root.hasSeverityScore(severity)) {
            return "unknown";
        }
        if (severity >= 9) {
            return "critical";
        }
        if (severity >= 7) {
            return "high";
        }
        if (severity >= 4) {
            return "medium";
        }
        return "low";
    }

    function severityBandColor(band) {
        switch (band) {
        case "critical":
            return root.criticalColor;
        case "high":
            return root.highColor;
        case "medium":
            return root.mediumColor;
        case "low":
            return root.lowColor;
        case "unknown":
            return root.unknownColor;
        default:
            return root.faintText;
        }
    }

    function severityColor(severity) {
        if (!root.hasSeverityScore(severity)) {
            return root.faintText;
        }
        if (severity >= 9) {
            return root.criticalColor;
        }
        if (severity >= 7) {
            return root.highColor;
        }
        if (severity >= 4) {
            return root.mediumColor;
        }
        return root.lowColor;
    }

    function severityText(severity) {
        return root.hasSeverityScore(severity) ? Number(severity).toFixed(1) : "—";
    }

    function confidenceLabel(value) {
        switch (value) {
        case "component_exact":
            return i18n("exact");
        case "component_expanded":
            return i18n("expanded");
        case "component_mixed":
            return i18n("mixed");
        case "package_version_only":
            return i18n("version only");
        default:
            return value || "—";
        }
    }

    function scannersLabel(scanners) {
        return (scanners && scanners.length) ? scanners.join(", ") : "—";
    }

    readonly property string masterHelpText: i18n("The Fix pill names the stage the fix currently sits in, and “fixed” once it reached the channel this system updates from (nixos-unstable or nixos-XX.YY):\n\n• fixed — the system's channel has a fixed version. Updating the channel fixes the finding.\n• staging — merged into staging-next/staging; it lands in master when the next staging cycle is merged.\n• master — master has it; the channel picks it up with the next channel bump (on a stable system a backport is still needed).\n• 26.05 — fixed on another line; it is not on the way to this system's channel.\n• issue — nothing is merged yet, but the Nixpkgs security issue is open.\n• no fix — still affected in every branch that was checked.\n• unknown / n/a / — — no verdict, no coverage, or no data.\n\nHover the Fix pill for the per-branch table (✓ fixed, ✗ affected, ? unknown), the next step, and ← marking the channel this system runs.")

    readonly property string confidenceHelpText: i18n("“Detected by” lists the scan engines that reported the finding and how closely each matched it to the installed package:\n\n• exact — the package and version/derivation match the vulnerability record exactly.\n• expanded — the component was found by expanding an SBOM or bundled component, so the match is indirect.\n• mixed — some scanners matched exactly and some by expansion.\n• version only — only the package name and version were matched; the exact derivation was not confirmed.\n\nvulnix scans Nix derivations; grype scans the SBOM and its components.")

    function confidenceDescription(value) {
        switch (value) {
        case "component_exact":
            return i18n("the package and version/derivation match the vulnerability record exactly");
        case "component_expanded":
            return i18n("the component was found by expanding an SBOM or bundled component, so the match is indirect");
        case "component_mixed":
            return i18n("some scanners matched exactly and some by expansion");
        case "package_version_only":
            return i18n("only the package name and version were matched; the exact derivation was not confirmed");
        default:
            return i18n("no confidence information is available");
        }
    }

    function viaShortText(item) {
        var lines = [i18n("Detected by: %1", root.scannersLabel(item.scanners))];
        if (item.confidence) {
            lines.push(i18n("Confidence: %1 — %2",
                root.confidenceLabel(item.confidence),
                root.confidenceDescription(item.confidence)));
        } else {
            lines.push(i18n("Confidence: not reported"));
        }
        if (item.patch_state) {
            lines.push(i18n("Patch state: %1", item.patch_state));
        }
        return lines.join("\n");
    }

    function viaLabel(item) {
        return root.scannersLabel(item.scanners)
            + (item.confidence ? " · " + root.confidenceLabel(item.confidence) : "");
    }

    // Dependency origin: the top-level package that pulls in the vulnerable
    // component. vulnscan-status.py derives this from vulnxscan's evidence
    // JSON and the runtime closure graph, so the table can answer "what
    // introduced this?" instead of only naming the vulnerable library.
    function originNames(item) {
        var origins = item ? item.origins : null;
        var names = origins ? origins.introduced_by : null;
        return (names && names.length) ? names : [];
    }

    function originName(item) {
        var names = root.originNames(item);
        return names.length > 0 ? names[0] : "";
    }

    function originCellText(item) {
        var names = root.originNames(item);
        if (names.length === 0) {
            return "—";
        }
        return names.length > 1
            ? i18n("%1 (+%2)", names[0], names.length - 1)
            : names[0];
    }

    function originChainText(item) {
        var origins = item ? item.origins : null;
        var chain = origins ? origins.chain : null;
        if (!chain || !chain.length) {
            return "";
        }
        // The backend can repeat a node (e.g. the top-level package appears
        // twice); collapse consecutive duplicates so the path stays readable.
        var parts = [];
        for (var i = 0; i < chain.length; ++i) {
            var node = String(chain[i] || "");
            if (node.length === 0 || (parts.length > 0 && parts[parts.length - 1] === node)) {
                continue;
            }
            parts.push(node);
        }
        // The last node is the vulnerable package itself; the row already
        // shows its version, so drop a trailing version/output suffix.
        if (item && item.package && item.version && parts.length > 0) {
            var last = parts[parts.length - 1];
            if (last.indexOf(item.package + "-") === 0 && last.indexOf(item.version) >= 0) {
                parts[parts.length - 1] = item.package;
            }
        }
        if (parts.length > 1 && parts[parts.length - 1] === parts[parts.length - 2]) {
            parts.pop();
        }
        // A chain that only names the vulnerable package adds nothing to the
        // package cell above it.
        if (parts.length === 1 && item && parts[0] === item.package) {
            return "";
        }
        return parts.join(" → ");
    }

    function originTooltip(item) {
        var origins = item ? item.origins : null;
        if (!origins || !origins.introduced_by || origins.introduced_by.length === 0) {
            return "";
        }
        var lines = [i18n("Introduced by: %1", origins.introduced_by.join(", "))];
        if (origins.chain && origins.chain.length > 0) {
            lines.push(i18n("Chain: %1", origins.chain.join(" → ")));
        }
        if (origins.chains && origins.chains.length > 1) {
            for (var i = 1; i < origins.chains.length && i < 3; ++i) {
                lines.push("  " + origins.chains[i].join(" → "));
            }
        }
        lines.push(i18n("Click an Origin value to show all findings from this package."));
        return lines.join("\n");
    }

    // Nixpkgs master branch state from the tracker suggestion. "unaffected"
    // means the fix is already in master; the URL points at the fix/bump
    // issue (GitHub) or the tracker page.
    function masterStatusOf(item) {
        if (!item || !item.tracker) {
            return "";
        }
        var status = item.tracker.master_status;
        if (status === "unaffected" || status === "affected" || status === "unknown") {
            return status;
        }
        if (item.tracker.found === true && item.tracker.status
                && item.tracker.status !== "rejected") {
            // The suggestion exists, but it has no branch for this package
            // (e.g. it covers haskellPackages.cpython while the finding is
            // python3), so there is no master verdict to show.
            return "unmatched";
        }
        return "";
    }

    // Fix data from the scan service: one row per nixpkgs ref that can carry
    // the fix (channels, master, staging, release branch), so the column can
    // answer "is it fixed, and where do I get it?".
    function fixRowsOf(item) {
        var tracker = item ? item.tracker : null;
        var rows = tracker ? tracker.fix_branches : null;
        return (rows && rows.length) ? rows : [];
    }

    function fixStateOf(item) {
        return (item && item.tracker && item.tracker.fix_state) || "";
    }

    function fixedRowWhere(item, predicate) {
        var rows = root.fixRowsOf(item);
        for (var i = 0; i < rows.length; ++i) {
            if (rows[i].state === "unaffected" && predicate(rows[i])) {
                return rows[i];
            }
        }
        return null;
    }

    function fixRowKind(item, kind) {
        return root.fixedRowWhere(item, function (row) {
            return row.kind === kind;
        });
    }

    function masterFixed(item) {
        return root.fixedRowWhere(item, function (row) {
            return row.name === "master";
        }) !== null;
    }

    function shortChannelName(name) {
        if (name === "nixos-unstable") {
            return i18n("unstable");
        }
        return name.indexOf("nixos-") === 0 ? name.substring("nixos-".length) : name;
    }

    function shortBranchName(name) {
        return name.indexOf("release-") === 0 ? name.substring("release-".length) : name;
    }

    function isUnstableSystem() {
        return root.systemChannel.length === 0
            || root.systemChannel === "nixos-unstable";
    }

    function shortRefName(name) {
        return name.indexOf("nixos-") === 0
            ? root.shortChannelName(name)
            : root.shortBranchName(name);
    }

    // Where an update gets the fix from, relative to the channel this system
    // runs: "fixed" only when *that* channel has it, otherwise where it is.
    // The Fix column names the stage the fix currently sits in; "fixed" means
    // it reached the channel this system updates from. The next step is in the
    // tooltip, so the column uses one vocabulary for every state.
    function fixText(item) {
        switch (root.fixStateOf(item)) {
        case "fixed":
            return i18n("fixed");
        case "in-staging":
            return i18n("staging");
        case "in-master":
            return i18n("master");
        case "in-release":
            return root.shortRefName(
                (item.tracker && item.tracker.fix_branch) || "");
        case "issue-open":
            return i18n("issue");
        }
        if (root.fixRowsOf(item).length > 0) {
            switch (root.masterStatusOf(item)) {
            case "unknown":
                return i18n("unknown");
            case "unmatched":
                return i18n("n/a");
            default:
                return i18n("no fix");
            }
        }
        return "";
    }

    // Which filter band a finding belongs to, and the colour/icon for it.
    function fixBucket(item) {
        switch (root.fixStateOf(item)) {
        case "fixed":
            return "fixed";
        case "in-master":
        case "in-staging":
        case "in-release":
        case "issue-open":
            return "progress";
        }
        // Older status files only carry the master verdict.
        if (root.fixRowsOf(item).length === 0
                && root.masterStatusOf(item) === "unaffected") {
            return "fixed";
        }
        switch (root.masterStatusOf(item)) {
        case "affected":
            return "none";
        case "unknown":
            return "unknown";
        case "unmatched":
            return "na";
        default:
            return "";
        }
    }

    function fixIconSource(item) {
        switch (root.fixBucket(item)) {
        case "fixed":
            return "checkmark";
        case "progress":
            return "go-next";
        case "none":
            return root.fixStateOf(item) === "issue-open"
                ? "dialog-information" : "dialog-error";
        case "unknown":
        case "na":
            return "help-about";
        default:
            return "";
        }
    }

    // Compact text for the Fix tooltip: the per-branch table plus the installed
    // version. The verbose tracker detail stays on the tracker button.
    function fixTooltipText(item) {
        var origin = root.originTooltip(item);
        var lines = root.fixTooltipLines(item);
        if (lines.length === 0) {
            var fallback = root.masterTooltip(item);
            if (origin.length === 0) {
                return fallback;
            }
            return fallback.length > 0 ? fallback + "\n\n" + origin : origin;
        }
        var text = [];
        if (item.version) {
            text.push(i18n("Installed version: %1", item.version));
        }
        if (root.systemChannel) {
            text.push(i18n("Your channel: %1", root.systemChannel));
        }
        var result = text.concat(lines);
        if (origin.length > 0) {
            result.push("");
            result.push(origin);
        }
        return result.join("\n");
    }

    function fixTooltipLines(item) {
        var rows = root.fixRowsOf(item);
        var lines = [];
        if (rows.length > 0) {
            lines.push(i18n("Fix status by nixpkgs branch:"));
            for (var i = 0; i < rows.length; ++i) {
                var row = rows[i];
                lines.push("  " + (row.state === "unaffected" ? "✓"
                    : (row.state === "affected" ? "✗" : "?")) + " "
                    + (row.version ? row.name + " " + row.version : row.name)
                    + (row.name === root.systemChannel ? "  ←" : ""));
            }
            switch (root.fixStateOf(item)) {
            case "in-staging":
                if (((item.tracker && item.tracker.fix_branch) || "") === "staging-next") {
                    lines.push(i18n("Next: master, at the end of the current staging cycle (staging-next is merged into master by PR)."));
                } else {
                    lines.push(i18n("In staging but not in staging-next yet: it misses the current cycle and joins the next one, then master."));
                }
                break;
            case "in-master":
                if (item.tracker && item.tracker.system_known === false) {
                    lines.push(i18n("The channel's package file has no plain version to compare, so whether %1 already carries it is unknown.", root.systemChannel));
                } else if (root.isUnstableSystem()) {
                    lines.push(i18n("Next: the nixos-unstable channel bump."));
                } else {
                    lines.push(i18n("Next: a backport to %1.", root.systemChannel));
                }
                break;
            case "in-release":
                lines.push(i18n("Not on the way to this system's channel; it is fixed on another line."));
                break;
            case "issue-open":
                lines.push(i18n("No fix merged yet."));
                break;
            }
            lines.push(i18n("Update to a branch marked ✓ to get the fix."));
            if (root.fixBucket(item) === "progress") {
                lines.push(i18n("Pending: the fix is merged, but no channel carries it yet."));
            }
            return lines;
        }
        switch (root.fixStateOf(item)) {
        case "fixed":
            lines.push(i18n("A fixed version is available in nixpkgs."));
            break;
        case "in-staging":
            lines.push(i18n("Merged into the nixpkgs staging branches; it lands in master with the next staging cycle."));
            break;
        case "in-release":
            lines.push(i18n("Backported to the release branch while master still carries the affected version."));
            break;
        case "issue-open":
            lines.push(i18n("No fix merged yet; the Nixpkgs security issue is open."));
            break;
        }
        return lines;
    }

    function masterStateMatches(item) {
        var filter = root.filterMasterState;
        if (!filter) {
            return true;
        }
        switch (filter) {
        case "fixed":
        case "progress":
        case "none":
        case "unknown":
        case "n/a":
            return root.fixBucket(item) === filter;
        default:
            return true;
        }
    }

    function trackerFilterMatches(item) {
        var filter = root.filterTracker;
        if (!filter) {
            return true;
        }
        var tracker = item ? item.tracker : null;
        var found = !!(tracker && tracker.found);
        switch (filter) {
        case "linked":
            return found;
        case "pending":
            return found && tracker.status === "pending";
        case "published":
            return found && tracker.status === "published";
        case "rejected":
            return found && tracker.status === "rejected";
        case "missing":
            return root.trackerState(item) === "missing";
        case "unknown":
            return root.trackerState(item) === "unknown";
        case "none":
        case "unchecked":
            return root.trackerState(item) === "none"
                || root.trackerState(item) === "unknown";
        default:
            return true;
        }
    }

    function filterBandCount(bands, key) {
        for (var i = 0; i < bands.length; ++i) {
            if (bands[i].key === key) {
                return bands[i].count;
            }
        }
        return 0;
    }

    function masterFilterColor(band) {
        switch (band) {
        case "fixed":
            return Kirigami.Theme.positiveTextColor;
        case "progress":
            return Kirigami.Theme.neutralTextColor;
        case "none":
            return Kirigami.Theme.negativeTextColor;
        // Grey, not amber: "unknown" is absence of a verdict, not progress.
        case "unknown":
        case "n/a":
            return Kirigami.Theme.disabledTextColor;
        case "":
            return Kirigami.Theme.textColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    function trackerFilterColor(band) {
        switch (band) {
        case "linked":
            return Kirigami.Theme.positiveTextColor;
        case "pending":
        case "missing":
            return Kirigami.Theme.neutralTextColor;
        case "":
            return Kirigami.Theme.textColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    function masterText(item) {
        if (root.fixRowsOf(item).length > 0) {
            return root.fixText(item);
        }
        // Older status files carry only the master verdict.
        switch (root.masterStatusOf(item)) {
        case "unaffected":
            return i18n("fixed");
        case "affected":
            return root.fixText(item).length > 0 ? root.fixText(item) : i18n("no fix");
        case "unknown":
            return i18n("unknown");
        case "unmatched":
            return i18n("n/a");
        default:
            return "—";
        }
    }

    // The row pill always gets a readable status; "—" means the backend did
    // not provide a fix verdict, so say that instead of hiding the column.
    function fixStatusText(item) {
        var text = root.masterText(item);
        return (text.length === 0 || text === "—") ? i18n("unknown") : text;
    }

    function masterColor(item) {
        switch (root.fixBucket(item)) {
        case "fixed":
            return Kirigami.Theme.positiveTextColor;
        case "progress":
            return Kirigami.Theme.neutralTextColor;
        case "none":
            return Kirigami.Theme.negativeTextColor;
        // "unknown" is "no information", not "in progress": keep it grey so it
        // cannot be confused with the amber pending rows.
        case "unknown":
        case "na":
            return Kirigami.Theme.disabledTextColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    function masterIconSource(item) {
        return root.fixIconSource(item);
    }

    function affectedProductsText(tracker) {
        var products = tracker ? (tracker.affected_products || []) : [];
        var parts = [];
        for (var i = 0; i < products.length; ++i) {
            var product = products[i];
            var constraints = [];
            var values = product.version_constraints || [];
            for (var j = 0; j < values.length; ++j) {
                if (values[j] && values[j].length >= 2) {
                    constraints.push(values[j][1]);
                }
            }
            parts.push((product.name || "?")
                + (constraints.length > 0 ? " (" + constraints.join(", ") + ")" : ""));
        }
        return parts.join(", ");
    }

    function masterFixUrl(item) {
        var tracker = item ? item.tracker : null;
        if (!tracker) {
            return "";
        }
        // The GitHub issue is the actual fix/bump discussion; the tracker
        // page is the fallback for pending suggestions.
        return tracker.github_issue_url || tracker.url || "";
    }

    function openMasterFix(item) {
        var url = root.masterFixUrl(item);
        if (url) {
            Qt.openUrlExternally(url);
        }
    }

    function masterTooltip(item) {
        var tracker = item ? item.tracker : null;
        if (!tracker) {
            return "";
        }
        var status = root.masterStatusOf(item);
        var version = tracker.master_version || i18n("unknown");
        var lines = [];
        if (status === "unaffected") {
            lines.push(i18n("Fixed in nixpkgs master (version %1)", version));
        } else if (status === "affected") {
            lines.push(i18n("Still affected in nixpkgs master (version %1)", version));
        } else if (status === "unknown") {
            lines.push(i18n("Nixpkgs master status unknown (version %1)", version));
        } else if (status === "unmatched") {
            lines.push(i18n("No nixpkgs master verdict for %1.", item.package || ""));
            var covered = tracker.suggestion_packages || [];
            if (covered.length > 0) {
                var shown = covered.slice(0, 6);
                lines.push(i18n("The tracker suggestion covers: %1%2",
                    shown.join(", "),
                    covered.length > 6
                        ? i18n(" (+%1 more)", covered.length - 6)
                        : ""));
            }
            var products = root.affectedProductsText(tracker);
            if (products.length > 0) {
                lines.push(i18n("CVE affected products: %1", products));
            }
            if (item.version) {
                lines.push(i18n("Your version: %1", item.version));
            }
            if (tracker.status) {
                lines.push(i18n("Tracker status: %1", root.trackerStatusText(tracker.status)));
            }
            if (root.masterFixUrl(item)) {
                lines.push(i18n("Click to open the suggestion"));
            }
            return lines.join("\n");
        } else {
            lines.push(i18n("No nixpkgs master data"));
        }
        var fixLines = root.fixTooltipLines(item);
        for (var i = 0; i < fixLines.length; ++i) {
            lines.push(fixLines[i]);
        }
        if (tracker.master_status_source === "version" && tracker.master_range) {
            if (status === "affected") {
                lines.push(i18n("Derived from the CVE's affected range (%1); the tracker has no master verdict.", tracker.master_range));
            } else if (status === "unaffected") {
                lines.push(i18n("Version %1 is outside the affected range (%2); derived from the CVE data.", version, tracker.master_range));
            }
        }
        if (tracker.issue) {
            lines.push(i18n("Security issue %1%2", tracker.issue,
                tracker.issue_state ? i18n(" (%1)", tracker.issue_state) : ""));
        }
        if (root.masterFixUrl(item)) {
            lines.push(i18n("Click to open the fix/bump"));
        }
        return lines.join("\n");
    }

    function defaultColumnWidths() {
        var result = {};
        for (var key in root.columnDefaults) {
            result[key] = root.columnDefaults[key];
        }
        return result;
    }

    function loadColumnWidths() {
        var result = root.defaultColumnWidths();
        var raw = String(Plasmoid.configuration.columnWidths || "");
        if (raw.length === 0) {
            return result;
        }
        try {
            var stored = JSON.parse(raw);
            if (stored && typeof stored === "object") {
                for (var key in result) {
                    var units = Number(stored[key]);
                    if (isFinite(units) && units >= root.columnMinimums[key]) {
                        result[key] = units;
                    }
                }
            }
        } catch (e) {
            console.warn("sentinel: cannot parse column widths:", e);
        }
        return result;
    }

    function setColumnWidth(key, units) {
        if (!root.columnDefaults.hasOwnProperty(key) || !isFinite(units)) {
            return;
        }
        var minimum = root.columnMinimums[key] || 3.0;
        var next = Math.max(minimum, Math.min(24.0, units));
        if (Math.abs(next - (root.columnWidths[key] || root.columnDefaults[key])) < 0.02) {
            return;
        }
        var copy = {};
        for (var name in root.columnWidths) {
            copy[name] = root.columnWidths[name];
        }
        copy[key] = next;
        root.columnWidths = copy;
    }

    function saveColumnWidths() {
        Plasmoid.configuration.columnWidths = JSON.stringify(root.columnWidths);
    }

    function resetColumnWidths() {
        root.columnWidths = root.defaultColumnWidths();
        root.saveColumnWidths();
        root.scrollToTopRequest += 1;
    }

    function columnWidth(key) {
        return root.columnPixels[key] || 0;
    }

    function sortArrow(key) {
        if (root.sortKey !== key) {
            return "↕";
        }
        return root.sortDescending ? "↓" : "↑";
    }

    function columnValue(item, key) {
        switch (key) {
        case "severity":
            return root.hasSeverityScore(item.severity) ? Number(item.severity) : -1;
        case "cve":
            return (item.id || "").toString();
        case "package":
            return (item.package || "").toString();
        case "origin":
            return root.originNames(item).join(" ") + " " + root.originChainText(item);
        case "version":
            return (item.version || "").toString();
        case "master":
            return root.masterText(item) + " "
                + ((item.tracker && item.tracker.master_version) || "");
        case "via":
            return root.viaLabel(item);
        default:
            return "";
        }
    }

    function filterFor(key) {
        switch (key) {
        case "severity":
            return root.filterSeverity;
        case "cve":
            return root.filterCve;
        case "package":
            return root.filterPackage;
        case "origin":
            return root.filterOrigin;
        case "version":
            return root.filterVersion;
        case "master":
            return root.filterMaster;
        case "via":
            return root.filterVia;
        default:
            return "";
        }
    }

    function setFilter(key, value) {
        switch (key) {
        case "severity":
            root.filterSeverity = value;
            break;
        case "cve":
            root.filterCve = value;
            break;
        case "package":
            root.filterPackage = value;
            break;
        case "origin":
            root.filterOrigin = value;
            break;
        case "version":
            root.filterVersion = value;
            break;
        case "master":
            root.filterMaster = value;
            break;
        case "via":
            root.filterVia = value;
            break;
        }
        root.scrollToTopRequest += 1;
    }

    function toggleSort(key) {
        if (root.sortKey === key) {
            root.sortDescending = !root.sortDescending;
        } else {
            root.sortKey = key;
            // Severity is most useful highest-first; text columns A-Z.
            root.sortDescending = (key === "severity");
        }
        root.scrollToTopRequest += 1;
    }

    function setSeverityBand(band) {
        root.severityBand = band;
        root.scrollToTopRequest += 1;
    }

    function setMasterStateFilter(state) {
        root.filterMasterState = state;
        root.scrollToTopRequest += 1;
    }

    function copyToClipboard(value) {
        if (!value) {
            return;
        }
        clipboardHelper.text = value;
        clipboardHelper.selectAll();
        clipboardHelper.copy();
        root.showTrackerHint(i18n("Copied %1 to the clipboard.", value));
    }

    function stampOf(value) {
        return (value && (value.scanned_at_iso || value.scanned_at)) || "";
    }

    // status.json is polled every few seconds. Assigning a freshly parsed
    // object unconditionally resets the ListView model, which destroys the row
    // delegates and with them any open tooltip — a hovered Master tooltip then
    // closes and reopens on every poll and cannot be read. Only rebuild the
    // rows when something they display actually changed; tracker progress is
    // kept in root.trackerData and updates on its own.
    function sameTracker(a, b) {
        if (!a || !b) {
            return !a === !b;
        }
        return a.found === b.found
            && a.status === b.status
            && a.issue === b.issue
            && a.issue_state === b.issue_state
            && a.master_status === b.master_status
            && a.master_version === b.master_version
            && a.master_status_source === b.master_status_source
            && a.master_range === b.master_range
            && a.fix_state === b.fix_state
            && a.fix_branch === b.fix_branch
            && a.fix_version === b.fix_version
            && a.github_issue_url === b.github_issue_url
            && a.url === b.url;
    }

    function sameVulnerabilities(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        for (var i = 0; i < a.length; ++i) {
            var x = a[i];
            var y = b[i];
            if (!x || !y
                    || x.id !== y.id
                    || x.package !== y.package
                    || x.version !== y.version
                    || x.severity !== y.severity
                    || x.url !== y.url
                    || x.patch_state !== y.patch_state
                    || x.confidence !== y.confidence
                    || root.scannersLabel(x.scanners) !== root.scannersLabel(y.scanners)
                    || root.originNames(x).join(",") !== root.originNames(y).join(",")
                    || root.originChainText(x) !== root.originChainText(y)
                    || !root.sameTracker(x.tracker, y.tracker)) {
                return false;
            }
        }
        return true;
    }

    function sameSeverityCounts(a, b) {
        var keys = ["critical", "high", "medium", "low", "unknown"];
        for (var i = 0; i < keys.length; ++i) {
            if (Number((a || {})[keys[i]] || 0) !== Number((b || {})[keys[i]] || 0)) {
                return false;
            }
        }
        return true;
    }

    // True when a new status.json has to replace the current one.
    function statusNeedsUpdate(parsed) {
        if (!root.haveStatus || !root.status) {
            return true;
        }
        var current = root.status;
        return root.stampOf(parsed) !== root.stampOf(current)
            || (parsed.state || "") !== (current.state || "")
            || Number(parsed.findings || 0) !== Number(current.findings || 0)
            || Number(parsed.max_severity || 0) !== Number(current.max_severity || 0)
            || Number(parsed.packages_affected || 0) !== Number(current.packages_affected || 0)
            || (parsed.error || "") !== (current.error || "")
            || !root.sameSeverityCounts(parsed.severity_counts, current.severity_counts)
            || !root.sameVulnerabilities(root.vulnerabilities,
                parsed.vulnerabilities || parsed.top || []);
    }

    // Apply a freshly read status.json. Tracker progress is always taken over;
    // the findings are only replaced when a row would look different, and not
    // at all while the pointer is over the list.
    function mergeStatus(parsed) {
        root.trackerData = parsed.tracker || null;
        if (!root.statusNeedsUpdate(parsed)) {
            return false;
        }
        if (root.listHovered && root.haveStatus
                && root.stampOf(parsed) === root.stampOf(root.status)) {
            // Tracker annotations arrived while a row tooltip is open; apply
            // them once the pointer leaves instead of rebuilding the rows now.
            root.deferredStatus = parsed;
            return false;
        }
        var restoreY = root.listContentY;
        root.status = parsed;
        root.haveStatus = true;
        root.restoreListY = restoreY;
        root.restoreListRequest += 1;
        return true;
    }

    function applyDeferredStatus() {
        var pending = root.deferredStatus;
        root.deferredStatus = null;
        if (pending) {
            root.mergeStatus(pending);
        }
    }

    // Options from contents/ui/configGeneral.qml.
    readonly property string badgeMode: Plasmoid.configuration.badgeMode || "count"

    Plasmoid.title: i18n("Sentinel")
    Plasmoid.icon: root.stateIcon
    Plasmoid.busy: root.scanning
    // The shell's default compact representation draws this with the same
    // badge the task manager and the battery applet use.
    badgeText: {
        if (!root.haveStatus || (root.state !== "vulnerable" && root.state !== "warn")) {
            return "";
        }
        switch (root.badgeMode) {
        case "none":
            return "";
        case "dot":
            return "•";
        default:
            return root.findings > 999
                ? i18nc("number of vulnerabilities", "999+")
                : i18nc("number of vulnerabilities", "%1", root.findings);
        }
    }

    toolTipMainText: Plasmoid.title
    toolTipSubText: {
        if (root.scanning) {
            return i18n("Scanning for vulnerabilities…");
        }
        return root.trackerSummaryText.length > 0
            ? root.stateDetail + "\n" + root.trackerSummaryText
            : root.stateDetail;
    }

    // Also reachable from the applet's context menu.
    Plasmoid.contextualActions: [
        PlasmaCore.Action {
            text: i18n("Scan for Vulnerabilities Now")
            icon.name: "view-refresh"
            enabled: !root.scanning
            onTriggered: root.startScan()
        },
        PlasmaCore.Action {
            text: i18n("Open Vulnerability Report")
            icon.name: "document-open"
            enabled: root.haveStatus
            onTriggered: root.openReport()
        },
        PlasmaCore.Action {
            text: i18n("Open Scan Log")
            icon.name: "text-x-generic"
            onTriggered: root.openLog()
        },
        PlasmaCore.Action {
            text: i18n("Open Nixpkgs Security Tracker")
            icon.name: "internet-services"
            onTriggered: Qt.openUrlExternally(root.trackerBase)
        }
    ]

    Plasma5Support.DataSource {
        id: executable
        engine: "executable"
        connectedSources: []

        onNewData: (sourceName, data) => {
            const exitCode = Number(data["exit code"] ?? 0);
            if (sourceName.indexOf("systemctl is-active") === 0) {
                const serviceState = String(data["stdout"] || "").trim();
                const active = serviceState === "active"
                    || serviceState === "activating"
                    || serviceState === "reloading"
                    || serviceState === "deactivating";
                root.scanServiceActive = active;
                if (active) {
                    if (!root.scanning) {
                        // Adopt a scan that was already running before the
                        // applet/plasmashell was restarted.
                        root.preScanStamp = root.haveStatus ? root.stampOf(root.status) : "";
                        root.scanning = true;
                        scanTimeout.restart();
                        root.scrollToTopRequest += 1;
                    }
                } else if (root.scanning) {
                    root.finishScan();
                }
                executable.disconnectSource(sourceName);
                return;
            }
            const trackerMatch = /\/api\/v1\/suggestions\/by-cve\/(CVE-\d{4}-\d+)/.exec(sourceName);
            if (sourceName.indexOf("curl ") === 0 && trackerMatch) {
                const cve = trackerMatch[1];
                const code = String(data["stdout"] || "").trim();
                if (code === "200") {
                    root.trackerChecked[cve] = true;
                    root.trackerRevision += 1;
                    root.trackerHint = "";
                    Qt.openUrlExternally(root.trackerBase + "/suggestions/by-cve/" + encodeURIComponent(cve));
                } else if (code === "404") {
                    root.trackerChecked[cve] = false;
                    root.trackerRevision += 1;
                    root.showTrackerHint(i18n("%1 is not in the Nixpkgs security tracker; this finding may be a false positive.", cve));
                } else if (code === "429") {
                    root.showTrackerHint(i18n("The Nixpkgs security tracker is rate-limiting requests; try again in a minute."));
                } else {
                    root.showTrackerHint(i18n("Could not check the Nixpkgs security tracker for %1.", cve));
                }
                executable.disconnectSource(sourceName);
                return;
            }
            if (sourceName.indexOf("cat ") === 0) {
                if (exitCode === 0) {
                    const raw = String(data["stdout"] || "");
                    // Skipping an unchanged file avoids reparsing and, more
                    // importantly, avoids resetting the list model under an
                    // open tooltip.
                    if (raw !== root.statusRaw) {
                        root.statusRaw = raw;
                        try {
                            const parsed = JSON.parse(raw);
                            root.mergeStatus(parsed);
                            const stamp = root.stampOf(parsed);
                            if (root.scanning && !root.scanServiceActive
                                    && stamp !== "" && stamp !== root.preScanStamp) {
                                root.finishScan();
                            }
                        } catch (e) {
                            console.warn("sentinel: cannot parse status.json:", e);
                        }
                    }
                }
            } else if (root.scanning && exitCode !== 0) {
                // systemctl could not start the scan (e.g. polkit denied).
                root.finishScan();
            }
            executable.disconnectSource(sourceName);
        }

        function exec(cmd) {
            if (cmd) {
                executable.connectSource(cmd);
            }
        }
    }

    function refresh() {
        executable.exec("cat " + root.statusFile + " 2>/dev/null");
    }

    function checkScanService() {
        executable.exec("systemctl is-active vulnscan.service 2>/dev/null");
    }

    function startScan() {
        if (root.scanning) {
            return;
        }
        root.preScanStamp = root.haveStatus ? root.stampOf(root.status) : "";
        root.scanning = true;
        root.scanServiceActive = true;
        scanTimeout.restart();
        root.refresh();
        executable.exec("systemctl start --no-block vulnscan.service");
    }

    function finishScan() {
        root.scanning = false;
        root.scanServiceActive = false;
        scanTimeout.stop();
        root.scrollToTopRequest += 1;
    }

    function openReport() {
        Qt.openUrlExternally("file://" + root.reportFile);
    }

    function openLog() {
        Qt.openUrlExternally("file://" + root.logFile);
    }

    function openVulnerability(item) {
        if (item && item.url) {
            Qt.openUrlExternally(item.url);
        }
    }

    Timer {
        // While the post-scan tracker check runs, follow its 3 s status writes
        // so the progress bar and Master column update live.
        interval: (root.trackerBusy && root.scanServiceActive) ? 3000 : 60000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: {
            root.refresh();
            root.checkScanService();
        }
    }

    // Poll faster while a scan is running so the result appears promptly.
    Timer {
        interval: 10000
        running: root.scanning
        repeat: true
        onTriggered: root.refresh()
    }

    // Keep the button/bar in sync with the real service, not just in-memory
    // state; this is what recovers the Scanning state after a shell restart.
    Timer {
        interval: 3000
        running: root.scanning
        repeat: true
        onTriggered: root.checkScanService()
    }

    // Matches the service's TimeoutStartSec: give up waiting, but keep polling
    // at the slow rate so a late result still shows up.
    Timer {
        id: scanTimeout
        interval: 150 * 60 * 1000
        onTriggered: root.finishScan()
    }

    Timer {
        interval: 30000
        running: true
        repeat: true
        onTriggered: root.clock = Date.now()
    }

    Timer {
        id: trackerHintTimer
        interval: 10000
        onTriggered: root.trackerHint = ""
    }


    TextEdit {
        id: clipboardHelper
        visible: false
    }

    fullRepresentation: PlasmaExtras.Representation {
        id: fullRoot

        // The pointer cannot hover a closed popup; flush any row update that
        // was deferred while a tooltip was open.
        onVisibleChanged: {
            if (!visible) {
                root.listHovered = false;
                root.fixTipItem = null;
                root.applyDeferredStatus();
            }
        }

        // Restore the scroll offset after a status/tracker refresh; jump to the
        // top only for explicit user actions (filters, sort, new scan).
        Timer {
            id: scrollToTopTimer
            interval: 0
            onTriggered: findingsList.positionViewAtBeginning()
        }

        Timer {
            id: restoreListTimer
            interval: 0
            onTriggered: findingsList.contentY = root.restoreListY
        }

        Connections {
            target: root

            function onScrollToTopRequestChanged() {
                scrollToTopTimer.restart();
            }

            function onRestoreListRequestChanged() {
                restoreListTimer.restart();
            }
        }

        function clearFilters() {
            // Move focus out of any text field so the bindings below can clear it.
            content.forceActiveFocus();
            root.searchText = "";
            root.filterSeverity = "";
            root.filterCve = "";
            root.filterPackage = "";
            root.filterOrigin = "";
            root.filterVersion = "";
            root.filterVia = "";
            root.filterMaster = "";
            root.filterMasterState = "";
            root.filterTracker = "";
            root.severityBand = "";
            root.scrollToTopRequest += 1;
        }

        // Narrow the table to a single package. Used by the package cell and
        // by the row menu; the external nixpkgs search is only a secondary
        // action.
        function showPackage(name) {
            if (!name) {
                return;
            }
            clearFilters();
            root.filterRowVisible = true;
            root.filterPackage = name;
            root.scrollToTopRequest += 1;
        }

        // Narrow the table to all findings introduced by one top-level package.
        // The Origin cell and its header use this; it is also how a user turns
        // "28 of these come from crossover" into a single filtered view.
        function showOrigin(name) {
            if (!name) {
                return;
            }
            clearFilters();
            root.filterRowVisible = true;
            root.filterOrigin = name;
            root.scrollToTopRequest += 1;
        }

        function setSeverity(band) {
            root.severityBand = band;
            root.scrollToTopRequest += 1;
        }

        Layout.minimumWidth: Kirigami.Units.gridUnit * 36
        Layout.preferredWidth: Kirigami.Units.gridUnit * 36
        Layout.minimumHeight: Kirigami.Units.gridUnit * 18
        // Tall, stable popup while findings exist so the list gets the
        // remaining space; content-driven otherwise.
        Layout.preferredHeight: root.hasFindings
            ? Kirigami.Units.gridUnit * 46
            : Kirigami.Units.gridUnit * 30

        // The summary cards need vertical room; below this threshold they
        // would overlap the table. Hide them (and the optional filter row) so
        // the header summary and the findings list stay usable when the popup
        // is resized very small.
        readonly property bool compactLayout: height < Kirigami.Units.gridUnit * 22

        header: PlasmaExtras.PlasmoidHeading {
            id: headerHeading
            // Keep the logo and the Settings button on the same outer edges
            // as the three summary cards.
            readonly property real cardsInset: (root.hasFindings && !root.compactLayout)
                ? Math.max(0, (width - content.cardsWidth) / 2)
                : Kirigami.Units.smallSpacing

            leftPadding: 0
            rightPadding: 0

            contentItem: Item {
                id: headerContent

                implicitHeight: headerRow.implicitHeight

                RowLayout {
                    id: headerRow

                    anchors.fill: parent
                    // Cancel the heading's own content margin so the row can
                    // start/end exactly at the cards' outer edges.
                    anchors.leftMargin: Math.max(0,
                        headerHeading.cardsInset - Kirigami.Units.smallSpacing
                        + Math.round(Kirigami.Units.gridUnit * 0.22))
                    anchors.rightMargin: Math.max(0,
                        headerHeading.cardsInset - Kirigami.Units.smallSpacing)
                    spacing: Kirigami.Units.smallSpacing

                Rectangle {
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 2
                    Layout.preferredHeight: Kirigami.Units.gridUnit * 2
                    radius: 10
                    color: root.primaryColor

                    Kirigami.Icon {
                        anchors.centerIn: parent
                        width: Math.round(parent.width * 0.55)
                        height: width
                        source: root.stateIcon
                        color: root.primaryText
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1

                    RowLayout {
                        spacing: Kirigami.Units.smallSpacing

                        PlasmaComponents3.Label {
                            text: i18n("Sentinel")
                            color: Kirigami.Theme.textColor
                            font.bold: true
                            font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.15)
                        }

                        Rectangle {
                            Layout.preferredWidth: headerPostureLabel.implicitWidth + Kirigami.Units.smallSpacing * 2
                            Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 0.95)
                            radius: 99
                            color: Qt.rgba(root.stateColor.r, root.stateColor.g, root.stateColor.b, 0.13)

                            PlasmaComponents3.Label {
                                id: headerPostureLabel

                                anchors.centerIn: parent
                                text: root.postureLabel
                                color: root.stateColor
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                font.bold: true
                            }
                        }
                    }

                    PlasmaComponents3.Label {
                        Layout.fillWidth: true
                        text: root.stateSummary
                        color: root.mutedText
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        elide: Text.ElideRight

                        HoverHandler {
                            id: detailHover
                        }

                        // The header buttons were removed; the help that used to
                        // live behind the About icon is available on this
                        // summary line. An error takes precedence.
                        QQC2.ToolTip.text: {
                            var parts = [];
                            if (root.state === "unknown" && root.status.error) {
                                parts.push(root.status.error);
                            }
                            parts.push(root.resultInfoText);
                            return parts.join("\n\n");
                        }
                        QQC2.ToolTip.visible: detailHover.hovered
                    }
                }

                PlasmaComponents3.Label {
                    text: root.lastScanLabel
                    visible: text.length > 0
                    color: root.mutedText
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize

                    HoverHandler {
                        id: lastScanHover
                    }

                    QQC2.ToolTip.text: root.lastScanTooltip
                    QQC2.ToolTip.visible: lastScanHover.hovered
                        && root.lastScanTooltip.length > 0
                }

                // One progress slot for both phases: the scanner has no
                // countable progress, so its bar animates; the tracker check
                // is determinate. If an old tracker state is still present
                // when a new scan starts, the scanner wins instead of showing
                // two indicators at once.
                Item {
                    id: headerProgress

                    // The indeterminate fill deliberately travels past both
                    // edges; clip it to the 4-unit track.
                    clip: true

                    readonly property bool indeterminate: (root.scanning && !root.trackerBusy)
                        || (root.trackerBusy && root.trackerProgressTotal <= 0)
                    readonly property real ratio: root.trackerProgressDone
                        / Math.max(1, root.trackerProgressTotal)

                    visible: root.scanning || (root.trackerBusy && root.scanServiceActive)
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 4
                    Layout.minimumWidth: Kirigami.Units.gridUnit * 4
                    Layout.maximumWidth: Kirigami.Units.gridUnit * 4
                    Layout.preferredHeight: Math.max(5,
                        Math.round(Kirigami.Units.gridUnit * 0.4))

                    property real sweepX: -width * 0.3

                    Rectangle {
                        anchors.fill: parent
                        radius: height / 2
                        color: root.hairline
                    }

                    Rectangle {
                        x: headerProgress.indeterminate ? headerProgress.sweepX : 0
                        width: headerProgress.indeterminate
                            ? Math.max(12, headerProgress.width * 0.3)
                            : Math.max(2, headerProgress.width * Math.min(1,
                                Math.max(0, headerProgress.ratio)))
                        height: parent.height
                        radius: height / 2
                        color: root.primaryColor
                    }

                    NumberAnimation on sweepX {
                        running: headerProgress.indeterminate
                        loops: Animation.Infinite
                        from: -headerProgress.width * 0.3
                        to: headerProgress.width
                        duration: 1400
                        easing.type: Easing.InOutSine
                    }

                    HoverHandler {
                        id: headerProgressHover
                    }

                    QQC2.ToolTip.text: root.scanning
                        ? i18n("Scanning for vulnerabilities…")
                        : root.trackerProgressText
                    QQC2.ToolTip.visible: headerProgressHover.hovered
                        && (root.scanning || root.trackerProgressText.length > 0)
                }

                Kirigami.Icon {
                    visible: !root.scanning
                        && !(root.trackerBusy && root.scanServiceActive)
                        && root.trackerProgressText.length > 0
                    source: "dialog-warning"
                    Layout.preferredWidth: Kirigami.Units.iconSizes.small
                    Layout.preferredHeight: Kirigami.Units.iconSizes.small
                    color: Kirigami.Theme.neutralTextColor

                    HoverHandler {
                        id: trackerWarningHover
                    }

                    QQC2.ToolTip.text: (root.trackerBusy && !root.scanServiceActive)
                        ? i18n("The last scan did not finish. Scan again to complete it.")
                        : root.trackerProgressText
                    QQC2.ToolTip.visible: trackerWarningHover.hovered
                        && (root.trackerBusy || root.trackerProgressText.length > 0)
                }

                QQC2.Button {
                    id: scanButton

                    text: (root.scanning || (root.trackerBusy && root.scanServiceActive))
                        ? i18n("Scanning…") : i18n("Scan now")
                    enabled: !root.scanning
                        && !(root.trackerBusy && root.scanServiceActive)
                    Layout.preferredHeight: Math.round(Kirigami.Units.gridUnit * 1.65)
                    leftPadding: Kirigami.Units.gridUnit * 0.7
                    rightPadding: Kirigami.Units.gridUnit * 0.7
                    topPadding: 0
                    bottomPadding: 0
                    onClicked: root.startScan()

                    contentItem: PlasmaComponents3.Label {
                        text: scanButton.text
                        color: root.primaryText
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        font.bold: true
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }

                    background: Rectangle {
                        radius: 8
                        color: scanButton.down ? Qt.darker(root.primaryColor, 1.08) : root.primaryColor
                        opacity: scanButton.enabled ? 1 : 0.55
                    }
                }

                PlasmaComponents3.ToolButton {
                    icon.name: "configure"
                    text: i18n("Settings")
                    display: QQC2.AbstractButton.IconOnly
                    onClicked: {
                        const action = Plasmoid.internalAction("configure");
                        if (action) {
                            action.trigger();
                        }
                    }

                    QQC2.ToolTip.text: i18n("Open the applet settings")
                    QQC2.ToolTip.visible: hovered
                }
            }
            }
        }

        contentItem: Item {
            ColumnLayout {
                id: content

                // Keep the search/table aligned with the three cards instead
                // of stretching them to the full popup width. In compact mode
                // the cards are hidden, so the table can use the full width.
                readonly property real cardsWidth: Kirigami.Units.gridUnit * (15.5 + 9.0 + 9.0)
                    + Kirigami.Units.gridUnit * 0.55 * 2
                readonly property real lowerWidth: root.hasFindings && !fullRoot.compactLayout
                    ? cardsWidth : width

                anchors.fill: parent
                anchors.margins: Kirigami.Units.largeSpacing
                spacing: Kirigami.Units.smallSpacing

                RowLayout {
                    Layout.fillWidth: false
                    Layout.preferredWidth: content.cardsWidth
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredHeight: Kirigami.Units.gridUnit * 8.2
                    Layout.maximumHeight: Kirigami.Units.gridUnit * 8.2
                    spacing: Kirigami.Units.gridUnit * 0.55
                    visible: root.hasFindings && !fullRoot.compactLayout

                    // Risk
                    Rectangle {
                        Layout.fillWidth: false
                        Layout.fillHeight: true
                        Layout.preferredWidth: Kirigami.Units.gridUnit * 15.5
                        radius: 16
                        color: root.cardColor
                        border.width: 1
                        border.color: root.cardBorder

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: Kirigami.Units.gridUnit * 0.4
                            spacing: Kirigami.Units.gridUnit * 0.5

                            Item {
                                Layout.preferredWidth: Kirigami.Units.gridUnit * 5.2
                                Layout.preferredHeight: Layout.preferredWidth

                                Shape {
                                    anchors.fill: parent

                                    ShapePath {
                                        strokeColor: root.hairline
                                        strokeWidth: 8
                                        fillColor: "transparent"
                                        PathAngleArc {
                                            centerX: Kirigami.Units.gridUnit * 2.6
                                            centerY: centerX
                                            radiusX: Kirigami.Units.gridUnit * 2.05
                                            radiusY: radiusX
                                            startAngle: -90
                                            sweepAngle: 360
                                        }
                                    }

                                    ShapePath {
                                        strokeColor: root.criticalColor
                                        strokeWidth: 8
                                        fillColor: "transparent"
                                        capStyle: ShapePath.RoundCap
                                        PathAngleArc {
                                            centerX: Kirigami.Units.gridUnit * 2.6
                                            centerY: centerX
                                            radiusX: Kirigami.Units.gridUnit * 2.05
                                            radiusY: radiusX
                                            startAngle: -90
                                            sweepAngle: 360 * 0.78
                                        }
                                    }
                                }

                                Column {
                                    anchors.centerIn: parent
                                    spacing: 1

                                    PlasmaComponents3.Label {
                                        anchors.horizontalCenter: parent.horizontalCenter
                                        text: root.maxSeverity > 0 ? root.maxSeverity.toFixed(1) : "—"
                                        color: Kirigami.Theme.textColor
                                        font.bold: true
                                        font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.35)
                                    }

                                    PlasmaComponents3.Label {
                                        anchors.horizontalCenter: parent.horizontalCenter
                                        text: i18n("CVSS")
                                        color: root.faintText
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 2)
                                    }
                                }
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 1

                                PlasmaComponents3.Label {
                                    text: i18n("CRITICAL EXPOSURE")
                                    color: root.criticalColor
                                    font.bold: true
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                                    font.letterSpacing: 0.6
                                }

                                PlasmaComponents3.Label {
                                    text: root.findings
                                    color: Kirigami.Theme.textColor
                                    font.bold: true
                                    font.pointSize: Math.round(Kirigami.Theme.defaultFont.pointSize * 1.65)
                                }

                                PlasmaComponents3.Label {
                                    text: i18n("potential vulnerabilities")
                                    color: root.mutedText
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                                }

                                RowLayout {
                                    spacing: Kirigami.Units.smallSpacing * 1.5

                                    PlasmaComponents3.Label {
                                        text: i18n("%1 packages", root.affectedPackages)
                                        color: root.mutedText
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                                    }

                                    PlasmaComponents3.Label {
                                        text: i18n("%1 CVEs", root.trackedCves)
                                        color: root.mutedText
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                                    }
                                }
                            }
                        }
                    }

                    // Severity
                    Rectangle {
                        Layout.fillWidth: false
                        Layout.fillHeight: true
                        Layout.preferredWidth: Kirigami.Units.gridUnit * 9.0
                        radius: 16
                        color: root.severitySurface
                        border.width: 1
                        border.color: root.cardBorder

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: Kirigami.Units.gridUnit * 0.4
                            spacing: 4

                            PlasmaComponents3.Label {
                                text: i18n("SEVERITY")
                                color: root.mutedText
                                font.bold: true
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                                font.letterSpacing: 0.6
                            }

                            Row {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 9
                                spacing: 2

                                Repeater {
                                    model: root.severityBands.slice(1)

                                    Rectangle {
                                        width: Math.max(2, (parent.width - 8) * modelData.count / Math.max(1, root.findings))
                                        height: 9
                                        radius: 2
                                        color: root.severityBandColor(modelData.key)
                                    }
                                }
                            }

                            GridLayout {
                                Layout.fillWidth: true
                                columns: 1
                                columnSpacing: Kirigami.Units.smallSpacing
                                rowSpacing: 2

                                Repeater {
                                    model: root.severityBands.slice(1)

                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 16
                                        radius: 4
                                        color: root.severityBand === modelData.key ? root.rowHover : "transparent"

                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 3
                                            anchors.rightMargin: 3
                                            spacing: 4

                                            Rectangle {
                                                Layout.preferredWidth: 7
                                                Layout.preferredHeight: 7
                                                radius: 2
                                                color: root.severityBandColor(modelData.key)
                                            }

                                            PlasmaComponents3.Label {
                                                Layout.fillWidth: true
                                                text: modelData.label
                                                color: root.mutedText
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                                elide: Text.ElideRight
                                            }

                                            PlasmaComponents3.Label {
                                                text: modelData.count
                                                color: Kirigami.Theme.textColor
                                                font.bold: true
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                            }
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: setSeverity(modelData.key)
                                        }
                                    }
                                }
                            }

                        }
                    }

                    // Fixes
                    Rectangle {
                        Layout.fillWidth: false
                        Layout.fillHeight: true
                        Layout.preferredWidth: Kirigami.Units.gridUnit * 9.0
                        radius: 16
                        color: root.fixesSurface
                        border.width: 1
                        border.color: root.cardBorder

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: Kirigami.Units.gridUnit * 0.4
                            spacing: 4

                            PlasmaComponents3.Label {
                                text: i18n("READY TO FIX")
                                color: root.mutedText
                                font.bold: true
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                                font.letterSpacing: 0.6
                            }

                            Item {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 9

                                Row {
                                    id: fixStateBar

                                    anchors.fill: parent
                                    spacing: 2

                                    Repeater {
                                        model: root.masterFilterBands.slice(1)

                                        Rectangle {
                                            width: Math.max(2, (fixStateBar.width - 8)
                                                * modelData.count
                                                / Math.max(1, root.fixStateTotal))
                                            height: 9
                                            radius: 2
                                            color: root.masterFilterColor(modelData.key)
                                        }
                                    }
                                }
                            }

                            GridLayout {
                                Layout.fillWidth: true
                                columns: 1
                                columnSpacing: Kirigami.Units.smallSpacing
                                rowSpacing: 2

                                Repeater {
                                    model: root.masterFilterBands.slice(1)

                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 16
                                        radius: 4
                                        color: root.filterMasterState === modelData.key
                                            ? root.rowHover : "transparent"

                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 3
                                            anchors.rightMargin: 3
                                            spacing: 4

                                            Rectangle {
                                                Layout.preferredWidth: 7
                                                Layout.preferredHeight: 7
                                                radius: 2
                                                color: root.masterFilterColor(modelData.key)
                                            }

                                            PlasmaComponents3.Label {
                                                Layout.fillWidth: true
                                                text: modelData.key === "fixed"
                                                    ? i18n("Fixed")
                                                    : (modelData.key === "progress"
                                                        ? i18n("Pending")
                                                        : modelData.label)
                                                color: root.mutedText
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                                elide: Text.ElideRight
                                            }

                                            PlasmaComponents3.Label {
                                                text: modelData.count
                                                color: modelData.key === "fixed"
                                                    ? Kirigami.Theme.positiveTextColor
                                                    : Kirigami.Theme.textColor
                                                font.bold: true
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                            }
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.setMasterStateFilter(modelData.key)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // One compact toolbar: search, filters and origin grouping.
                // The old column header/filter rows duplicated information and
                // are gone; severity is conveyed by the row colour.
                RowLayout {
                    Layout.fillWidth: false
                    Layout.preferredWidth: content.lowerWidth
                    Layout.maximumWidth: content.lowerWidth
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Kirigami.Units.smallSpacing
                    visible: root.hasFindings

                    Kirigami.SearchField {
                        id: searchField

                        Layout.fillWidth: true
                        Layout.minimumWidth: Kirigami.Units.gridUnit * 7
                        placeholderText: i18n("Search…")

                        Binding on text {
                            value: root.searchText
                            when: !searchField.activeFocus
                            restoreMode: Binding.RestoreNone
                        }

                        onTextChanged: {
                            if (text !== root.searchText) {
                                root.searchText = text;
                            }
                        }

                        onAccepted: {
                            root.scrollToTopRequest += 1;
                            searchField.focus = false;
                        }
                    }

                    PlasmaComponents3.ToolButton {
                        id: filtersButton

                        text: i18n("Filters")
                        icon.name: "view-filter"
                        display: QQC2.AbstractButton.TextBesideIcon
                        onClicked: filtersMenu.popup(filtersButton, 0, filtersButton.height)

                        QQC2.ToolTip.text: i18n("Filter by severity or fix state")
                        QQC2.ToolTip.visible: hovered
                    }

                    QQC2.Menu {
                        id: filtersMenu

                        QQC2.MenuItem {
                            text: i18n("All severities")
                            checkable: true
                            checked: root.severityBand === ""
                            onTriggered: root.setSeverityBand("")
                        }
                        QQC2.MenuItem {
                            text: i18n("Critical")
                            checkable: true
                            checked: root.severityBand === "critical"
                            onTriggered: root.setSeverityBand("critical")
                        }
                        QQC2.MenuItem {
                            text: i18n("High")
                            checkable: true
                            checked: root.severityBand === "high"
                            onTriggered: root.setSeverityBand("high")
                        }
                        QQC2.MenuItem {
                            text: i18n("Medium")
                            checkable: true
                            checked: root.severityBand === "medium"
                            onTriggered: root.setSeverityBand("medium")
                        }
                        QQC2.MenuItem {
                            text: i18n("Low")
                            checkable: true
                            checked: root.severityBand === "low"
                            onTriggered: root.setSeverityBand("low")
                        }
                        QQC2.MenuItem {
                            text: i18n("Unknown severity")
                            checkable: true
                            checked: root.severityBand === "unknown"
                            onTriggered: root.setSeverityBand("unknown")
                        }

                        QQC2.MenuSeparator {}

                        QQC2.MenuItem {
                            text: i18n("All fix states")
                            checkable: true
                            checked: root.filterMasterState === ""
                            onTriggered: root.setMasterStateFilter("")
                        }
                        QQC2.MenuItem {
                            text: i18n("Fix available")
                            checkable: true
                            checked: root.filterMasterState === "fixed"
                            onTriggered: root.setMasterStateFilter("fixed")
                        }
                        QQC2.MenuItem {
                            text: i18n("Fix pending")
                            checkable: true
                            checked: root.filterMasterState === "progress"
                            onTriggered: root.setMasterStateFilter("progress")
                        }
                        QQC2.MenuItem {
                            text: i18n("No fix")
                            checkable: true
                            checked: root.filterMasterState === "none"
                            onTriggered: root.setMasterStateFilter("none")
                        }
                        QQC2.MenuItem {
                            text: i18n("Unknown fix state")
                            checkable: true
                            checked: root.filterMasterState === "unknown"
                            onTriggered: root.setMasterStateFilter("unknown")
                        }
                        QQC2.MenuItem {
                            text: i18n("n/a")
                            checkable: true
                            checked: root.filterMasterState === "n/a"
                            onTriggered: root.setMasterStateFilter("n/a")
                        }

                        QQC2.MenuSeparator {}

                        QQC2.MenuItem {
                            text: i18n("Clear filters")
                            icon.name: "edit-clear-all"
                            enabled: root.anyFilterActive
                            onTriggered: clearFilters()
                        }
                    }

                    PlasmaComponents3.ToolButton {
                        id: groupByButton

                        // The icon shows the current view: the list icon in
                        // flat mode, the grouped/tree icon in origin mode.
                        icon.name: root.groupByOrigin
                            ? "view-list-tree"
                            : "view-list-details"
                        text: root.groupByOrigin
                            ? i18n("Show flat list")
                            : i18n("Group by origin")
                        display: QQC2.AbstractButton.IconOnly
                        onClicked: {
                            root.groupByOrigin = !root.groupByOrigin;
                            root.scrollToTopRequest += 1;
                        }

                        QQC2.ToolTip.text: root.groupByOrigin
                            ? i18n("Show the flat findings list")
                            : i18n("Group findings by the package that introduced them")
                        QQC2.ToolTip.visible: hovered
                    }

                    PlasmaComponents3.ToolButton {
                        icon.name: "edit-clear-all"
                        text: i18n("Clear filters")
                        display: QQC2.AbstractButton.IconOnly
                        visible: root.anyFilterActive
                        onClicked: clearFilters()

                        QQC2.ToolTip.text: i18n("Clear the search and filters")
                        QQC2.ToolTip.visible: hovered
                    }

                    PlasmaComponents3.Label {
                        text: i18n("%1 of %2", root.filteredVulnerabilities.length, root.vulnerabilities.length)
                        opacity: 0.7
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                    }
                }

                Rectangle {
                    id: listContainer

                    Layout.fillWidth: false
                    Layout.preferredWidth: content.lowerWidth
                    Layout.maximumWidth: content.lowerWidth
                    Layout.alignment: Qt.AlignHCenter
                    Layout.fillHeight: true
                    // Let the list shrink instead of forcing the whole column
                    // past the popup height when the window is very short.
                    Layout.minimumHeight: 0
                    visible: root.hasFindings
                    color: root.cardColor
                    radius: 12
                    border.width: 1
                    border.color: root.cardBorder

                    // One Plasma-themed tooltip for the whole list. It is not
                    // attached to a row, so rebuilding the rows (every few
                    // seconds while the tracker reports) cannot close it.
                    PlasmaComponents3.ToolTip {
                        id: fixToolTip

                        text: root.fixTipItem ? root.fixTooltipText(root.fixTipItem) : ""
                        visible: root.fixTipItem !== null && text.length > 0
                        x: Math.max(4, Math.min(root.fixTipX,
                            fullRoot.width - implicitWidth - 4))
                        y: (root.fixTipYBelow + implicitHeight + 4 > fullRoot.height)
                            ? Math.max(4, root.fixTipYAbove - implicitHeight - 4)
                            : root.fixTipYBelow
                    }

                    HoverHandler {
                        id: listHoverHandler

                        onHoveredChanged: {
                            root.listHovered = hovered;
                            if (!hovered) {
                                root.fixTipItem = null;
                                root.applyDeferredStatus();
                            }
                        }
                    }

                    // Compact, fixed column titles. Click a title to sort; the
                    // arrow marks the active sort key and direction.
                    RowLayout {
                        id: listHeader

                        anchors.top: parent.top
                        anchors.left: parent.left
                        anchors.right: parent.right
                        height: Math.max(Kirigami.Units.gridUnit * 1.3,
                            Kirigami.Theme.smallFont.pointSize
                                + Kirigami.Units.smallSpacing * 2)
                        spacing: Kirigami.Units.smallSpacing

                        Item {
                            Layout.preferredWidth: Kirigami.Units.smallSpacing + 3
                        }

                        Repeater {
                            model: root.listHeaderColumns

                            delegate: Item {
                                Layout.preferredWidth: modelData.fill ? 0 : modelData.width
                                Layout.minimumWidth: modelData.fill ? 0 : modelData.width
                                Layout.fillWidth: modelData.fill
                                implicitHeight: headerTitle.implicitHeight

                                PlasmaComponents3.Label {
                                    id: headerTitle

                                    anchors.left: parent.left
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    horizontalAlignment: modelData.align === "center"
                                        ? Text.AlignHCenter : Text.AlignLeft
                                    text: modelData.label + " " + root.sortArrow(modelData.key)
                                    color: root.sortKey === modelData.key
                                        ? Kirigami.Theme.textColor
                                        : root.faintText
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Math.max(6,
                                        Kirigami.Theme.smallFont.pointSize - 1)
                                    font.bold: root.sortKey === modelData.key
                                    elide: Text.ElideRight
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.toggleSort(modelData.key)

                                    QQC2.ToolTip.text: root.sortKey === modelData.key
                                        ? (root.sortDescending
                                            ? i18n("Sorted descending — click for ascending")
                                            : i18n("Sorted ascending — click for descending"))
                                        : i18n("Sort by %1", modelData.label)
                                    QQC2.ToolTip.visible: containsMouse
                                }
                            }
                        }

                        Item {
                            Layout.preferredWidth: findingsList.rightMargin
                        }
                    }

                    Rectangle {
                        id: listHeaderRule

                        anchors.top: listHeader.bottom
                        anchors.left: parent.left
                        anchors.right: parent.right
                        height: 1
                        color: root.hairline
                    }

                    Component {
                        id: originSection

                        Item {
                            width: findingsList.width - findingsList.rightMargin
                            height: sectionHeader.implicitHeight + Kirigami.Units.smallSpacing * 2

                            Rectangle {
                                anchors.fill: parent
                                anchors.topMargin: Kirigami.Units.smallSpacing
                                radius: 6
                                color: root.inputBackground
                            }

                            RowLayout {
                                id: sectionHeader

                                anchors.fill: parent
                                anchors.leftMargin: Kirigami.Units.smallSpacing * 2
                                anchors.rightMargin: Kirigami.Units.smallSpacing * 2
                                spacing: Kirigami.Units.smallSpacing

                                PlasmaComponents3.Label {
                                    text: "◈"
                                    color: root.primaryColor
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                                }

                                PlasmaComponents3.Label {
                                    Layout.fillWidth: true
                                    text: section
                                    color: Kirigami.Theme.textColor
                                    font.bold: true
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                                    elide: Text.ElideRight
                                }

                                PlasmaComponents3.Label {
                                    text: i18np("%1 finding", "%1 findings", root.originGroupCount(section))
                                    color: root.mutedText
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                                }
                            }
                        }
                    }

                    ListView {
                        id: findingsList

                        anchors.top: listHeaderRule.bottom
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        clip: true
                        spacing: 0
                        boundsBehavior: Flickable.StopAtBounds
                        model: root.displayedVulnerabilities
                        section.property: root.groupByOrigin ? "originKey" : ""
                        section.criteria: ViewSection.FullString
                        section.delegate: originSection
                        onContentYChanged: root.listContentY = contentY

                        // Plasma scroll bars are overlays: reserve their width
                        // so they cannot cover the fix pill.
                        rightMargin: scrollBar.visible ? scrollBar.width + Kirigami.Units.smallSpacing * 2 : 0

                        QQC2.ScrollBar.vertical: PlasmaComponents3.ScrollBar {
                            id: scrollBar
                            policy: QQC2.ScrollBar.AlwaysOn
                        }

                        delegate: PlasmaComponents3.ItemDelegate {
                            id: findingItem

                            width: ListView.view.width - ListView.view.rightMargin
                            // Keep one-line rows (no origin chain) as tall as
                            // two-line rows so spacing and the click target
                            // stay consistent.
                            height: Math.max(contentItem.implicitHeight
                                    + topPadding + bottomPadding,
                                Kirigami.Units.gridUnit * 2.4)
                            // The 3 px severity strip paints over the leading
                            // edge; include it so the score has equal space on
                            // both sides of its column.
                            leftPadding: Kirigami.Units.smallSpacing + 3
                            rightPadding: Kirigami.Units.smallSpacing
                            topPadding: Kirigami.Units.smallSpacing
                            bottomPadding: Kirigami.Units.smallSpacing
                            hoverEnabled: true
                            onClicked: root.openVulnerability(modelData)

                            background: Rectangle {
                                color: findingItem.hovered ? root.rowHover : "transparent"

                                Rectangle {
                                    anchors.left: parent.left
                                    anchors.top: parent.top
                                    anchors.bottom: parent.bottom
                                    width: 3
                                    color: root.severityColor(modelData.severity)
                                }

                                Rectangle {
                                    anchors.left: parent.left
                                    anchors.right: parent.right
                                    anchors.bottom: parent.bottom
                                    height: 1
                                    color: root.hairline
                                    visible: index < findingsList.count - 1
                                }
                            }

                            Accessible.name: i18n("%1 in %2, severity %3",
                                modelData.id || i18n("unknown CVE"),
                                modelData.package || i18n("unknown package"),
                                root.severityText(modelData.severity))
                            Accessible.description: root.originChainText(modelData)

                            contentItem: ColumnLayout {
                                spacing: 1

                                // 02 and 04 share this first line. The flat view
                                // adds the origin chain underneath; the grouped
                                // view gets the origin from the section header.
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Kirigami.Units.smallSpacing

                                    PlasmaComponents3.Label {
                                        Layout.preferredWidth: Kirigami.Units.gridUnit * 2
                                        Layout.minimumWidth: Kirigami.Units.gridUnit * 2
                                        Layout.maximumWidth: Kirigami.Units.gridUnit * 2
                                        horizontalAlignment: Text.AlignHCenter
                                        text: root.severityText(modelData.severity)
                                        color: root.severityColor(modelData.severity)
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                                        font.bold: root.hasSeverityScore(modelData.severity)
                                            && modelData.severity >= 7
                                    }

                                    PlasmaComponents3.Label {
                                        id: cveLabel

                                        Layout.preferredWidth: Kirigami.Units.gridUnit * 8.5
                                        Layout.minimumWidth: Kirigami.Units.gridUnit * 8.5
                                        Layout.maximumWidth: Kirigami.Units.gridUnit * 8.5
                                        text: modelData.id || "—"
                                        color: modelData.url ? Kirigami.Theme.linkColor : Kirigami.Theme.textColor
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                                        font.underline: cveHover.hovered && !!modelData.url
                                        elide: Text.ElideRight

                                        HoverHandler {
                                            id: cveHover
                                            cursorShape: modelData.url ? Qt.PointingHandCursor : Qt.ArrowCursor
                                        }

                                        QQC2.ToolTip.text: modelData.url
                                            ? i18n("Open %1 in the vulnerability database", modelData.id)
                                            : modelData.id
                                        QQC2.ToolTip.visible: cveHover.hovered
                                    }

                                    Item {
                                        Layout.fillWidth: true
                                        implicitHeight: packageRow.implicitHeight

                                        RowLayout {
                                            id: packageRow

                                            anchors.fill: parent
                                            spacing: Kirigami.Units.smallSpacing

                                            PlasmaComponents3.Label {
                                                text: modelData.package || "—"
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                                font.bold: true
                                                elide: Text.ElideRight
                                            }

                                            PlasmaComponents3.Label {
                                                text: modelData.version || ""
                                                visible: text.length > 0
                                                color: root.mutedText
                                                font.family: Kirigami.Theme.smallFont.family
                                                font.pointSize: Kirigami.Theme.smallFont.pointSize
                                                elide: Text.ElideRight
                                            }

                                            Item {
                                                Layout.fillWidth: true
                                            }
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            hoverEnabled: true
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: showPackage(modelData.package)

                                            QQC2.ToolTip.text: modelData.package
                                                ? i18n("Show all findings for %1", modelData.package)
                                                : ""
                                            QQC2.ToolTip.visible: containsMouse
                                                && (modelData.package || "").length > 0
                                        }
                                    }

                                    Rectangle {
                                        id: fixPill

                                        readonly property color tone: root.masterColor(modelData)

                                        visible: fixPillLabel.text.length > 0
                                        Layout.preferredHeight: fixPillLabel.implicitHeight
                                            + Kirigami.Units.smallSpacing
                                        Layout.preferredWidth: root.fixPillWidth
                                        Layout.minimumWidth: root.fixPillWidth
                                        Layout.maximumWidth: root.fixPillWidth
                                        radius: 99
                                        color: Qt.rgba(tone.r, tone.g, tone.b,
                                            root.darkMode ? 0.18 : 0.10)
                                        border.width: 1
                                        border.color: Qt.rgba(tone.r, tone.g, tone.b,
                                            root.darkMode ? 0.55 : 0.45)

                                        PlasmaComponents3.Label {
                                            id: fixPillLabel

                                            anchors.centerIn: parent
                                            text: root.fixStatusText(modelData)
                                            color: fixPill.tone
                                            font.family: Kirigami.Theme.smallFont.family
                                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                                        }

                                        MouseArea {
                                            anchors.fill: parent
                                            hoverEnabled: true
                                            cursorShape: root.masterFixUrl(modelData)
                                                ? Qt.PointingHandCursor
                                                : Qt.ArrowCursor
                                            onClicked: root.openMasterFix(modelData)

                                            QQC2.ToolTip.text: root.fixTooltipText(modelData)
                                            QQC2.ToolTip.visible: containsMouse
                                                && QQC2.ToolTip.text.length > 0
                                        }
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    Layout.leftMargin: Kirigami.Units.gridUnit * 2
                                        + Kirigami.Units.smallSpacing
                                    spacing: Kirigami.Units.smallSpacing
                                    visible: !root.groupByOrigin
                                        && root.originChainText(modelData).length > 0

                                    PlasmaComponents3.Label {
                                        text: "↳"
                                        color: root.faintText
                                        font.family: Kirigami.Theme.smallFont.family
                                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                                    }

                                    Item {
                                        Layout.fillWidth: true
                                        implicitHeight: chainLabel.implicitHeight

                                        PlasmaComponents3.Label {
                                            id: chainLabel

                                            anchors.left: parent.left
                                            anchors.right: parent.right
                                            anchors.verticalCenter: parent.verticalCenter
                                            text: root.originChainText(modelData)
                                            color: root.mutedText
                                            font.family: Kirigami.Theme.smallFont.family
                                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                                            elide: Text.ElideRight
                                        }

                                        HoverHandler {
                                            id: chainHover
                                            cursorShape: Qt.PointingHandCursor
                                        }

                                        QQC2.ToolTip.text: root.originTooltip(modelData)
                                        QQC2.ToolTip.visible: chainHover.hovered
                                            && QQC2.ToolTip.text.length > 0

                                        MouseArea {
                                            anchors.fill: parent
                                            onClicked: showOrigin(root.originName(modelData))
                                        }
                                    }
                                }
                            }

                            TapHandler {
                                acceptedButtons: Qt.RightButton
                                onTapped: rowMenu.popup()
                            }

                            QQC2.Menu {
                                id: rowMenu

                                QQC2.MenuItem {
                                    text: i18n("Show all findings for %1", modelData.package || "")
                                    icon.name: "view-filter"
                                    enabled: !!modelData.package
                                    onTriggered: showPackage(modelData.package)
                                }
                                QQC2.MenuItem {
                                    text: i18n("Filter by origin")
                                    icon.name: "view-filter"
                                    enabled: root.originNames(modelData).length > 0
                                    onTriggered: showOrigin(root.originName(modelData))
                                }
                                QQC2.MenuItem {
                                    text: i18n("Open in Nixpkgs security tracker")
                                    icon.name: "internet-services"
                                    enabled: root.trackerState(modelData) !== "none"
                                    onTriggered: root.openTracker(modelData)
                                }
                                QQC2.MenuItem {
                                    text: i18n("Open master fix/bump")
                                    icon.name: "internet-services"
                                    enabled: root.masterFixUrl(modelData) !== ""
                                    onTriggered: root.openMasterFix(modelData)
                                }
                                QQC2.MenuItem {
                                    text: i18n("Open nixpkgs master source")
                                    icon.name: "document-open"
                                    enabled: !!(modelData.tracker && modelData.tracker.master_url)
                                    onTriggered: Qt.openUrlExternally(modelData.tracker.master_url)
                                }
                                QQC2.MenuSeparator {}
                                QQC2.MenuItem {
                                    text: i18n("Copy CVE ID")
                                    icon.name: "edit-copy"
                                    enabled: !!modelData.id
                                    onTriggered: root.copyToClipboard(modelData.id || "")
                                }
                                QQC2.MenuItem {
                                    text: i18n("Copy package name")
                                    icon.name: "edit-copy"
                                    enabled: !!modelData.package
                                    onTriggered: root.copyToClipboard(modelData.package || "")
                                }
                                QQC2.MenuItem {
                                    text: i18n("Copy fix/bump URL")
                                    icon.name: "edit-copy"
                                    enabled: root.masterFixUrl(modelData) !== ""
                                    onTriggered: root.copyToClipboard(root.masterFixUrl(modelData))
                                }
                                QQC2.MenuItem {
                                    text: i18n("Search nixpkgs unstable for %1", modelData.package || "")
                                    icon.name: "edit-find"
                                    enabled: !!modelData.package
                                    onTriggered: Qt.openUrlExternally("https://search.nixos.org/packages?channel=unstable&query=" + encodeURIComponent(modelData.package || ""))
                                }
                            }
                        }

                        PlasmaComponents3.Label {
                            anchors.centerIn: parent
                            width: parent.width - Kirigami.Units.gridUnit * 2
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            visible: root.filteredVulnerabilities.length === 0
                            text: i18n("No vulnerabilities match your search or filters.")
                            opacity: 0.7
                            font.family: Kirigami.Theme.smallFont.family
                            font.pointSize: Kirigami.Theme.smallFont.pointSize
                        }
                    }
                }

                Item {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.minimumHeight: 0
                    visible: !root.hasFindings

                    PlasmaExtras.PlaceholderMessage {
                        anchors.centerIn: parent
                        width: parent.width - Kirigami.Units.gridUnit * 4

                        iconName: root.emptyIcon
                        text: root.emptyTitle
                        explanation: root.emptyExplanation
                    }
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    visible: root.trackerHint.length > 0
                    text: root.trackerHint
                    color: Kirigami.Theme.neutralTextColor
                    wrapMode: Text.WordWrap
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

            }
        }
    }
}
