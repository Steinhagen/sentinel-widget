import QtQuick
import QtQuick.Window
import QtTest
import org.kde.kirigami as Kirigami
import "../../contents/ui/components" as Components

TestCase {
    name: "SummaryCards"

    QtObject {
        id: fakeLabels
        function exposureTitle(band) {
            return ({critical:"CRITICAL EXPOSURE", high:"HIGH EXPOSURE",
                medium:"MEDIUM EXPOSURE", low:"LOW EXPOSURE",
                unknown:"UNKNOWN EXPOSURE"})[band] || "UNKNOWN EXPOSURE";
        }
        function potentialVulnerabilities() { return "potential vulnerabilities"; }
        function packagesText(n) { return n + " packages"; }
        function cvesText(n) { return n + " CVEs"; }
        function cvssLabel() { return "CVSS"; }
        function severityTitle() { return "SEVERITY"; }
        function severityBandLabel(band) { return band; }
        function readyToFixTitle() { return "READY TO FIX"; }
        function fixBucketLabel(bucket) { return bucket; }
    }

    Components.SentinelTheme { id: theme }

    Window {
        id: window
        width: 800
        height: 260
        visible: true

        Components.SummaryCards {
            id: cards
            x: 8
            y: 8
            width: Kirigami.Units.gridUnit * 34.6
            height: Kirigami.Units.gridUnit * 8.2
            maxSeverity: 8.8
            findings: 449
            affectedPackages: 34
            uniqueCves: 227
            severityBands: [
                { key: "", count: 449 },
                { key: "critical", count: 0 },
                { key: "high", count: 109 },
                { key: "medium", count: 312 },
                { key: "low", count: 28 },
                { key: "unknown", count: 0 }
            ]
            fixBands: [
                { key: "", count: 449 },
                { key: "fixed", count: 1 },
                { key: "progress", count: 12 },
                { key: "none", count: 408 },
                { key: "unknown", count: 17 },
                { key: "n/a", count: 11 }
            ]
            fixTotal: 449
            theme: theme
            labels: fakeLabels
        }
    }

    function test_high_score_uses_high_exposure() {
        const title = findChild(cards, "exposureTitle");
        verify(title);
        cards.maxSeverity = 8.8;
        compare(title.text, "HIGH EXPOSURE");
        compare(String(title.color), String(theme.highColor));
    }

    function test_critical_score_uses_critical_exposure() {
        const title = findChild(cards, "exposureTitle");
        cards.maxSeverity = 9.1;
        compare(title.text, "CRITICAL EXPOSURE");
        compare(String(title.color), String(theme.criticalColor));
    }

    function test_medium_score_uses_medium_exposure() {
        const title = findChild(cards, "exposureTitle");
        cards.maxSeverity = 5.0;
        compare(title.text, "MEDIUM EXPOSURE");
        compare(String(title.color), String(theme.mediumColor));
    }

    function test_no_score_uses_unknown_exposure() {
        const title = findChild(cards, "exposureTitle");
        cards.maxSeverity = 0;
        compare(title.text, "UNKNOWN EXPOSURE");
        compare(String(title.color), String(theme.unknownColor));
    }
}
