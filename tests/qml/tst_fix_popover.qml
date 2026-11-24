import QtQuick
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    name: "FixPopover"

    width: 420
    height: 520

    property var sampleRow: ({
        package: "bison",
        version: "3.8.2",
        url: "https://tracker.example/CVE-2026-8461",
        fix: {
            bucket: "none",
            labelKey: "no fix",
            url: "https://github.com/NixOS/nixpkgs/pull/1",
            matchedPackage: "bison",
            rows: [
                { name: "nixos-unstable", version: "3.8.2", state: "affected" },
                { name: "nixos-26.05", version: "3.8.2", state: "affected" },
                { name: "master", version: "3.8.2", state: "affected" }
            ]
        }
    })

    QtObject {
        id: fakeTheme

        readonly property color tooltipBackground: "#20242b"
        readonly property color tooltipBorder: "#353b45"
        readonly property color textColor: "#e8eaed"
        readonly property color mutedText: "#9aa0a6"
        readonly property color faintText: "#6f7680"
        readonly property color hairline: "#2b3038"
        readonly property color highColor: "#fbbf24"
        readonly property color primaryColor: "#3daee9"
        readonly property color originFooterBackground: "#1b1e24"

        function fixColor(bucket) {
            return bucket === "fixed" ? "#22c55e" : "#fb7185";
        }

        function fixPillBackground(bucket) {
            return "transparent";
        }

        function fixPillBorder(bucket) {
            return "#fb7185";
        }
    }

    QtObject {
        id: fakeLabels

        function fixPopoverTitle() { return "Remediere"; }
        function fixTrackerLabel() { return "Tracker"; }
        function fixChannelLabel() { return "Channel"; }
        function fixTrackerPackage(fix) {
            return fix && fix.matchedPackage ? "Pachet tracker: " + fix.matchedPackage : "";
        }
        function fixChannel(channel) {
            return channel ? "Canalul tău: " + channel : "";
        }
        function fixBranchesTitle() { return "Ramuri Nixpkgs"; }
        function fixBranchCount(count) { return count + " verificate"; }
        function fixYourChannelTag() { return "canalul tău"; }
        function fixSummary(fix) { return "Afectat în toate ramurile verificate"; }
        function fixOpenTracker() { return "Deschide tracker"; }
        function fixOpenFix() { return "Deschide remedierea"; }
        function fixText(fix) { return "fără remediere"; }
    }

    Components.FixPopover {
        id: card

        width: 360
        row: sampleRow
        theme: fakeTheme
        labels: fakeLabels
        systemChannel: "nixos-unstable"
    }

    function test_card_renders_with_branch_table() {
        verify(card.implicitHeight > 0);
        verify(card.implicitWidth > 0);
        compare(card.width, 360);
    }
}
