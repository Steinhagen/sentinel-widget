import QtQuick
import QtQuick.Window
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    id: testCase
    name: "FindingRow"

    width: 700
    height: 100

    property var sampleRow: ({
        id: "CVE-2026-0001",
        package: "bison",
        version: "3.8.2",
        severityValue: 8.6,
        severityText: "8.6",
        severityBold: true,
        url: "https://tracker.example/CVE-2026-0001",
        fix: null,
        origin: null,
        source: null,
        triageVerdict: "confirmed",
        needsReview: false
    })

    QtObject {
        id: fakeTheme

        readonly property color rowHover: "#262b33"
        readonly property color textColor: "#e8eaed"
        readonly property color mutedText: "#9aa0a6"
        readonly property color faintText: "#6f7680"
        readonly property color hairline: "#2b3038"
        readonly property color reviewColor: "#f3d79a"
        readonly property color reviewSurface: "#3a2f16"
        readonly property color reviewBorder: "#6b5624"

        function severityColor(value) { return "#fb7185"; }
        function fixColor(bucket) { return "#fb7185"; }
        function fixPillBackground(bucket) { return "transparent"; }
        function fixPillBorder(bucket) { return "#fb7185"; }
    }

    FakeLabels {
        id: fakeLabels
    }

    Window {
        width: 700
        height: 100
        visible: true
        color: "#101317"

        Components.FindingRow {
            id: row

            width: parent.width
            height: 72
            rowData: testCase.sampleRow
            theme: fakeTheme
            labels: fakeLabels
        }
    }

    function test_hide_eye_emits_the_ignore_signal() {
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.signalName = "ignoreRequested";
        spy.target = row;
        const button = row.hideButton;
        verify(button !== null);
        verify(button.visible);
        mouseClick(button);
        compare(spy.count, 1);
        compare(spy.signalArguments[0][0].id, "CVE-2026-0001");
        spy.destroy();
    }

    function test_hidden_view_eye_emits_restore() {
        row.hiddenMode = true;
        compare(row.hideButton.icon.name, "view-visible");
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.signalName = "restoreRequested";
        spy.target = row;
        mouseClick(row.hideButton);
        compare(spy.count, 1);
        compare(spy.signalArguments[0][0].id, "CVE-2026-0001");
        spy.destroy();
        row.hiddenMode = false;
    }
}
