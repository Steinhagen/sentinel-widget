import QtQuick
import QtQuick.Window
import QtTest
import org.kde.kirigami as Kirigami
import "../../contents/ui/components" as Components

TestCase {
    id: testCase
    name: "OriginPopover"

    QtObject {
        id: fakeLabels
        function originEyebrow() { return "ORIGINE"; }
        function originIntroducedBy() { return "Introdus de"; }
        function originTrails() { return "TRASEE"; }
        function originHint() { return "Click pe rândul de origine pentru a filtra toate constatările."; }
    }

    readonly property var origin: ({
        names: ["calibre-9.17.0", "open-webui-0.13.3"],
        chains: [
            ["calibre-9.17.0", "ffmpeg"],
            ["calibre-9.17.0", "ffmpeg-9.0.2-lib", "ffmpeg-9.0.2-data"],
            ["open-webui-0.13.3", "python3.14-pydub-0.25.1", "ffmpeg-9.0.2-bin"]
        ]
    })

    Components.SentinelTheme { id: theme }

    Window {
        id: window
        width: 470
        height: 430
        visible: true
        color: "#101317"

        Components.OriginPopover {
            id: popover
            x: 24
            y: 24
            width: Kirigami.Units.gridUnit * 22
            origin: testCase.origin
            theme: theme
            labels: fakeLabels
        }
    }

    function test_content() {
        const title = findChild(window, "originTitle");
        verify(title);
        compare(title.text, "Introdus de");
        const count = findChild(window, "originChainCount");
        verify(count);
        compare(count.text, "3");
    }
}
