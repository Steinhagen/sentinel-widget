import QtQuick
import QtQuick.Window
import QtTest

TestCase {
    id: testCase
    name: "ConfigIgnored"

    width: 600
    height: 500

    Window {
        id: window
        width: 600
        height: 500
        visible: true
        color: "#101317"
    }

    function test_restore_all_clears_the_list_without_crashing() {
        const component = Qt.createComponent(
            Qt.resolvedUrl("../../contents/ui/configIgnored.qml"));
        compare(component.status, Component.Ready);
        const page = component.createObject(window.contentItem, {
            width: window.width,
            height: window.height,
            cfg_triageIgnore: '[{"cve":"CVE-2026-1","package":"ffmpeg","version":"6.1.6"},'
                + '{"cve":"CVE-2026-2","package":"zlib","version":"1.3.2"}]'
        });
        verify(page !== null);
        compare(page.ignoredCount(), 2);
        mouseClick(page.restoreAllButton);
        wait(50);
        compare(page.cfg_triageIgnore, "[]");
        compare(page.ignoredCount(), 0);
        page.destroy();
    }
}
