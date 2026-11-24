import QtQuick
import QtQuick.Window
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    id: testCase
    name: "OriginStep"

    width: 300
    height: 100

    Window {
        width: 300
        height: 100
        visible: true
        color: "#101317"

        Components.OriginStep {
            id: step
            node: "lutris-0.5.22-bwrap"
        }
    }

    function test_click_emits_selected_node() {
        const spy = Qt.createQmlObject("import QtTest; SignalSpy {}", testCase);
        spy.target = step;
        spy.signalName = "selected";
        mouseClick(step);
        compare(spy.count, 1);
        compare(spy.signalArguments[0][0], "lutris-0.5.22-bwrap");
    }
}
