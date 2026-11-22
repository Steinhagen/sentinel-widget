import QtQml
import QtQuick

// A single ticking clock. Callers read `now`; tests set it directly.
QtObject {
    id: clock

    property double now: Date.now()
    property int interval: 30000
    property bool running: true

    property Timer timer: Timer {
        interval: clock.interval
        running: clock.running
        repeat: true
        onTriggered: clock.tick()
    }

    function tick() {
        clock.now = Date.now();
    }
}
