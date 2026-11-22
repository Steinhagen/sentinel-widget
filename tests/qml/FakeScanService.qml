import QtQml

QtObject {
    id: service

    property bool active: false
    property var queryCallback: null
    property var startCallback: null
    property int queryCount: 0
    property int startCount: 0

    function queryActive(callback) {
        service.queryCount += 1;
        service.queryCallback = callback;
    }

    function start(callback) {
        service.startCount += 1;
        service.startCallback = callback;
    }

    function respondActive(value) {
        service.active = value;
        if (service.queryCallback) {
            service.queryCallback(value);
        }
    }

    function respondStart(ok) {
        if (service.startCallback) {
            service.startCallback(ok, ok ? 0 : 1, ok ? "" : "start failed");
        }
    }
}
