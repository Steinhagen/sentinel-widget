import QtQml

QtObject {
    id: source

    property int readCount: 0
    signal loaded(string text, string errorCode)
    signal notModified()

    function read() {
        source.readCount += 1;
    }

    function deliver(text, errorCode) {
        source.loaded(String(text || ""), String(errorCode || ""));
    }

    function deliverUnchanged() {
        source.notModified();
    }
}
