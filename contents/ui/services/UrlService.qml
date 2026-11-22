import QtQml
import "../domain/urls.mjs" as Urls

// The only place that opens external URLs or local report/log files.
QtObject {
    id: service

    signal blocked(string url)

    function open(url) {
        const value = String(url || "");
        if (!Urls.isSafeExternalUrl(value)) {
            service.blocked(value);
            return false;
        }
        Qt.openUrlExternally(value);
        return true;
    }

    function openLocalFile(path) {
        const value = String(path || "");
        if (!Urls.isLocalFilePath(value)) {
            service.blocked(value);
            return false;
        }
        Qt.openUrlExternally("file://" + value);
        return true;
    }
}
