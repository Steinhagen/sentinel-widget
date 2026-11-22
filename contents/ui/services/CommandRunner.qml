import QtQml
import QtQuick
import org.kde.plasma.plasma5support as Plasma5Support

// One place that executes shell commands and routes results back to callers.
//
// The executable DataSource is asynchronous and identifies a response only by
// its command string. This runner keeps a pending entry per command so that
// concurrent callers, duplicate requests and timeouts are handled explicitly
// instead of by parsing command prefixes in a store.
QtObject {
    id: runner

    property int timeoutMs: 10000
    property var pending: ({})
    property int pendingCount: 0
    property int requestSerial: 0

    signal response(string token, int exitCode, string stdout, string stderr)
    signal timedOut(string token)

    property Plasma5Support.DataSource dataSource: Plasma5Support.DataSource {
        engine: "executable"
        connectedSources: []

        onNewData: (sourceName, data) => runner.handleData(sourceName, data)
    }

    property Timer watchdog: Timer {
        interval: 500
        repeat: true
        running: runner.pendingCount > 0
        onTriggered: runner.checkTimeouts()
    }

    function run(command, callback) {
        const source = String(command || "");
        if (source.length === 0 || typeof callback !== "function") {
            return "";
        }
        const token = "cmd-" + (++runner.requestSerial);
        let entry = runner.pending[source];
        if (!entry) {
            entry = {
                source: source,
                tokens: [],
                callbacks: [],
                startedAt: Date.now()
            };
            runner.pending[source] = entry;
            runner.pendingCount = Object.keys(runner.pending).length;
            runner.dataSource.connectSource(source);
        }
        entry.tokens.push(token);
        entry.callbacks.push(callback);
        return token;
    }

    function handleData(sourceName, data) {
        const entry = runner.pending[sourceName];
        if (!entry) {
            runner.dataSource.disconnectSource(sourceName);
            return;
        }
        delete runner.pending[sourceName];
        runner.pendingCount = Object.keys(runner.pending).length;
        runner.dataSource.disconnectSource(sourceName);

        const exitCode = Number(data["exit code"] !== undefined
            ? data["exit code"] : 0);
        const stdout = String(data["stdout"] || "");
        const stderr = String(data["stderr"] || "");
        for (let i = 0; i < entry.callbacks.length; ++i) {
            const callback = entry.callbacks[i];
            const token = entry.tokens[i];
            runner.response(token, exitCode, stdout, stderr);
            try {
                callback(exitCode, stdout, stderr);
            } catch (error) {
                console.warn("sentinel: command callback failed:", error);
            }
        }
    }

    function checkTimeouts() {
        const now = Date.now();
        const expired = [];
        for (const source in runner.pending) {
            const entry = runner.pending[source];
            if (now - entry.startedAt >= runner.timeoutMs) {
                expired.push(source);
            }
        }
        for (let i = 0; i < expired.length; ++i) {
            const source = expired[i];
            const entry = runner.pending[source];
            delete runner.pending[source];
            runner.dataSource.disconnectSource(source);
            for (let j = 0; j < entry.callbacks.length; ++j) {
                runner.timedOut(entry.tokens[j]);
                try {
                    entry.callbacks[j](-1, "", "timeout");
                } catch (error) {
                    console.warn("sentinel: timeout callback failed:", error);
                }
            }
        }
        runner.pendingCount = Object.keys(runner.pending).length;
    }

    function cancel(token) {
        for (const source in runner.pending) {
            const entry = runner.pending[source];
            const index = entry.tokens.indexOf(token);
            if (index < 0) {
                continue;
            }
            entry.tokens.splice(index, 1);
            entry.callbacks.splice(index, 1);
            if (entry.tokens.length === 0) {
                delete runner.pending[source];
                runner.dataSource.disconnectSource(source);
            }
            runner.pendingCount = Object.keys(runner.pending).length;
            return;
        }
    }

    function cancelAll() {
        for (const source in runner.pending) {
            runner.dataSource.disconnectSource(source);
        }
        runner.pending = ({});
        runner.pendingCount = 0;
    }
}
