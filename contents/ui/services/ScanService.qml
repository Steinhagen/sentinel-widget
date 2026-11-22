import QtQml

// Starts and queries the vulnscan systemd unit.
QtObject {
    id: service

    required property var runner
    property string unit: "vulnscan.service"
    property bool active: false

    function isActiveState(state) {
        return state === "active"
            || state === "activating"
            || state === "reloading"
            || state === "deactivating";
    }

    function queryActive(callback) {
        const command = "systemctl is-active " + service.unit + " 2>/dev/null";
        service.runner.run(command, function (exitCode, stdout) {
            const state = String(stdout || "").trim();
            const next = service.isActiveState(state);
            if (next !== service.active) {
                service.active = next;
            }
            if (typeof callback === "function") {
                callback(next, state);
            }
        });
    }

    function start(callback) {
        const command = "systemctl start --no-block " + service.unit;
        service.runner.run(command, function (exitCode, stdout, stderr) {
            const ok = exitCode === 0;
            if (typeof callback === "function") {
                callback(ok, exitCode, String(stderr || ""));
            }
        });
    }
}
