import QtQml
import "../domain/tracker.mjs" as Tracker
import "../domain/urls.mjs" as Urls

// On-demand tracker check for a single CVE. The scan-time tracker data is the
// primary source; this only resolves a CVE when no scan-time verdict exists.
QtObject {
    id: client

    required property var runner
    property string baseUrl: Urls.TRACKER_BASE

    signal result(string cve, string state, string detail)

    function check(cve) {
        const id = String(cve || "");
        if (!Tracker.isCve(id)) {
            client.result(id, "failed", "invalid-cve");
            return;
        }
        const command = "curl -sS -o /dev/null -w '%{http_code}' --max-time 6 "
            + Urls.trackerApi(client.baseUrl, id);
        client.runner.run(command, function (exitCode, stdout, stderr) {
            const code = String(stdout || "").trim();
            if (code === "200") {
                client.result(id, "found", code);
            } else if (code === "404") {
                client.result(id, "missing", code);
            } else if (code === "429") {
                client.result(id, "rate-limited", code);
            } else {
                client.result(id, "failed", code || String(exitCode || ""));
            }
        });
    }
}
