import QtQml

// Reads status.json and reports raw text plus a load-error code. It does not
// parse or interpret the file.
QtObject {
    id: source

    required property var runner
    property string path: ""
    property string lastStat: ""

    signal loaded(string text, string errorCode)
    signal notModified()

    onPathChanged: source.lastStat = ""

    function shellQuote(value) {
        return "'" + String(value || "").replace(/'/g, "'\\''") + "'";
    }

    function read() {
        if (source.path.length === 0) {
            source.loaded("", "missing");
            return;
        }
        // Skip the 1.8 MB read and JSON parse when the file has not changed.
        const command = "stat -c '%y:%s' -- " + source.shellQuote(source.path);
        source.runner.run(command, function (exitCode, stdout) {
            if (exitCode !== 0) {
                source.readDirect();
                return;
            }
            const stat = String(stdout || "").trim();
            if (source.lastStat.length > 0 && stat === source.lastStat) {
                source.notModified();
                return;
            }
            source.lastStat = stat;
            source.readDirect();
        });
    }

    function readDirect() {
        const command = "cat -- " + source.shellQuote(source.path);
        source.runner.run(command, function (exitCode, stdout, stderr) {
            if (exitCode === 0) {
                source.loaded(String(stdout || ""), "");
                return;
            }
            source.loaded("", source.errorFor(stderr));
        });
    }

    function errorFor(stderr) {
        const text = String(stderr || "").toLowerCase();
        if (text.indexOf("permission denied") >= 0) {
            return "permission";
        }
        if (text.indexOf("no such file") >= 0
                || text.indexOf("cannot open") >= 0
                || text.indexOf("not found") >= 0) {
            return "missing";
        }
        return "unknown";
    }
}
