import QtQml

// Records commands and lets a test deliver scripted results.
QtObject {
    id: fake

    property var calls: []
    signal called(string command)

    function run(command, callback) {
        fake.calls.push({ command: String(command || ""), callback: callback });
        fake.called(String(command || ""));
        return "fake-" + fake.calls.length;
    }

    function count() {
        return fake.calls.length;
    }

    function commandAt(index) {
        return fake.calls[index] ? fake.calls[index].command : "";
    }

    function respond(index, exitCode, stdout, stderr) {
        const call = fake.calls[index];
        if (!call) {
            return;
        }
        call.callback(exitCode, String(stdout || ""), String(stderr || ""));
    }

    function respondLast(exitCode, stdout, stderr) {
        fake.respond(fake.calls.length - 1, exitCode, stdout, stderr);
    }

    function reset() {
        fake.calls = [];
    }
}
