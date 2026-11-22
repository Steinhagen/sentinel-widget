import QtQuick
import QtTest

TestCase {
    id: testCase
    name: "CommandRunner"

    function createRunner() {
        const component = Qt.createComponent(Qt.resolvedUrl("../../contents/ui/services/CommandRunner.qml"));
        return component.createObject(testCase, {});
    }

    function test_executes_a_command_and_dispatches_a_callback() {
        const runner = testCase.createRunner();
        let result = null;
        runner.run("printf sentinel", function (exitCode, stdout, stderr) {
            result = { exitCode: exitCode, stdout: stdout, stderr: stderr };
        });
        let waited = 0;
        while (result === null && waited < 3000) {
            wait(50);
            waited += 50;
        }
        verify(result !== null);
        compare(result.exitCode, 0);
        compare(result.stdout, "sentinel");
        runner.destroy();
    }

    function test_duplicate_commands_share_one_result() {
        const runner = testCase.createRunner();
        let first = null;
        let second = null;
        runner.run("printf shared", function (exitCode, stdout) { first = stdout; });
        runner.run("printf shared", function (exitCode, stdout) { second = stdout; });
        let waited = 0;
        while ((first === null || second === null) && waited < 3000) {
            wait(50);
            waited += 50;
        }
        compare(first, "shared");
        compare(second, "shared");
        runner.destroy();
    }
}
