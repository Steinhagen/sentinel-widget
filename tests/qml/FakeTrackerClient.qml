import QtQml

QtObject {
    id: client

    property string lastCve: ""
    property int checkCount: 0
    signal result(string cve, string state, string detail)

    function check(cve) {
        client.lastCve = String(cve || "");
        client.checkCount += 1;
    }

    function respond(cve, state, detail) {
        client.result(String(cve || ""), String(state || ""), String(detail || ""));
    }
}
