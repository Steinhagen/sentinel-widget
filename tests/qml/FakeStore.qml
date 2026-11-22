import QtQml

QtObject {
    property var report: null
    property var checked: ({})
    property int checkedRevision: 0
    property string systemChannel: ""
    property var tracker: null
    property string loadError: ""
    property bool schemaNewer: false
    property string scanError: ""
    property var clock: null
}
