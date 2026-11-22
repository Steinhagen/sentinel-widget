import QtQuick

// A hidden TextEdit is the reliable clipboard bridge in a Plasma applet.
Item {
    id: service

    visible: false
    width: 0
    height: 0

    function copy(text) {
        const value = String(text || "");
        if (value.length === 0) {
            return false;
        }
        helper.text = value;
        helper.selectAll();
        helper.copy();
        return true;
    }

    TextEdit {
        id: helper
        visible: false
    }
}
