import QtQml

QtObject {
    function fixText(fix) {
        return fix ? fix.labelKey : "";
    }

    function viaLabel(row) {
        return row.scanners.join(", ") + " " + row.confidence;
    }

    function severityBandLabel(band) {
        return band || "All";
    }
}
