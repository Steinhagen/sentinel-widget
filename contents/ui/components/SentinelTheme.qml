import QtQml
import QtQuick
import org.kde.kirigami as Kirigami

// Derived colours. Kirigami follows the system colour scheme; every surface
// here comes from the theme so light/dark works automatically.
QtObject {
    id: theme

    readonly property bool darkMode: Kirigami.Theme.backgroundColor.hsvValue < 0.5
    readonly property color cardColor: darkMode
        ? Qt.rgba(1, 1, 1, 0.06)
        : Qt.rgba(1, 1, 1, 0.86)
    readonly property color cardBorder: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b,
        darkMode ? 0.16 : 0.10)
    readonly property color textColor: Kirigami.Theme.textColor
    readonly property color tooltipBackground: darkMode ? "#20242b" : "#ffffff"
    readonly property color tooltipBorder: darkMode ? "#353c46" : "#d8dde4"
    readonly property color chipBackground: darkMode ? "#2b323c" : "#f2f5f9"
    readonly property color chipBorder: darkMode ? "#3a424d" : "#dfe4ea"
    readonly property color originRowBackground: darkMode ? "#1b2026" : "#f7f9fc"
    readonly property color originFooterBackground: darkMode ? "#1b2026" : "#f4f6f9"
    readonly property color mutedText: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.62)
    readonly property color faintText: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.42)
    readonly property color hairline: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.10)
    readonly property color rowHover: Qt.rgba(Kirigami.Theme.textColor.r,
        Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.055)
    readonly property color inputBackground: darkMode
        ? Qt.rgba(1, 1, 1, 0.055)
        : Qt.rgba(0, 0, 0, 0.025)
    readonly property color primaryColor: Kirigami.Theme.highlightColor
    readonly property color primaryText: Kirigami.Theme.highlightedTextColor
    readonly property color criticalColor: darkMode ? "#fb7185" : "#e11d48"
    readonly property color highColor: darkMode ? "#fbbf24" : "#f97316"
    readonly property color mediumColor: darkMode ? "#facc15" : "#f59e0b"
    readonly property color lowColor: darkMode ? "#4ade80" : "#22c55e"
    readonly property color unknownColor: darkMode ? "#94a3b8" : "#cbd5e1"
    readonly property color severitySurface: darkMode
        ? Qt.rgba(0.45, 0.38, 0.95, 0.22)
        : Qt.rgba(0.45, 0.38, 0.95, 0.10)
    readonly property color fixesSurface: darkMode
        ? Qt.rgba(0.05, 0.72, 0.50, 0.22)
        : Qt.rgba(0.05, 0.72, 0.50, 0.10)
    readonly property color reviewColor: darkMode ? "#f3d79a" : "#8a5a00"
    readonly property color reviewSurface: darkMode
        ? Qt.rgba(0.98, 0.75, 0.28, 0.16)
        : Qt.rgba(0.98, 0.75, 0.28, 0.22)
    readonly property color reviewBorder: darkMode
        ? Qt.rgba(0.98, 0.75, 0.28, 0.45)
        : Qt.rgba(0.55, 0.38, 0.05, 0.35)

    function severityBandColor(band) {
        switch (band) {
        case "critical":
            return theme.criticalColor;
        case "high":
            return theme.highColor;
        case "medium":
            return theme.mediumColor;
        case "low":
            return theme.lowColor;
        case "unknown":
            return theme.unknownColor;
        default:
            return theme.faintText;
        }
    }

    function severityColor(severity) {
        if (!(Number(severity) > 0)) {
            return theme.faintText;
        }
        if (severity >= 9) {
            return theme.criticalColor;
        }
        if (severity >= 7) {
            return theme.highColor;
        }
        if (severity >= 4) {
            return theme.mediumColor;
        }
        return theme.lowColor;
    }

    function stateColor(state, hasReport) {
        if (!hasReport) {
            return Kirigami.Theme.disabledTextColor;
        }
        switch (state) {
        case "secure":
            return Kirigami.Theme.positiveTextColor;
        case "vulnerable":
            return Kirigami.Theme.negativeTextColor;
        case "warn":
            return Kirigami.Theme.neutralTextColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    function fixColor(bucket) {
        switch (bucket) {
        case "fixed":
            return Kirigami.Theme.positiveTextColor;
        case "progress":
            return Kirigami.Theme.neutralTextColor;
        case "none":
            return Kirigami.Theme.negativeTextColor;
        case "unknown":
        case "n/a":
            return Kirigami.Theme.disabledTextColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }

    function fixPillBackground(bucket) {
        const tone = theme.fixColor(bucket);
        return Qt.rgba(tone.r, tone.g, tone.b, theme.darkMode ? 0.18 : 0.10);
    }

    function fixPillBorder(bucket) {
        const tone = theme.fixColor(bucket);
        return Qt.rgba(tone.r, tone.g, tone.b, theme.darkMode ? 0.55 : 0.45);
    }

    function trackerFilterColor(key) {
        switch (key) {
        case "linked":
            return Kirigami.Theme.positiveTextColor;
        case "pending":
        case "missing":
            return Kirigami.Theme.neutralTextColor;
        case "":
            return Kirigami.Theme.textColor;
        default:
            return Kirigami.Theme.disabledTextColor;
        }
    }
}
