pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

PlasmaComponents3.ItemDelegate {
    id: root

    property var rowData: null
    property var theme: null
    property var labels: null
    property string systemChannel: ""
    property real cveWidth: Kirigami.Units.gridUnit * 11
    property real fixPillWidth: Kirigami.Units.gridUnit * 4
    property real triageWidth: 0
    property real hideActionWidth: Kirigami.Units.iconSizes.small
        + Kirigami.Units.smallSpacing * 2
    property bool hiddenMode: false
    // Both hover cards (origin trails and fix details) use the same delay.
    readonly property int previewDelay: 1200
    signal openFinding(string url)
    signal filterPackageRequested(string packageName)
    signal filterOriginRequested(string originName)
    signal originPreviewRequested(var origin, var anchor)
    signal fixPreviewRequested(var row, var anchor)
    signal openFixRequested(string url)
    signal trackerRequested(var finding)
    signal copyRequested(string text)
    signal openMasterSourceRequested(string url)
    signal nixpkgsSearchRequested(string packageName)
    signal ignoreRequested(var finding)
    signal restoreRequested(var finding)

    // Exposed for tests and keyboard/accessibility wiring.
    readonly property alias hideButton: hideButton

    readonly property var fix: root.rowData ? root.rowData.fix : null
    readonly property string fixText: root.rowData && root.labels
        ? root.labels.fixText(root.rowData.fix) : ""
    readonly property string originChain: root.rowData && root.rowData.origin
        ? root.rowData.origin.chainText : ""
    readonly property string originPrimary: root.rowData && root.rowData.origin
        ? root.rowData.origin.primary : ""
    readonly property var originInfo: root.rowData ? root.rowData.origin : null
    readonly property bool hasOrigin: !!root.originInfo
        && root.originInfo.names !== undefined
        && root.originInfo.names !== null
        && root.originInfo.names.length > 0
    readonly property string sourceText: root.rowData
        ? (root.rowData.sourceText || "") : ""
    readonly property string sourceName: root.rowData
        ? (root.rowData.sourceName || "") : ""
    readonly property string sourceRef: root.rowData
        ? (root.rowData.sourceRef || "") : ""
    readonly property string sourceRev: root.rowData
        ? (root.rowData.sourceRev || "") : ""
    // On a narrow CVE column the flake prefix is dropped so the channel and
    // revision stay readable; the tooltip always names both.
    readonly property bool sourceNameFits: {
        if (!root.sourceRev || !root.sourceRef) {
            return true;
        }
        return sourceNameMetrics.width + sourceRevMetrics.width
            + Kirigami.Units.smallSpacing <= root.cveWidth;
    }
    readonly property var sourceInfo: root.rowData ? root.rowData.source : null
    readonly property string sourceTooltip: root.labels && root.sourceInfo
        ? root.labels.sourceTooltip(root.sourceInfo) : ""
    readonly property string triageVerdict: root.rowData
        ? (root.rowData.triageVerdict
            || (root.rowData.needsReview ? "unverified" : "")) : ""
    readonly property string triageLabel: root.labels
        && root.triageVerdict.length > 0
        ? root.labels.triageVerdictLabel(root.triageVerdict) : ""
    readonly property string triageTooltip: root.labels && root.rowData
        ? root.labels.triageTooltip(root.rowData) : ""
    readonly property string fixUrl: root.fix ? root.fix.url : ""

    TextMetrics {
        id: sourceNameMetrics

        font.family: Kirigami.Theme.smallFont.family
        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
        text: root.sourceName
    }

    TextMetrics {
        id: sourceRevMetrics

        font.family: Kirigami.Theme.smallFont.family
        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
        text: root.sourceRev
    }

    width: parent ? parent.width : implicitWidth
    height: Math.max(contentItem.implicitHeight + topPadding + bottomPadding,
        Kirigami.Units.gridUnit * 2.4)
    leftPadding: Kirigami.Units.smallSpacing + 3
    rightPadding: Kirigami.Units.smallSpacing
    topPadding: Kirigami.Units.smallSpacing
    bottomPadding: Kirigami.Units.smallSpacing
    hoverEnabled: true
    activeFocusOnTab: true

    Keys.onReturnPressed: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    Keys.onSpacePressed: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    Keys.onMenuPressed: rowMenu.popup()

    onClicked: {
        if (root.rowData && root.rowData.url) {
            root.openFinding(root.rowData.url);
        }
    }

    background: Rectangle {
        color: root.hovered && root.theme
            ? root.theme.rowHover
            : (root.triageVerdict === "unverified"
                ? Qt.rgba(0.95, 0.84, 0.60, 0.035)
                : (root.triageVerdict === "suppressed"
                    ? Qt.rgba(0.95, 0.60, 0.60, 0.04)
                    : "transparent"))

        Rectangle {
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            width: 3
            color: root.theme && root.rowData
                ? root.theme.severityColor(root.rowData.severityValue)
                : "transparent"
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 1
            color: root.theme ? root.theme.hairline : "transparent"
        }
    }

    Accessible.name: root.rowData && root.labels
        ? root.labels.rowAccessibleName(root.rowData.id, root.rowData.package, root.rowData.severityText)
        : ""
    Accessible.description: {
        const parts = [];
        if (root.triageLabel.length > 0) {
            parts.push(root.triageLabel);
        }
        if (root.sourceText.length > 0) {
            parts.push(root.sourceText);
        }
        if (root.originChain.length > 0) {
            parts.push(root.originChain);
        }
        return parts.join(" · ");
    }

    contentItem: ColumnLayout {
        spacing: 1

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Label {
                Layout.preferredWidth: Kirigami.Units.gridUnit * 2
                Layout.minimumWidth: Kirigami.Units.gridUnit * 2
                Layout.maximumWidth: Kirigami.Units.gridUnit * 2
                horizontalAlignment: Text.AlignHCenter
                text: root.rowData ? root.rowData.severityText : "—"
                color: root.theme && root.rowData
                    ? root.theme.severityColor(root.rowData.severityValue)
                    : Kirigami.Theme.textColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                font.bold: root.rowData ? root.rowData.severityBold : false
            }

            PlasmaComponents3.Label {
                id: cveLabel

                Layout.preferredWidth: root.cveWidth
                Layout.minimumWidth: root.cveWidth
                Layout.maximumWidth: root.cveWidth
                text: root.rowData ? (root.rowData.id || "—") : "—"
                color: root.rowData && root.rowData.url
                    ? Kirigami.Theme.linkColor : Kirigami.Theme.textColor
                font.family: Kirigami.Theme.smallFont.family
                font.pointSize: Kirigami.Theme.smallFont.pointSize
                font.underline: cveHover.hovered && root.rowData && !!root.rowData.url
                elide: Text.ElideRight

                HoverHandler {
                    id: cveHover
                    cursorShape: root.rowData && root.rowData.url
                        ? Qt.PointingHandCursor : Qt.ArrowCursor
                }

                QQC2.ToolTip.text: root.labels && root.rowData
                    ? root.labels.cveTooltip(root.rowData.id, !!(root.rowData.url))
                    : ""
                QQC2.ToolTip.visible: cveHover.hovered
                    && QQC2.ToolTip.text.length > 0
            }

            Item {
                Layout.fillWidth: true
                implicitHeight: packageRow.implicitHeight

                RowLayout {
                    id: packageRow

                    anchors.fill: parent
                    spacing: Kirigami.Units.smallSpacing

                    PlasmaComponents3.Label {
                        text: root.rowData ? (root.rowData.package || "—") : "—"
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        font.bold: true
                        font.strikeout: root.triageVerdict === "suppressed"
                        elide: Text.ElideRight
                    }

                    PlasmaComponents3.Label {
                        text: root.rowData ? (root.rowData.version || "") : ""
                        visible: text.length > 0
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        elide: Text.ElideRight
                    }

                    Item {
                        Layout.fillWidth: true
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        if (root.rowData && root.rowData.package) {
                            root.filterPackageRequested(root.rowData.package);
                        }
                    }

                    QQC2.ToolTip.text: root.labels && root.rowData
                        ? root.labels.filterPackageTooltip(root.rowData.package)
                        : ""
                    QQC2.ToolTip.visible: containsMouse
                        && QQC2.ToolTip.text.length > 0
                }
            }

            Rectangle {
                id: fixPill

                readonly property color tone: root.theme && root.fix
                    ? root.theme.fixColor(root.fix.bucket)
                    : Kirigami.Theme.disabledTextColor

                visible: root.fixText.length > 0
                Layout.preferredHeight: fixPillLabel.implicitHeight
                    + Kirigami.Units.smallSpacing
                Layout.preferredWidth: root.fixPillWidth
                Layout.minimumWidth: root.fixPillWidth
                Layout.maximumWidth: root.fixPillWidth
                radius: 99
                color: root.theme && root.fix
                    ? root.theme.fixPillBackground(root.fix.bucket)
                    : "transparent"
                border.width: 1
                border.color: root.theme && root.fix
                    ? root.theme.fixPillBorder(root.fix.bucket)
                    : "transparent"

                PlasmaComponents3.Label {
                    id: fixPillLabel

                    anchors.centerIn: parent
                    text: root.fixText
                    color: fixPill.tone
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

                Timer {
                    id: fixHoverTimer

                    interval: root.previewDelay
                    repeat: false
                    onTriggered: {
                        if (!fixPillMouse.containsMouse || !root.rowData) {
                            return;
                        }
                        const point = fixPill.mapToItem(null, 0, 0);
                        root.fixPreviewRequested(root.rowData, {
                            x: point.x,
                            y: point.y,
                            width: fixPill.width,
                            height: fixPill.height
                        });
                    }
                }

                MouseArea {
                    id: fixPillMouse

                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: root.fixUrl ? Qt.PointingHandCursor : Qt.ArrowCursor
                    onClicked: {
                        if (root.fixUrl) {
                            root.openFixRequested(root.fixUrl);
                        }
                    }

                    onContainsMouseChanged: {
                        if (containsMouse && root.rowData) {
                            fixHoverTimer.restart();
                        } else {
                            fixHoverTimer.stop();
                        }
                    }
                }
            }

            Item {
                id: triageColumn

                // Omit the item entirely when the column is hidden so the
                // RowLayout spacing matches the header.
                visible: root.triageWidth > 0

                readonly property color tone: {
                    if (root.triageVerdict === "unverified") {
                        return root.theme ? root.theme.reviewColor : "#f3d79a";
                    }
                    if (root.triageVerdict === "suppressed") {
                        return root.theme ? root.theme.fixColor("none")
                            : Kirigami.Theme.negativeTextColor;
                    }
                    if (root.triageVerdict === "confirmed") {
                        return root.theme ? root.theme.fixColor("fixed")
                            : Kirigami.Theme.positiveTextColor;
                    }
                    return Kirigami.Theme.disabledTextColor;
                }

                readonly property color surface: {
                    if (root.triageVerdict === "unverified") {
                        return root.theme ? root.theme.reviewSurface : "#3a2f16";
                    }
                    if (root.triageVerdict === "suppressed") {
                        return root.theme ? root.theme.fixPillBackground("none")
                            : Qt.rgba(0.95, 0.35, 0.35, 0.12);
                    }
                    if (root.triageVerdict === "confirmed") {
                        return root.theme ? root.theme.fixPillBackground("fixed")
                            : Qt.rgba(0.35, 0.8, 0.5, 0.12);
                    }
                    return "transparent";
                }

                readonly property color outline: {
                    if (root.triageVerdict === "unverified") {
                        return root.theme ? root.theme.reviewBorder : "#6b5624";
                    }
                    if (root.triageVerdict === "suppressed") {
                        return root.theme ? root.theme.fixPillBorder("none")
                            : Qt.rgba(0.95, 0.35, 0.35, 0.5);
                    }
                    if (root.triageVerdict === "confirmed") {
                        return root.theme ? root.theme.fixPillBorder("fixed")
                            : Qt.rgba(0.35, 0.8, 0.5, 0.5);
                    }
                    return "transparent";
                }

                Layout.preferredWidth: root.triageWidth
                Layout.minimumWidth: root.triageWidth
                Layout.maximumWidth: root.triageWidth
                Layout.fillHeight: true

                Rectangle {
                    id: triageIcon

                    visible: root.triageWidth > 0
                        && root.triageVerdict.length > 0
                    anchors.centerIn: parent
                    width: 18
                    height: 18
                    radius: 9
                    color: triageColumn.surface
                    border.width: 1
                    border.color: triageColumn.outline

                    PlasmaComponents3.Label {
                        anchors.centerIn: parent
                        text: root.triageVerdict === "unverified" ? "!"
                            : (root.triageVerdict === "suppressed" ? "⊘" : "✓")
                        color: triageColumn.tone
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Math.max(7,
                            Kirigami.Theme.smallFont.pointSize - 1)
                        font.bold: true
                    }
                }

                HoverHandler {
                    id: triageHover
                    cursorShape: Qt.WhatsThisCursor
                }

                QQC2.ToolTip.text: root.triageTooltip
                QQC2.ToolTip.visible: triageHover.hovered
                    && QQC2.ToolTip.text.length > 0
            }

            PlasmaComponents3.ToolButton {
                id: hideButton

                objectName: "hideFindingButton"
                visible: !!(root.rowData && root.rowData.id && root.rowData.package)
                Layout.preferredWidth: root.hideActionWidth
                Layout.minimumWidth: root.hideActionWidth
                Layout.maximumWidth: root.hideActionWidth
                Layout.preferredHeight: root.hideActionWidth
                Layout.minimumHeight: root.hideActionWidth
                Layout.maximumHeight: root.hideActionWidth
                flat: true
                display: QQC2.AbstractButton.IconOnly
                icon.name: root.hiddenMode ? "view-visible" : "view-hidden"
                icon.width: Kirigami.Units.iconSizes.small
                icon.height: Kirigami.Units.iconSizes.small
                icon.color: root.theme
                    ? (hovered ? root.theme.textColor : root.theme.mutedText)
                    : Kirigami.Theme.textColor
                leftPadding: 0
                rightPadding: 0
                topPadding: 0
                bottomPadding: 0
                focusPolicy: Qt.NoFocus
                Accessible.name: root.labels
                    ? (root.hiddenMode
                        ? root.labels.restoreFindingText()
                        : root.labels.ignoreFindingText())
                    : ""
                onClicked: {
                    if (!root.rowData) {
                        return;
                    }
                    if (root.hiddenMode) {
                        root.restoreRequested(root.rowData);
                    } else {
                        root.ignoreRequested(root.rowData);
                    }
                }

                QQC2.ToolTip.text: root.labels
                    ? (root.hiddenMode
                        ? root.labels.restoreFindingText()
                        : root.labels.ignoreFindingText())
                    : ""
                QQC2.ToolTip.visible: hovered
                    && QQC2.ToolTip.text.length > 0
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: Kirigami.Units.gridUnit * 2
                + Kirigami.Units.smallSpacing
            spacing: Kirigami.Units.smallSpacing
            visible: root.sourceText.length > 0 || root.originChain.length > 0

            // The package source sits under the CVE; the origin chain starts
            // under the package name, in the next column.
            Item {
                id: sourceColumn

                Layout.preferredWidth: root.cveWidth
                Layout.minimumWidth: root.cveWidth
                Layout.maximumWidth: root.cveWidth
                implicitHeight: sourceRow.implicitHeight

                // The channel is allowed to elide; the revision stays
                // readable at the end of the cell. The full pair is in the
                // tooltip.
                RowLayout {
                    id: sourceRow

                    anchors.fill: parent
                    spacing: Kirigami.Units.smallSpacing

                    PlasmaComponents3.Label {
                        id: sourceLabel

                        Layout.maximumWidth: Math.max(0, root.cveWidth
                            - sourceRevMetrics.width - Kirigami.Units.smallSpacing)
                        text: root.sourceNameFits || root.sourceRef.length === 0
                            ? root.sourceName : root.sourceRef
                        visible: text.length > 0
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                        elide: Text.ElideRight
                    }

                    PlasmaComponents3.Label {
                        text: root.sourceRev
                        visible: text.length > 0
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                    }

                    Item {
                        Layout.fillWidth: true
                    }
                }

                HoverHandler {
                    id: sourceHover
                    cursorShape: Qt.WhatsThisCursor
                }

                QQC2.ToolTip.text: root.sourceTooltip
                QQC2.ToolTip.visible: sourceHover.hovered
                    && QQC2.ToolTip.text.length > 0
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing
                visible: root.originChain.length > 0

                PlasmaComponents3.Label {
                    text: "↳"
                    color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }

                Item {
                    id: originAnchor

                    Layout.fillWidth: true
                    implicitHeight: chainLabel.implicitHeight

                    PlasmaComponents3.Label {
                        id: chainLabel

                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.originChain
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Kirigami.Theme.smallFont.pointSize
                        elide: Text.ElideRight
                    }

                    Timer {
                        id: originHoverTimer

                        interval: root.previewDelay
                        repeat: false
                        onTriggered: {
                            if (!chainHover.hovered || !root.originInfo) {
                                return;
                            }
                            const point = originAnchor.mapToItem(null, 0, 0);
                            root.originPreviewRequested(root.originInfo, {
                                x: point.x,
                                y: point.y,
                                width: originAnchor.width,
                                height: originAnchor.height
                            });
                        }
                    }

                    HoverHandler {
                        id: chainHover
                        cursorShape: Qt.PointingHandCursor

                        onHoveredChanged: {
                            if (hovered) {
                                originHoverTimer.restart();
                            } else {
                                originHoverTimer.stop();
                            }
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            if (root.originPrimary) {
                                root.filterOriginRequested(root.originPrimary);
                            }
                        }
                    }
                }
            }
        }
    }

    TapHandler {
        acceptedButtons: Qt.RightButton
        onTapped: rowMenu.popup()
    }

    RowContextMenu {
        id: rowMenu
        rowData: root.rowData
        labels: root.labels
        hiddenMode: root.hiddenMode

        onFilterPackageRequested: (packageName) => root.filterPackageRequested(packageName)
        onFilterOriginRequested: (originName) => root.filterOriginRequested(originName)
        onTrackerRequested: (finding) => root.trackerRequested(finding)
        onOpenFixRequested: (url) => root.openFixRequested(url)
        onOpenMasterSourceRequested: (url) => root.openMasterSourceRequested(url)
        onCopyRequested: (text) => root.copyRequested(text)
        onNixpkgsSearchRequested: (packageName) => root.nixpkgsSearchRequested(packageName)
        onIgnoreRequested: (finding) => root.ignoreRequested(finding)
        onRestoreRequested: (finding) => root.restoreRequested(finding)
    }
}
