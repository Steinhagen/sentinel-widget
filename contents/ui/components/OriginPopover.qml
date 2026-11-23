pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3

import "../domain/origins.mjs" as Origins

// Rich content for the dependency-origin tooltip. The row's plain tooltip was
// a single wrapped string; this separates the origins, the trails and the
// package versions so a long chain stays readable.
Rectangle {
    id: root

    objectName: "originPopover"

    property var origin: null
    property var theme: null
    property var labels: null

    signal originSelected(string name)

    readonly property var originNames: {
        if (!origin || !origin.names) {
            return [];
        }
        return origin.names.length !== undefined ? origin.names : [];
    }
    readonly property var chains: {
        if (!origin) {
            return [];
        }
        const raw = origin.chains && origin.chains.length !== undefined
            ? origin.chains : [];
        const selected = [];
        for (let i = 0; i < raw.length && selected.length < 3; ++i) {
            if (raw[i] && raw[i].length > 0) {
                selected.push(raw[i]);
            }
        }
        if (selected.length === 0 && origin.chain && origin.chain.length > 0) {
            selected.push(origin.chain);
        }
        const result = [];
        for (let c = 0; c < selected.length; ++c) {
            const chain = selected[c];
            const steps = [];
            for (let s = 0; s < chain.length; ++s) {
                steps.push({ node: chain[s], last: s === chain.length - 1 });
            }
            result.push({ index: c, nodes: chain, steps: steps });
        }
        return result;
    }
    readonly property int chainCount: root.chains.length

    function stepName(node) {
        return Origins.splitNode(node).name;
    }

    function stepVersion(node) {
        return Origins.splitNode(node).version;
    }

    implicitWidth: Kirigami.Units.gridUnit * 22
    implicitHeight: layout.implicitHeight
    radius: 14
    color: root.theme ? root.theme.tooltipBackground : Kirigami.Theme.backgroundColor
    border.width: 1
    border.color: root.theme ? root.theme.tooltipBorder : Kirigami.Theme.disabledTextColor

    // Consume clicks anywhere on the card so they cannot fall through to the
    // findings list behind the overlay.
    MouseArea {
        anchors.fill: parent
        onClicked: {}
    }

    ColumnLayout {
        id: layout

        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            id: body

            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.gridUnit * 0.75
            spacing: 10

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                Rectangle {
                    Layout.preferredWidth: Kirigami.Units.gridUnit * 1.65
                    Layout.preferredHeight: Layout.preferredWidth
                    radius: 8
                    color: root.theme
                        ? Qt.rgba(root.theme.primaryColor.r,
                            root.theme.primaryColor.g,
                            root.theme.primaryColor.b, 0.12)
                        : "transparent"
                    border.width: 1
                    border.color: root.theme
                        ? Qt.rgba(root.theme.primaryColor.r,
                            root.theme.primaryColor.g,
                            root.theme.primaryColor.b, 0.28)
                        : "transparent"

                    PlasmaComponents3.Label {
                        anchors.centerIn: parent
                        text: "↳"
                        color: root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor
                        font.bold: true
                        font.pointSize: Math.max(9,
                            Math.round(Kirigami.Theme.defaultFont.pointSize * 1.2))
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0

                    PlasmaComponents3.Label {
                        text: root.labels ? root.labels.originEyebrow() : "ORIGIN"
                        color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                        font.bold: true
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize - 1)
                        font.letterSpacing: 0.8
                    }

                    PlasmaComponents3.Label {
                        objectName: "originTitle"

                        text: root.labels ? root.labels.originIntroducedBy()
                            : "Introduced by"
                        color: root.theme ? root.theme.textColor : Kirigami.Theme.textColor
                        font.bold: true
                        font.family: Kirigami.Theme.defaultFont.family
                        font.pointSize: Math.max(9,
                            Math.round(Kirigami.Theme.defaultFont.pointSize * 1.05))
                    }
                }
            }

            Flow {
                Layout.fillWidth: true
                Layout.preferredHeight: implicitHeight
                spacing: 6

                Repeater {
                    model: root.originNames

                    Rectangle {
                        id: originChip

                        objectName: "originChip"

                        required property string modelData

                        readonly property var parts: Origins.splitNode(modelData)

                        width: chipRow.implicitWidth + 16
                        height: chipRow.implicitHeight + 10
                        radius: 8
                        color: root.theme
                            ? Qt.rgba(root.theme.primaryColor.r,
                                root.theme.primaryColor.g,
                                root.theme.primaryColor.b, 0.09)
                            : "transparent"
                        border.width: 1
                        border.color: root.theme
                            ? Qt.rgba(root.theme.primaryColor.r,
                                root.theme.primaryColor.g,
                                root.theme.primaryColor.b, 0.32)
                            : "transparent"

                        RowLayout {
                            id: chipRow

                            anchors.centerIn: parent
                            spacing: 5

                            PlasmaComponents3.Label {
                                text: originChip.parts.name
                                color: root.theme ? root.theme.textColor : Kirigami.Theme.textColor
                                font.bold: true
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                            }

                            PlasmaComponents3.Label {
                                visible: text.length > 0
                                text: originChip.parts.version
                                color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                                font.family: Kirigami.Theme.smallFont.family
                                font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                            }
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.originSelected(originChip.modelData)
                        }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 7

                PlasmaComponents3.Label {
                    text: root.labels ? root.labels.originTrails() : "TRAILS"
                    color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                    font.bold: true
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize - 1)
                    font.letterSpacing: 0.8
                }

                Rectangle {
                    Layout.preferredWidth: Math.max(16, countLabel.implicitWidth + 10)
                    Layout.preferredHeight: 16
                    radius: 8
                    color: root.theme ? root.theme.chipBackground : "transparent"

                    PlasmaComponents3.Label {
                        id: countLabel

                        objectName: "originChainCount"

                        anchors.centerIn: parent
                        text: root.chainCount
                        color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                        font.bold: true
                        font.family: Kirigami.Theme.smallFont.family
                        font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 7

                Repeater {
                    model: root.chains

                    Rectangle {
                        id: chainCard

                        required property var modelData
                        required property int index

                        Layout.fillWidth: true
                        implicitHeight: chainRow.implicitHeight + 14
                        radius: 9
                        color: root.theme ? root.theme.originRowBackground : "transparent"
                        border.width: 1
                        border.color: root.theme ? root.theme.hairline : "transparent"

                        RowLayout {
                            id: chainRow

                            anchors.fill: parent
                            anchors.margins: 7
                            spacing: 8

                            Rectangle {
                                Layout.preferredWidth: 18
                                Layout.preferredHeight: 18
                                Layout.alignment: Qt.AlignTop
                                radius: 9
                                color: root.theme ? root.theme.chipBackground : "transparent"

                                PlasmaComponents3.Label {
                                    anchors.centerIn: parent
                                    text: chainCard.modelData.index + 1
                                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                                    font.bold: true
                                    font.family: Kirigami.Theme.smallFont.family
                                    font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                                }
                            }

                            Flow {
                                id: chainFlow

                                property var nodes: chainCard.modelData.steps

                                Layout.fillWidth: true
                                Layout.preferredHeight: implicitHeight
                                spacing: 4

                                Repeater {
                                    model: chainFlow.nodes.slice(0, -1)

                                    RowLayout {
                                        id: stepGroup

                                        required property var modelData

                                        spacing: 4

                                        OriginStep {
                                            node: stepGroup.modelData.node
                                            last: false
                                            theme: root.theme
                                        }

                                        PlasmaComponents3.Label {
                                            text: "→"
                                            color: root.theme ? root.theme.faintText : Kirigami.Theme.disabledTextColor
                                            font.family: Kirigami.Theme.smallFont.family
                                            font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                                        }
                                    }
                                }

                                OriginStep {
                                    node: chainFlow.nodes.length > 0
                                        ? chainFlow.nodes[chainFlow.nodes.length - 1].node : ""
                                    last: true
                                    theme: root.theme
                                }
                            }
                        }
                    }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: hintRow.implicitHeight + 18
            color: root.theme ? root.theme.originFooterBackground : "transparent"

            Rectangle {
                anchors.top: parent.top
                width: parent.width
                height: 1
                color: root.theme ? root.theme.tooltipBorder : Kirigami.Theme.disabledTextColor
            }

            RowLayout {
                id: hintRow

                anchors.fill: parent
                anchors.margins: 9
                spacing: 7

                PlasmaComponents3.Label {
                    text: "↗"
                    color: root.theme ? root.theme.primaryColor : Kirigami.Theme.highlightColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(7, Kirigami.Theme.smallFont.pointSize)
                }

                PlasmaComponents3.Label {
                    objectName: "originHint"

                    Layout.fillWidth: true
                    text: root.labels ? root.labels.originHint()
                        : "Click the origin row to filter all findings."
                    color: root.theme ? root.theme.mutedText : Kirigami.Theme.disabledTextColor
                    font.family: Kirigami.Theme.smallFont.family
                    font.pointSize: Math.max(6, Kirigami.Theme.smallFont.pointSize - 1)
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
