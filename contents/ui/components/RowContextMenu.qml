import QtQuick
import QtQuick.Controls as QQC2

QQC2.Menu {
    id: root

    property var rowData: null
    property var labels: null

    signal filterPackageRequested(string packageName)
    signal filterOriginRequested(string originName)
    signal trackerRequested(var finding)
    signal openFixRequested(string url)
    signal openMasterSourceRequested(string url)
    signal copyRequested(string text)
    signal nixpkgsSearchRequested(string packageName)
    signal ignoreRequested(var finding)

    QQC2.MenuItem {
        text: root.labels ? root.labels.showAllForPackage(root.rowData ? root.rowData.package : "") : ""
        icon.name: "view-filter"
        enabled: !!(root.rowData && root.rowData.package)
        onTriggered: root.filterPackageRequested(root.rowData.package)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.filterByOrigin() : ""
        icon.name: "view-filter"
        enabled: !!(root.rowData && root.rowData.origin && root.rowData.origin.names.length > 0)
        onTriggered: root.filterOriginRequested(root.rowData.origin.primary)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.openTrackerText() : ""
        icon.name: "internet-services"
        enabled: !!(root.rowData && root.rowData.trackerState !== "none")
        onTriggered: root.trackerRequested(root.rowData)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.openMasterFixText() : ""
        icon.name: "internet-services"
        enabled: !!(root.rowData && root.rowData.fix && root.rowData.fix.url)
        onTriggered: root.openFixRequested(root.rowData.fix.url)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.openMasterSourceText() : ""
        icon.name: "document-open"
        enabled: !!(root.rowData && root.rowData.tracker && root.rowData.tracker.master_url)
        onTriggered: root.openMasterSourceRequested(root.rowData.tracker.master_url)
    }

    QQC2.MenuSeparator {}

    QQC2.MenuItem {
        text: root.labels ? root.labels.copyCveText() : ""
        icon.name: "edit-copy"
        enabled: !!(root.rowData && root.rowData.id)
        onTriggered: root.copyRequested(root.rowData.id)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.copyPackageText() : ""
        icon.name: "edit-copy"
        enabled: !!(root.rowData && root.rowData.package)
        onTriggered: root.copyRequested(root.rowData.package)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.copyFixUrlText() : ""
        icon.name: "edit-copy"
        enabled: !!(root.rowData && root.rowData.fix && root.rowData.fix.url)
        onTriggered: root.copyRequested(root.rowData.fix.url)
    }

    QQC2.MenuItem {
        text: root.labels ? root.labels.searchNixpkgsText(root.rowData ? root.rowData.package : "") : ""
        icon.name: "edit-find"
        enabled: !!(root.rowData && root.rowData.package)
        onTriggered: root.nixpkgsSearchRequested(root.rowData.package)
    }

    QQC2.MenuSeparator {}

    QQC2.MenuItem {
        text: root.labels ? root.labels.ignoreFindingText() : ""
        icon.name: "edit-delete"
        enabled: !!(root.rowData && root.rowData.id && root.rowData.package)
        onTriggered: root.ignoreRequested(root.rowData)
    }
}
