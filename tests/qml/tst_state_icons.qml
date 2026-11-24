import QtQuick
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    name: "StateIcons"

    Components.Labels { id: labels }

    function test_shield_follows_the_highest_severity() {
        compare(labels.stateIcon("vulnerable", true, 9.1),
            "sentinel-severity-critical");
        compare(labels.stateIcon("vulnerable", true, 8.8),
            "sentinel-severity-high");
        compare(labels.stateIcon("vulnerable", true, 5.0),
            "sentinel-severity-medium");
        compare(labels.stateIcon("vulnerable", true, 2.0),
            "sentinel-severity-low");
        compare(labels.stateIcon("secure", true, 0),
            "sentinel-severity-secure");
        compare(labels.stateIcon("unknown", true, 0),
            "sentinel-severity-unknown");
        compare(labels.stateIcon("vulnerable", false, 9.8),
            "sentinel-severity-unknown");
    }
}
