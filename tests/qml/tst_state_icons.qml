import QtQuick
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    name: "StateIcons"

    Components.Labels { id: labels }

    function test_shield_follows_the_highest_severity() {
        compare(labels.stateIcon("vulnerable", true, 9.1), "security-low");
        compare(labels.stateIcon("vulnerable", true, 8.8), "security-medium");
        compare(labels.stateIcon("vulnerable", true, 5.0), "security-medium");
        compare(labels.stateIcon("vulnerable", true, 2.0), "security-high");
        compare(labels.stateIcon("secure", true, 0), "security-high");
        compare(labels.stateIcon("unknown", true, 0), "security-medium");
        compare(labels.stateIcon("vulnerable", false, 9.8), "security-medium");
    }
}
