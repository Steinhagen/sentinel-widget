import QtQuick
import QtTest
import "../../contents/ui/components" as Components

TestCase {
    id: testCase
    name: "SearchFocus"

    Components.FindingsToolbar {
        id: toolbar
        width: 600
        height: 36
        labels: null
        onSearchChanged: (text) => toolbar.searchText = text
    }

    function test_typing_does_not_blur_the_field() {
        const field = findChild(toolbar, "searchField");
        verify(field !== null);
        // Live filtering uses onTextChanged; SearchField's accepted timer must
        // not blur the field after the first keystroke.
        compare(field.autoAccept, false);
        field.forceActiveFocus();
        verify(field.activeFocus);
        field.text = "b";
        wait(400);
        verify(field.activeFocus);
        field.accepted();
        verify(field.activeFocus);
        field.text = "";
        compare(field.text, "");
    }
}
