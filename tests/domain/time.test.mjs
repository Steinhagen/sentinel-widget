import test from "node:test";
import assert from "node:assert/strict";
import { relativeToken, scanAge } from "../../contents/ui/domain/time.mjs";

test("scan age is clamped at zero and missing timestamps are -1", () => {
    assert.equal(scanAge(1000, 5000), 4);
    assert.equal(scanAge(5000, 1000), 0);
    assert.equal(scanAge(null, 1000), -1);
});

test("relative boundaries", () => {
    assert.equal(relativeToken(-1).key, "");
    assert.equal(relativeToken(0).key, "just-now");
    assert.equal(relativeToken(59).key, "just-now");
    assert.equal(relativeToken(60).key, "minutes");
    assert.equal(relativeToken(60).value, 1);
    assert.equal(relativeToken(3599).key, "minutes");
    assert.equal(relativeToken(3600).key, "hours");
    assert.equal(relativeToken(86400).key, "days");
    assert.equal(relativeToken(86400 * 2).value, 2);
});
