import test from "node:test";
import assert from "node:assert/strict";
import { bandOf, formatScore, hasScore, isBold, numberOf } from "../../contents/ui/domain/severity.mjs";

test("hasScore rejects zero, null and non-numeric values", () => {
    assert.equal(hasScore(9.9), true);
    assert.equal(hasScore("7.2"), true);
    assert.equal(hasScore(0), false);
    assert.equal(hasScore(null), false);
    assert.equal(hasScore(undefined), false);
    assert.equal(hasScore("nope"), false);
});

test("band boundaries match the dashboard", () => {
    assert.equal(bandOf(9.0), "critical");
    assert.equal(bandOf(8.9), "high");
    assert.equal(bandOf(7.0), "high");
    assert.equal(bandOf(6.9), "medium");
    assert.equal(bandOf(4.0), "medium");
    assert.equal(bandOf(3.9), "low");
    assert.equal(bandOf(0), "unknown");
    assert.equal(bandOf(null), "unknown");
});

test("score formatting and emphasis", () => {
    assert.equal(formatScore(9.9), "9.9");
    assert.equal(formatScore(0), "—");
    assert.equal(formatScore(null), "—");
    assert.equal(isBold(9.9), true);
    assert.equal(isBold(7.0), true);
    assert.equal(isBold(6.9), false);
    assert.equal(numberOf("8.5"), 8.5);
    assert.equal(numberOf("nope"), 0);
});
