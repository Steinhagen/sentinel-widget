import test from "node:test";
import assert from "node:assert/strict";
import { normalizeSource, sourceText, sourceRevText } from "../../contents/ui/domain/source.mjs";

test("missing or empty sources are null", () => {
    assert.equal(normalizeSource(null), null);
    assert.equal(normalizeSource(undefined), null);
    assert.equal(normalizeSource(""), null);
    assert.equal(normalizeSource({}), null);
    assert.equal(sourceText(null), "");
    assert.equal(sourceRevText(null), "");
});

test("a flake source renders as flake/ref (short rev)", () => {
    const source = normalizeSource({
        flake: "nixpkgs",
        ref: "nixos-unstable",
        rev: "2786a2a72088ecf32aea5b3ec52099e6a7cff78f",
        short_rev: "2786a2a"
    });
    assert.equal(sourceText(source), "nixpkgs/nixos-unstable (2786a2a)");
    assert.equal(sourceRevText(source), "2786a2a72088ecf32aea5b3ec52099e6a7cff78f");
});

test("the short rev falls back to the first seven characters", () => {
    assert.equal(sourceText({
        flake: "nixpkgs",
        ref: "nixos-unstable",
        rev: "2786a2a72088ecf32aea5b3ec52099e6a7cff78f"
    }), "nixpkgs/nixos-unstable (2786a2a)");
});

test("partial sources stay readable", () => {
    assert.equal(sourceText({ flake: "nixpkgs" }), "nixpkgs");
    assert.equal(sourceText({ ref: "nixos-unstable" }), "nixos-unstable");
    assert.equal(sourceText({ flake: "nixpkgs", short_rev: "2786a2a" }),
        "nixpkgs (2786a2a)");
});

test("alternate field names and plain strings are accepted", () => {
    assert.equal(sourceText({ input: "nixpkgs", branch: "nixos-26.05" }),
        "nixpkgs/nixos-26.05");
    assert.equal(sourceText("nixpkgs/nixos-unstable (2786a2a)"),
        "nixpkgs/nixos-unstable (2786a2a)");
});
