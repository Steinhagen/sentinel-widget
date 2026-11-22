import test from "node:test";
import assert from "node:assert/strict";
import { chainText, groupKeyOf, namesOf, normalizedChain, primaryOf } from "../../contents/ui/domain/origins.mjs";
import { finding } from "../helpers/fixtures.mjs";

test("missing origins are empty", () => {
    assert.deepEqual(namesOf({}), []);
    assert.deepEqual(normalizedChain({}), []);
    assert.equal(primaryOf({}), "");
    assert.equal(groupKeyOf({}), "");
});

test("normalization removes repeated nodes and the vulnerable tail", () => {
    const item = {
        package: "network",
        version: "3.2.8.0",
        origins: {
            introduced_by: ["haskell-language-server-2.13.0.0"],
            chain: [
                "haskell-language-server-2.13.0.0",
                "haskell-language-server-2.13.0.0",
                "network-3.2.8.0"
            ]
        }
    };
    assert.deepEqual(normalizedChain(item),
        ["haskell-language-server-2.13.0.0", "network"]);
    assert.equal(chainText(item),
        "haskell-language-server-2.13.0.0 → network");
});

test("a chain that only repeats the package is hidden", () => {
    const item = { package: "zlib", version: "1.3.0", origins: { chain: ["zlib-1.3.0"] } };
    assert.deepEqual(normalizedChain(item), []);
    assert.equal(chainText(item), "");
});

test("the fixture exposes multiple origins and chains", () => {
    const item = finding("CVE-2026-111497");
    assert.ok(namesOf(item).length >= 2);
    assert.ok(normalizedChain(item).length >= 2);
    assert.equal(primaryOf(item), "imagemagick-7.1.2-35");
});
