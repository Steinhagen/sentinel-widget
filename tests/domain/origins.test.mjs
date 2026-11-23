import test from "node:test";
import assert from "node:assert/strict";
import { chainText, groupKeyOf, namesOf, normalizedChain, primaryOf, splitNode } from "../../contents/ui/domain/origins.mjs";
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

test("origin step nodes split package names from versions", () => {
    assert.deepEqual(splitNode("calibre-9.17.0"), { name: "calibre", version: "9.17.0" });
    assert.deepEqual(splitNode("open-webui-0.13.3"), { name: "open-webui", version: "0.13.3" });
    assert.deepEqual(splitNode("ffmpeg-9.0.2-lib"), { name: "ffmpeg-lib", version: "9.0.2" });
    assert.deepEqual(splitNode("ffmpeg-9.0.2-data"), { name: "ffmpeg-data", version: "9.0.2" });
    assert.deepEqual(splitNode("python3.14-pydub-0.25.1"), { name: "python3.14-pydub", version: "0.25.1" });
    assert.deepEqual(splitNode("ffmpeg"), { name: "ffmpeg", version: "" });
    assert.deepEqual(splitNode("python3.14-pydub"), { name: "python3.14-pydub", version: "" });
});
