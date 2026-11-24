import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const iconDir = join(here, "..", "..", "contents", "icons");

const expected = {
    critical: "#fb7185",
    high: "#f97316",
    medium: "#facc15",
    low: "#4ade80",
    secure: "#22c55e",
    unknown: "#94a3b8"
};

test("brand shield and severity shields are present", () => {
    const logo = readFileSync(join(iconDir, "sentinel-shield.svg"), "utf8");
    assert.match(logo, /<svg[\s>]/);
    assert.ok(logo.includes("#ffffff"));

    for (const [name, color] of Object.entries(expected)) {
        const file = join(iconDir, `sentinel-severity-${name}.svg`);
        const svg = readFileSync(file, "utf8");
        assert.match(svg, /<svg[\s>]/, `${name} is an SVG`);
        assert.ok(svg.includes(color), `${name} uses ${color}`);
    }
});
