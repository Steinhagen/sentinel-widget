import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { normalizeReport } from "../../contents/ui/domain/status.mjs";

const here = dirname(fileURLToPath(import.meta.url));

export function readFixture(name) {
    return JSON.parse(readFileSync(join(here, "..", "fixtures", name), "utf8"));
}

export const v7Raw = readFixture("status-v7.json");
export const legacyRaw = readFixture("status-legacy.json");
export const v7 = normalizeReport(v7Raw);
export const legacy = normalizeReport(legacyRaw);

export function finding(id) {
    return v7.vulnerabilities.find((item) => item.id === id);
}

export function rawFinding(id) {
    return v7Raw.vulnerabilities.find((item) => item.id === id);
}
