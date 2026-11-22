import test from "node:test";
import assert from "node:assert/strict";
import { isSafeExternalUrl, nixpkgsSearch, trackerApi, trackerPage } from "../../contents/ui/domain/urls.mjs";

test("tracker URLs escape the CVE", () => {
    assert.equal(
        trackerApi("https://tracker.security.nixos.org", "CVE-2026-1"),
        "https://tracker.security.nixos.org/api/v1/suggestions/by-cve/CVE-2026-1"
    );
    assert.equal(
        trackerPage("https://tracker.security.nixos.org", "CVE-2026-1"),
        "https://tracker.security.nixos.org/suggestions/by-cve/CVE-2026-1"
    );
});

test("nixpkgs search escapes the package", () => {
    assert.ok(nixpkgsSearch("python3").includes("python3"));
    assert.ok(nixpkgsSearch("a b").includes("a%20b"));
});

test("external URLs are restricted to web schemes", () => {
    assert.equal(isSafeExternalUrl("https://example.org/x"), true);
    assert.equal(isSafeExternalUrl("http://example.org/x"), true);
    assert.equal(isSafeExternalUrl("file:///etc/passwd"), false);
    assert.equal(isSafeExternalUrl("javascript:alert(1)"), false);
});
