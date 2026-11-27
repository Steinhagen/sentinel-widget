"""Backend rules that are easy to get wrong: tracker package matching."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sentinel_status", ROOT / "nix/backend/sentinel-status.py")
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)

PACKAGES = {
    "ffmpeg": {"master": {"version": "9.0.1", "status": "unknown"}},
    "ffmpeg_6": {"master": {"version": "6.1.6", "status": "affected"}},
    "ffmpeg_7": {"master": {"version": "7.1.5", "status": "affected"}},
    "ffmpeg_8": {"master": {"version": "8.1.2", "status": "affected"}},
    "ffmpeg_9": {"master": {"version": "9.0.1", "status": "unknown"}},
    "openssl": {"master": {"version": "3.6.0", "status": "affected"}},
    "openssl_1_1": {"master": {"version": "1.1.1w", "status": "affected"}},
    "openssl_3_5": {"master": {"version": "3.5.2", "status": "affected"}},
    "openssl_3_6": {"master": {"version": "3.6.0", "status": "affected"}},
    "libressl": {"master": {"version": "4.3.0", "status": "affected"}},
    "libressl_4_2": {"master": {"version": "4.2.1", "status": "affected"}},
    "capstone": {"master": {"version": "5.0.3", "status": "affected"}},
    "capstone_4": {"master": {"version": "4.0.2", "status": "affected"}},
}

GENERIC_NIX = (
    "https://github.com/NixOS/nixpkgs/blob/0123456789abcdef0123456789abcdef01234567/"
    "pkgs/development/libraries/ffmpeg/generic.nix#L1076"
)
FFMPEG_ENTRY = {
    "affected_products": [{
        "name": "FFmpeg",
        "version_constraints": [["affected", "<9.0"]],
    }],
}
FFMPEG_BRANCHES = {
    "master": {
        "version": "8.1.2",
        "status": "affected",
        "src_position": GENERIC_NIX,
    },
    "release-26.05": {
        "version": "8.1.2",
        "status": "affected",
        "src_position": GENERIC_NIX,
    },
}


class MatchPackageTests(unittest.TestCase):
    def test_exact_package_when_the_major_matches(self):
        matched, _ = STATUS.match_package(PACKAGES, "ffmpeg", "9.0.2")
        self.assertEqual(matched, "ffmpeg")

    def test_legacy_major_uses_the_versioned_attribute(self):
        self.assertEqual(
            STATUS.match_package(PACKAGES, "ffmpeg", "8.1.3")[0], "ffmpeg_8")
        self.assertEqual(
            STATUS.match_package(PACKAGES, "ffmpeg", "6.1.6")[0], "ffmpeg_6")

    def test_an_already_versioned_package_stays_exact(self):
        matched, _ = STATUS.match_package(PACKAGES, "ffmpeg_8", "8.1.3")
        self.assertEqual(matched, "ffmpeg_8")

    def test_minor_versioned_attributes_are_selected_by_prefix(self):
        self.assertEqual(
            STATUS.match_package(PACKAGES, "openssl", "1.1.1w")[0],
            "openssl_1_1")
        self.assertEqual(
            STATUS.match_package(PACKAGES, "openssl", "3.5.2")[0],
            "openssl_3_5")
        self.assertEqual(
            STATUS.match_package(PACKAGES, "libressl", "4.2.1")[0],
            "libressl_4_2")
        self.assertEqual(
            STATUS.match_package(PACKAGES, "capstone", "4.0.2")[0],
            "capstone_4")

    def test_an_exact_major_still_wins_over_its_variant(self):
        self.assertEqual(
            STATUS.match_package(PACKAGES, "ffmpeg", "9.0.2")[0], "ffmpeg")
        self.assertEqual(
            STATUS.match_package(PACKAGES, "openssl", "3.6.0")[0], "openssl")

    def test_unknown_package(self):
        self.assertEqual(STATUS.match_package(PACKAGES, "curl", "8.0"), (None, None))


OPENSSL_NIX = (
    "https://github.com/NixOS/nixpkgs/blob/0123456789abcdef0123456789abcdef01234567/"
    "pkgs/development/libraries/openssl/default.nix#L1"
)
ALSA_PATCH = "f84cd4ced7b36fddb8e4ee24404cf7c091d27020"
ALSA_NIX = (
    "https://github.com/NixOS/nixpkgs/blob/0123456789abcdef0123456789abcdef01234567/"
    "pkgs/by-name/al/alsa-lib/package.nix#L50"
)
ALSA_ENTRY = {
    "affected_products": [{
        "name": "alsa-lib",
        "version_constraints": [
            ["affected", "=<1.2.16.1"],
            ["unaffected", "==" + ALSA_PATCH],
        ],
    }],
}
ALSA_BRANCHES = {
    "master": {
        "version": "1.2.16.1",
        "status": "unknown",
        "src_position": ALSA_NIX,
    },
    "release-26.05": {
        "version": "1.2.15.3",
        "status": "unknown",
        "src_position": ALSA_NIX,
    },
}

BISON_NIX = (
    "https://github.com/NixOS/nixpkgs/blob/0123456789abcdef0123456789abcdef01234567/"
    "pkgs/by-name/bi/bison/package.nix#L1"
)

OPENSSL_ENTRY = {
    "affected_products": [{
        "name": "OpenSSL",
        "version_constraints": [["affected", "<3.6"]],
    }],
}
OPENSSL_BRANCHES = {
    "master": {
        "version": "3.5.2",
        "status": "affected",
        "src_position": OPENSSL_NIX,
    },
    "release-26.05": {
        "version": "3.5.2",
        "status": "affected",
        "src_position": OPENSSL_NIX,
    },
}


class BranchRowsTests(unittest.TestCase):
    def test_shared_package_file_reading_for_another_major_is_ignored(self):
        probed = {
            "pkgs/development/libraries/ffmpeg/generic.nix": {
                # nixos-unstable probes generic.nix and reads the default
                # ffmpeg 9.x, not the ffmpeg_8 attribute.
                "nixos-unstable": {"version": "9.0.2", "ref": "deadbeef"},
            },
        }
        rows, path = STATUS.branch_rows(
            FFMPEG_ENTRY, {"package": "ffmpeg"}, FFMPEG_BRANCHES, probed)
        self.assertEqual(path, "pkgs/development/libraries/ffmpeg/generic.nix")
        names = [row["name"] for row in rows]
        self.assertNotIn("nixos-unstable", names)
        self.assertEqual(names, ["master", "release-26.05"])
        self.assertTrue(all(row["state"] == "affected" for row in rows))
        self.assertTrue(all(row["url"].endswith("#L1076") for row in rows))

    def test_ffmpeg_8_has_no_fix_while_master_has_9(self):
        probed = {
            "pkgs/development/libraries/ffmpeg/generic.nix": {
                "nixos-unstable": {"version": "9.0.2", "ref": "deadbeef"},
            },
        }
        fix = STATUS.fix_in_progress(
            FFMPEG_ENTRY, {"package": "ffmpeg"}, FFMPEG_BRANCHES, probed, None)
        self.assertNotIn(fix["fix_state"], ("fixed", "in-master"))
        self.assertEqual(fix["fix_branches"][0]["name"], "master")
        self.assertEqual(fix["fix_branches"][0]["state"], "affected")

    def test_probe_with_the_same_major_but_another_minor_is_ignored(self):
        probed = {
            "pkgs/development/libraries/openssl/default.nix": {
                "nixos-unstable": {
                    "version": "3.6.0",
                    "ref": "deadbeef",
                    "line": 42,
                },
            },
        }
        rows, _ = STATUS.branch_rows(
            OPENSSL_ENTRY, {"package": "openssl"}, OPENSSL_BRANCHES, probed)
        self.assertNotIn("nixos-unstable", [row["name"] for row in rows])

    def test_a_probe_with_the_same_major_and_minor_is_kept(self):
        probed = {
            "pkgs/development/libraries/openssl/default.nix": {
                "nixos-unstable": {
                    "version": "3.5.3",
                    "ref": "deadbeef",
                    "line": 42,
                },
            },
        }
        rows, _ = STATUS.branch_rows(
            OPENSSL_ENTRY, {"package": "openssl"}, OPENSSL_BRANCHES, probed)
        channel = [row for row in rows if row["name"] == "nixos-unstable"]
        self.assertEqual(len(channel), 1)
        self.assertTrue(channel[0]["url"].endswith("#L42"))

    def test_staging_probe_for_another_major_is_ignored_too(self):
        probed = {
            "pkgs/development/libraries/ffmpeg/generic.nix": {
                "staging-next": {"version": "9.0.2", "ref": "deadbeef"},
            },
        }
        rows, _ = STATUS.branch_rows(
            FFMPEG_ENTRY, {"package": "ffmpeg"}, FFMPEG_BRANCHES, probed)
        self.assertNotIn("staging-next", [row["name"] for row in rows])


class LineAwareRangeTests(unittest.TestCase):
    """A CVE can carry one affected range per release line."""

    products = [{
        "name": "OpenSSL",
        "version_constraints": [
            ["affected", "<4.1.1"],
            ["affected", "<3.5.10"],
            ["affected", "<4.0.4"],
        ],
    }]

    def test_openssl_3_6_5_is_fixed_by_the_3_5_line(self):
        self.assertEqual(
            STATUS.version_verdict(self.products, "openssl", "3.5.9"),
            "affected")
        self.assertEqual(
            STATUS.version_verdict(self.products, "openssl", "3.6.5"),
            "unaffected")
        self.assertEqual(
            STATUS.version_verdict(self.products, "openssl", "4.0.3"),
            "affected")
        self.assertEqual(
            STATUS.version_verdict(self.products, "openssl", "4.1.0"),
            "affected")
        self.assertTrue(
            STATUS.is_fixed_version(self.products, "openssl", "3.6.5"))
        self.assertEqual(
            STATUS.ref_state(self.products, "openssl", "3.6.5", "unknown"),
            "unaffected")

        entry = {"affected_products": self.products}
        branches = {
            "master": {
                "version": "3.5.9",
                "status": "affected",
                "src_position": OPENSSL_NIX,
            },
            "release-26.05": {
                "version": "3.6.5",
                "status": "unknown",
                "src_position": OPENSSL_NIX,
            },
        }
        rows, _ = STATUS.branch_rows(
            entry, {"package": "openssl"}, branches, {})
        states = {row["name"]: row["state"] for row in rows}
        self.assertEqual(states["master"], "affected")
        self.assertEqual(states["release-26.05"], "unaffected")

        fix = STATUS.fix_in_progress(
            entry, {"package": "openssl"}, branches, {}, None,
            "nixos-unstable")
        self.assertEqual(fix["fix_state"], "in-release")
        self.assertEqual(fix["fix_branch"], "release-26.05")
        self.assertEqual(fix["fix_version"], "3.6.5")


class BranchInferenceTests(unittest.TestCase):
    """Branches that cannot be newer than an affected master are affected."""

    def test_affected_master_propagates_to_channels_and_staging(self):
        entry = {"affected_products": []}
        branches = {
            "master": {
                "version": "3.8.2",
                "status": "affected",
                "src_position": BISON_NIX,
            },
            "release-26.05": {
                "version": "3.8.2",
                "status": "affected",
                "src_position": BISON_NIX,
            },
        }
        probed = {
            "pkgs/by-name/bi/bison/package.nix": {
                "nixos-unstable": {"version": "3.8.2", "ref": "unstable"},
                "nixos-26.05": {"version": "3.8.2", "ref": "release-26.05"},
                "staging-next": {"version": "3.8.2", "ref": "staging-next"},
                "staging": {"version": "3.8.2", "ref": "staging"},
            },
        }
        rows, _ = STATUS.branch_rows(
            entry, {"package": "bison"}, branches, probed)
        states = {row["name"]: row["state"] for row in rows}
        self.assertEqual(states["master"], "affected")
        self.assertEqual(states["nixos-unstable"], "affected")
        self.assertEqual(states["nixos-26.05"], "affected")
        self.assertEqual(states["staging-next"], "affected")
        self.assertEqual(states["staging"], "affected")
        self.assertEqual(states["release-26.05"], "affected")

        fix = STATUS.fix_in_progress(
            entry, {"package": "bison"}, branches, probed, None,
            "nixos-unstable")
        self.assertIsNone(fix["fix_state"])


class PatchBackportTests(unittest.TestCase):
    """A branch containing the upstream fix hash is fixed by backport."""

    def test_master_patch_is_unaffected_while_release_is_not(self):
        probed = {
            "pkgs/by-name/al/alsa-lib/package.nix": {
                "master": {
                    "version": "1.2.16.1",
                    "ref": "master",
                    "line": 16,
                    "hashes": [ALSA_PATCH],
                },
                "release-26.05": {
                    "version": "1.2.15.3",
                    "ref": "release-26.05",
                    "line": 55,
                    "hashes": [],
                },
            },
        }
        rows, _ = STATUS.branch_rows(
            ALSA_ENTRY, {"package": "alsa-lib"}, ALSA_BRANCHES, probed)
        master = next(row for row in rows if row["name"] == "master")
        release = next(row for row in rows if row["name"] == "release-26.05")
        self.assertTrue(master["patched"])
        self.assertEqual(master["state"], "unaffected")
        self.assertTrue(master["url"].endswith("#L16"))
        self.assertFalse(release["patched"])
        self.assertEqual(release["state"], "affected")
        self.assertTrue(release["url"].endswith("#L55"))

        fix = STATUS.fix_in_progress(
            ALSA_ENTRY, {"package": "alsa-lib"}, ALSA_BRANCHES, probed,
            None, "nixos-unstable")
        self.assertEqual(fix["fix_state"], "in-master")
        self.assertEqual(fix["fix_branch"], "master")


class TriageStatusTests(unittest.TestCase):
    def test_triage_failure_releases_the_report_with_a_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "status.json"
            path.write_text(json.dumps({
                "schema_version": 7,
                "state": "vulnerable",
                "triage_ready": False,
                "triage_failed": False,
            }))
            self.assertEqual(STATUS.triage_failed_mode(str(path)), 0)
            data = json.loads(path.read_text())
            self.assertTrue(data["triage_ready"])
            self.assertTrue(data["triage_failed"])


class TrackerApplicabilityTests(unittest.TestCase):
    def test_compact_suggestion_keeps_ignored_packages(self):
        compact = STATUS.compact_suggestion({
            "id": 3625,
            "status": "published",
            "issue_code": "NIXPKGS-2026-0627",
            "packages": {
                "openssh_gssapi": {
                    "branches": {
                        "master": {"version": "10.2p1", "status": "affected"},
                    },
                },
            },
            "ignored_packages": {
                "openssh": {"branches": {}},
            },
            "affected_products": [{"name": "openssh", "version_constraints": []}],
        })
        self.assertEqual(compact["ignored_packages"], ["openssh"])
        self.assertEqual(list(compact["packages"]), ["openssh_gssapi"])


if __name__ == "__main__":
    unittest.main()
