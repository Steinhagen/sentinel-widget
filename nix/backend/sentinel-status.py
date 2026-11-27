#!/usr/bin/env python3
"""Turn vulnxscan's CSV report into status.json for the Sentinel Plasma applet.

The applet reads this file; the fields here are the contract between the scan
service and the applet (see system/sentinel.nix).

Usage: sentinel-status.py report REPORT STATUS LOG EXIT_CODE [EVIDENCE]
       sentinel-status.py tracker STATUS TRACKER_CACHE

Findings are also enriched with a dependency origin: vulnxscan's
--evidence-out names the store paths a finding was matched to, and the
runtime closure graph (nix-store --query --graph) is walked from those paths
up to the first non-system package. status.json carries the result as
`origins` (introduced_by, chain, chains, store_paths), so the applet can show
which top-level package pulled in the vulnerable copy.

Findings are also enriched with the public Nixpkgs security tracker API:
https://tracker.security.nixos.org/api/v1/suggestions/by-cve/<CVE>
The API token comes from the applet's settings (stored in the user's KConfig
file) or from a root-readable token file. Tracker responses are cached so a
daily scan only looks up new CVEs (and refreshes old entries once a week); a
tracker outage never fails the scan.

The tracker only evaluates master and the release branches, which is not enough
to answer "is this fixed?": a curl-style update lands in the nixpkgs `staging`
branches weeks before the next cycle merges it into master, and a security fix
can already sit on the release branch (or in `nixos-XX.YY`) while master still
carries the affected version. The package file named by the tracker's master
src_position is therefore also read from the staging branches and, at the
channel's own git revision, from `nixos-unstable` and the stable channel. Those
are plain file fetches from raw.githubusercontent.com and channels.nixos.org
(cached for PROBE_TTL), so they do not count against the tracker API budget.

Each finding gets one row per checked ref (channel, master, staging branch,
release branch) with a fixed/affected/unknown verdict, so the applet can show
where an update would get the fix instead of only what master says.
"""

import concurrent.futures
import csv
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TRACKER_BASE = os.environ.get(
    "SENTINEL_TRACKER_BASE", "https://tracker.security.nixos.org"
).rstrip("/")
# Anonymous access is limited to 30 requests/minute, which is too slow to look
# up a whole system closure. Inline status therefore requires an API token:
#   https://tracker.security.nixos.org/user/tokens
TRACKER_TOKEN_FILE = os.environ.get(
    "SENTINEL_TRACKER_TOKEN_FILE", "/var/lib/sentinel/tracker-token"
)
# Plasma stores applet settings in this KConfig file. The applet settings page
# writes sentinelTrackerToken there; the service reads it as root.
APPLET_CONFIG = os.environ.get("SENTINEL_APPLET_CONFIG", "")
TRACKER_USER_AGENT = "sentinel-status/1.3 (NixOS vulnerability applet)"
TRACKER_TIMEOUT = 10
# Authenticated requests are allowed 600/minute; anonymous access 30/minute.
TRACKER_TOKEN_WORKERS = 4
TRACKER_TOKEN_INTERVAL = 1.0
TRACKER_ANON_WORKERS = 1
# 2.1 s between anonymous requests stays just below 30/minute.
TRACKER_ANON_INTERVAL = 2.1
# Stop issuing requests after this many seconds; cached data is still used.
TRACKER_BUDGET = 3600.0
# Write status.json this often while a long anonymous check is running.
TRACKER_WRITE_INTERVAL = 3.0
# Refresh tracker answers weekly; the API allows 600 requests/minute with a
# token, but there is no reason to re-ask every day for every CVE.
TRACKER_TTL = 7 * 24 * 60 * 60
TRACKER_MISS_TTL = TRACKER_TTL
TRACKER_CACHE_MAX_AGE = 30 * 24 * 60 * 60

# Dependency origins: vulnxscan's --evidence-out names the store paths a
# finding was matched to; the runtime closure graph turns those into the
# top-level package that pulls the vulnerable copy in. The service sets
# SENTINEL_NIX_STORE; a test can point it at any nix-store binary.
NIX_STORE = os.environ.get("SENTINEL_NIX_STORE", "nix-store")
ORIGIN_ROOT = os.environ.get("SENTINEL_ORIGIN_ROOT", "/run/current-system")
ORIGIN_MAX_CHAINS = 3
GRAPH_EDGE_RE = re.compile(r'^"([^"]+)"\s*->\s*"([^"]+)"')
# NixOS system wrappers sit between the closure root and the packages. They
# are not the package a user installed, so origin chains start after them.
SCAFFOLDING_NAMES = frozenset(
    {
        "etc",
        "user-environment",
        "system-path",
        "system-units",
        "local-cmds",
        "specialisation",
    }
)
SCAFFOLDING_PREFIXES = ("nixos-system-", "initrd-", "unit-")
# Prefer the main output of a package over its -dev/-doc/-man siblings when
# several outputs land in the closure: the vulnerable library is almost always
# in the main (or -lib/-bin) output, not in the development tree.
OUTPUT_SUFFIX_PENALTY = (
    "-dev",
    "-devdoc",
    "-doc",
    "-man",
    "-debug",
    "-info",
    "-terminfo",
)

# Nixpkgs refs that can carry a fix before it reaches the running system:
#   staging-next / staging — merged, but waiting for the staging cycle
#   nixos-unstable, nixos-XX.YY — the channels users actually update from
#   release-XX.YY — the stable branch the channel is built from
NIXPKGS_RAW = os.environ.get(
    "SENTINEL_NIXPKGS_RAW", "https://raw.githubusercontent.com/NixOS/nixpkgs"
).rstrip("/")
CHANNELS_BASE = os.environ.get(
    "SENTINEL_CHANNELS_BASE", "https://channels.nixos.org"
).rstrip("/")
UNSTABLE_CHANNEL = "nixos-unstable"
# The release the scanned system runs (config.system.nixos.release, e.g.
# "26.05"), used to decide whether a fix reaches *this* system. Empty means
# unknown, in which case nixos-unstable is assumed.
SYSTEM_RELEASE = os.environ.get("SENTINEL_SYSTEM_RELEASE", "").strip()
# An explicit channel is authoritative. Without it, the release is only a
# candidate: the backend picks a channel only when its resolved revision
# matches the system's Nixpkgs revision.
SYSTEM_CHANNEL = os.environ.get("SENTINEL_SYSTEM_CHANNEL", "").strip()
CHANNEL_RE = re.compile(r"^nixos-(?:unstable|[0-9]{2}\.[0-9]{2})$")
# The Nixpkgs revision the scanned system was built from
# (config.system.nixos.revision). Together with the system channel resolved
# below it becomes the package source shown in each finding row.
SYSTEM_NIXPKGS_REV = os.environ.get("SENTINEL_NIXPKGS_REV", "").strip()
SYSTEM_NIXPKGS_FLAKE = (
    os.environ.get("SENTINEL_NIXPKGS_FLAKE", "nixpkgs").strip() or "nixpkgs"
)
STAGING_BRANCHES = ("staging-next", "staging")
# How long a probed ref (branch head or channel revision) is trusted. Staging
# moves slowly (one cycle is weeks); a channel pointer is re-resolved more
# often, and a package file is re-read whenever that pointer moves.
PROBE_TTL = 24 * 60 * 60
CHANNEL_TTL = 2 * 60 * 60
PROBE_TIMEOUT = 15
PROBE_WORKERS = 4

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
# The tracker's src_position is a GitHub blob permalink; keep the repo path so
# the same file can be fetched from another branch.
COMMIT_HASH_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
NIXPKGS_BLOB_RE = re.compile(
    r"^https?://github\.com/NixOS/nixpkgs/(?:blob|tree)/[0-9a-f]+/(.+?)(?:#.*)?$"
)
VERSION_ASSIGN_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"\s*;', re.MULTILINE)
SIMPLE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+_-]*$")
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class RateLimiter:
    """Spread requests so the tracker's authenticated throttle is not tripped."""

    def __init__(self, interval):
        self._interval = interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            time.sleep(delay)


def read_applet_config_token():
    """Read sentinelTrackerToken from the Plasma applet's KConfig file."""
    if not APPLET_CONFIG:
        return ""
    try:
        with open(APPLET_CONFIG, errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return ""
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("sentinelTrackerToken="):
            value = line.split("=", 1)[1].strip()
            return value.strip('"')
    return ""


def read_tracker_token():
    # The applet's settings page is the primary interface. A root-readable
    # token file remains available for sops/automation and is used when the
    # applet setting is empty.
    token = read_applet_config_token()
    if token:
        return token
    if not TRACKER_TOKEN_FILE:
        return ""
    try:
        with open(TRACKER_TOKEN_FILE) as handle:
            return handle.read().strip()
    except OSError:
        return ""


def read_report(path):
    try:
        with open(path, newline="") as handle:
            return [row for row in csv.reader(handle) if row]
    except (OSError, csv.Error):
        return []


def severity_band(severity):
    # vulnxscan leaves the score empty when none is known; some scanners write
    # 0.0 for that as well, which is not a meaningful CVSS score here.
    if severity is None or severity <= 0:
        return "unknown"
    if severity >= 9.0:
        return "critical"
    if severity >= 7.0:
        return "high"
    if severity >= 4.0:
        return "medium"
    return "low"


def parse_findings(rows):
    findings = 0
    maxsev = 0.0
    packages_affected = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    vulnerabilities = []

    if not rows:
        return findings, maxsev, packages_affected, severity_counts, vulnerabilities

    header = [c.strip().lower() for c in rows[0]]
    has_header = any(c in header for c in ("vuln_id", "package", "severity"))
    data = rows[1:] if has_header else rows

    def column(*names):
        for name in names:
            if name in header:
                return header.index(name)
        return None

    i_id = column("vuln_id", "vulnerability", "cve", "id")
    i_pkg = column("package", "pkg", "name")
    i_ver = column("version_local", "version")
    i_sev = column("severity", "cvss", "score")
    i_url = column("url", "link")
    i_grype = column("grype")
    i_osv = column("osv")
    i_vulnix = column("vulnix")
    i_scope = column("evidence_scope")
    i_patch = column("patch_state")

    def cell(row, index):
        return row[index] if index is not None and index < len(row) else ""

    parsed = []
    packages = set()
    for row in data:
        raw = cell(row, i_sev).strip()
        try:
            severity = float(raw) if raw not in ("", "-") else None
        except ValueError:
            severity = None
        if severity is not None and severity <= 0:
            severity = None
        parsed.append((severity, row))
        package = cell(row, i_pkg)
        if package:
            packages.add(package)

    findings = len(parsed)
    packages_affected = len(packages)
    for severity, _ in parsed:
        severity_counts[severity_band(severity)] += 1

    scored = [severity for severity, _ in parsed if severity is not None]
    if scored:
        maxsev = max(scored)

    # Highest score first; findings without a CVSS score go last instead of
    # masquerading as "0.0".
    parsed.sort(key=lambda item: item[0] if item[0] is not None else -1.0, reverse=True)

    vulnerabilities = [
        {
            "id": cell(row, i_id),
            "package": cell(row, i_pkg),
            "version": cell(row, i_ver),
            "severity": round(severity, 1) if severity is not None else None,
            "url": cell(row, i_url),
            "scanners": [
                name
                for name, index in (
                    ("grype", i_grype),
                    ("osv", i_osv),
                    ("vulnix", i_vulnix),
                )
                if index is not None and cell(row, index) == "1"
            ],
            "confidence": cell(row, i_scope),
            "patch_state": cell(row, i_patch),
        }
        for severity, row in parsed
    ]
    return findings, maxsev, packages_affected, severity_counts, vulnerabilities


def load_tracker_cache(path):
    try:
        with open(path) as handle:
            raw = handle.read()
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            data.setdefault("issues", {})
            # Remember the on-disk text so the first save of a run that changed
            # nothing is a no-op as well.
            _TRACKER_CACHE_SNAPSHOT[path] = raw
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "entries": {}, "issues": {}}


# Serialized cache text last written, by path. The pass saves the cache after
# every phase; when all answers are cached there is nothing new to write and
# rewriting the multi-megabyte file is pure SSD wear.
_TRACKER_CACHE_SNAPSHOT = {}


def save_tracker_cache(path, cache):
    try:
        data = json.dumps(cache, ensure_ascii=False, separators=(",", ":"))
        if _TRACKER_CACHE_SNAPSHOT.get(path) == data:
            return False
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w") as handle:
            handle.write(data)
        os.replace(temporary, path)
        _TRACKER_CACHE_SNAPSHOT[path] = data
        return True
    except OSError as error:
        print("WARN     cannot write tracker cache: %s" % error, file=sys.stderr)
        return False


def compact_suggestion(suggestion):
    """Keep only what the applet needs, dropping descriptions and maintainers."""
    packages = {}
    for name, info in (suggestion.get("packages") or {}).items():
        branches = {}
        for branch, data in (info.get("branches") or {}).items():
            branches[branch] = {
                "version": data.get("version"),
                "status": data.get("status"),
                "src_position": data.get("src_position"),
            }
        packages[name] = branches
    return {
        "status": suggestion.get("status"),
        "issue": suggestion.get("issue_code"),
        "suggestion_id": suggestion.get("id"),
        "packages": packages,
        "ignored_packages": sorted(
            (suggestion.get("ignored_packages") or {}).keys()),
        "affected_products": suggestion.get("affected_products") or [],
    }


def fetch_tracker_entry(cve, deadline, stop, token, limiter, flags):
    limiter.wait()
    if stop.is_set() or time.monotonic() >= deadline:
        return None, "skipped"
    url = "%s/api/v1/suggestions/by-cve/%s" % (
        TRACKER_BASE,
        urllib.parse.quote(cve, safe=""),
    )
    headers = {"Accept": "application/json", "User-Agent": TRACKER_USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TRACKER_TIMEOUT) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"checked_at": int(time.time()), "found": False}, None
        if error.code in (401, 403):
            flags["auth_failed"] = True
            stop.set()
        elif error.code == 429:
            # Be a good citizen: stop the rest of this run on rate limiting.
            flags["throttled"] = True
            stop.set()
        return None, "HTTP %d" % error.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return None, str(error)
    return {
        "checked_at": int(time.time()),
        "found": True,
        **compact_suggestion(payload),
    }, None


def fetch_issue_entry(code, deadline, stop, token, limiter, flags):
    """Look up a NIXPKGS security issue for its GitHub issue/fix link."""
    limiter.wait()
    if stop.is_set() or time.monotonic() >= deadline:
        return None, "skipped"
    url = "%s/api/v1/issues/%s" % (
        TRACKER_BASE,
        urllib.parse.quote(code, safe=""),
    )
    headers = {"Accept": "application/json", "User-Agent": TRACKER_USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TRACKER_TIMEOUT) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"checked_at": int(time.time()), "found": False}, None
        if error.code in (401, 403):
            flags["auth_failed"] = True
            stop.set()
        elif error.code == 429:
            flags["throttled"] = True
            stop.set()
        return None, "HTTP %d" % error.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return None, str(error)

    state = ""
    for value in payload.get("github_issue_state") or []:
        if value in ("OPEN", "CLOSED"):
            state = value.lower()
            break
    return {
        "checked_at": int(time.time()),
        "found": True,
        "code": payload.get("code") or code,
        "github_issue_url": payload.get("github_issue_url"),
        "state": state,
    }, None


def fetch_package_suggestions(package, deadline, stop, token, limiter, flags):
    """Return every suggestion that mentions this package.

    The tracker has no CVE batch endpoint, but the suggestions list supports
    ?package=, which returns the full suggestion objects (packages, master
    branch state and affected ranges) in a handful of 25-item pages.
    """
    suggestions = []
    url = "%s/api/v1/suggestions?package=%s" % (
        TRACKER_BASE, urllib.parse.quote(package, safe="")
    )
    pages = 0
    while url:
        pages += 1
        if pages > 40:
            break
        limiter.wait()
        if stop.is_set() or time.monotonic() >= deadline:
            return suggestions, "skipped"
        headers = {"Accept": "application/json", "User-Agent": TRACKER_USER_AGENT}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=TRACKER_TIMEOUT) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                flags["auth_failed"] = True
                stop.set()
            elif error.code == 429:
                flags["throttled"] = True
                stop.set()
            return suggestions, "HTTP %d" % error.code
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            return suggestions, str(error)
        suggestions.extend(payload.get("results") or [])
        url = payload.get("next")
    return suggestions, None


def _version_components(value):
    match = re.match(r"^\s*[vV]?(\d+(?:[._-]\d+)*)", str(value or ""))
    if not match:
        return []
    return [int(part) for part in re.split(r"[._-]", match.group(1))]


def _version_prefix_length(left, right):
    left_parts = _version_components(left)
    right_parts = _version_components(right)
    count = 0
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part != right_part:
            break
        count += 1
    return count


def _probe_matches(master_version, probe_version):
    """Whether a channel/staging probe read the matched attribute's file.

    The probe reads one version literal from a package file. Versioned
    attributes often share that file with the default (ffmpeg generic.nix,
    openssl/default.nix), so a probe is only trusted when its leading
    major.minor matches the matched attribute's master version.
    """
    master = _version_components(master_version)
    probe = _version_components(probe_version)
    if not master or not probe:
        return True
    depth = min(2, len(master), len(probe))
    return master[:depth] == probe[:depth]


def _branch_version(branches):
    """The version of the matched attribute, from master or any branch."""
    master = (branches or {}).get("master") or {}
    if master.get("version"):
        return master.get("version")
    for info in (branches or {}).values():
        if isinstance(info, dict) and info.get("version"):
            return info.get("version")
    return ""


def _variant_suffix(candidate, key):
    """The version suffix of a versioned attribute, if this is one.

    ``ffmpeg_8``, ``ffmpeg_8-full``, ``openssl_1_1`` and ``capstone_4`` are
    variants of ``ffmpeg``, ``openssl`` and ``capstone``; ``ffmpeg-full`` is
    an output variant, not a version.
    """
    if not key.startswith(candidate):
        return None
    rest = key[len(candidate):]
    if not rest or rest[0] not in "_-":
        return None
    suffix = rest[1:]
    if not re.match(
        r"^\d+(?:[._-]\d+)*(?:-(?:full|headless|unwrapped|wrapper|dev|doc|man|bin|lib))?$",
        suffix,
    ):
        return None
    return suffix


def match_package(packages, name, version=None):
    """Find the suggestion package that corresponds to the finding's package.

    A tracker suggestion can cover several nixpkgs attributes (``ffmpeg``,
    ``ffmpeg_8``, ``ffmpeg_6``, …). The plain name is not enough: master's
    default ``ffmpeg`` may already be 9.x while ``ffmpeg_8`` is still 8.x and
    affected. When the installed major differs from the base attribute's
    major, prefer the versioned attribute for the installed major.
    """
    if not name:
        return None, None
    candidate = name if name in packages else None
    if candidate is None:
        # Nix attribute paths such as python313Packages.ultralytics.
        shortened = [key for key in packages if key.rsplit(".", 1)[-1] == name]
        if len(shortened) == 1:
            candidate = shortened[0]
    if candidate is None:
        for suffix in ("-unwrapped", "-wrapper"):
            candidate = name + suffix
            if candidate in packages:
                break
            candidate = None
    if candidate is None:
        return None, None

    if not version:
        return candidate, packages[candidate]

    # Score every versioned attribute of the base package by how many leading
    # version components match the installed version; the exact base wins a
    # tie. This selects ffmpeg_8 for 8.1.3, openssl_1_1 for 1.1.1w and
    # openssl_3_5 for 3.5.2, not only the bare names.
    options = []
    for key, branches in packages.items():
        suffix = "" if key == candidate else _variant_suffix(candidate, key)
        if suffix is None:
            continue
        options.append({
            "key": key,
            "score": _version_prefix_length(version, _branch_version(branches)),
            "exact": key == candidate,
        })
    if not options:
        return candidate, packages[candidate]
    best = max(options, key=lambda item: (
        item["score"], 1 if item["exact"] else 0, -len(item["key"])))
    return best["key"], packages[best["key"]]


def master_status(branches):
    if not branches:
        return None, None, None
    info = branches.get("master")
    if not info:
        return None, None, None
    status = info.get("status")
    if status not in ("affected", "unaffected"):
        status = "unknown" if status else None
    return status, info.get("version"), info.get("src_position")


def _version_key(value):
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.findall(r"\d+|[A-Za-z]+", value or "")
    )


def _version_cmp(first, second):
    first_key, second_key = _version_key(first), _version_key(second)
    return (first_key > second_key) - (first_key < second_key)


def _version_in_range(version, constraint):
    for part in (constraint or "").split(","):
        part = part.strip()
        match = re.match(r"^(<=|>=|=<|=>|==|=|<|>)\s*(\S+)$", part)
        if not match:
            continue
        op = {"=<": "<=", "=>": ">="}.get(match.group(1), match.group(1))
        cmp = _version_cmp(version, match.group(2))
        if op == "<" and cmp >= 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == ">=" and cmp < 0:
            return False
        if op in ("=", "==") and cmp != 0:
            return False
    return True


def _product_for_package(products, package):
    if not products or not package:
        return None

    def tail(name):
        name = (name or "").rsplit("/", 1)[-1].lower()
        for suffix in ("-unwrapped", "-wrapper"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return name

    wanted = tail(package)
    matches = [product for product in products if tail(product.get("name")) == wanted]
    if len(matches) == 1:
        return matches[0]
    if not matches and len(products) == 1:
        return products[0]
    return None


def product_constraints(products, package):
    """Affected version ranges the CVE lists for this package, if any."""
    product = _product_for_package(products, package)
    if not product:
        return []

    constraints = []
    for item in product.get("version_constraints") or []:
        if (isinstance(item, (list, tuple)) and len(item) >= 2
                and item[0] == "affected" and item[1]):
            constraints.append(item[1])
    return constraints


def _version_line(version):
    """(major, minor) for a version string; None when it has no numbers."""
    match = re.match(r"^\s*(\d+)(?:\.(\d+))?", str(version or ""))
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2) or 0))


def _constraint_upper_bounds(constraint):
    bounds = []
    for part in (constraint or "").split(","):
        match = re.match(r"^(<=|=<|<|=|==)\s*(\S+)$", part.strip())
        if match:
            bounds.append((match.group(1), match.group(2)))
    return bounds


def constraints_for_version(products, package, version):
    """Affected ranges that apply to the version's major/minor line.

    A CVE can list several ranges for different release lines, for example
    ``<4.1.1``, ``<3.5.10`` and ``<4.0.4``.  Comparing a 3.6 version against
    the 4.x ceilings would wrongly call it affected.  Pick the ranges for the
    closest version line at or below the candidate; if there is no such line,
    use the oldest listed line so an older branch is still checked.
    """
    constraints = product_constraints(products, package)
    if not constraints or not version:
        return constraints
    line = _version_line(version)
    if line is None:
        return constraints

    candidates = []
    for constraint in constraints:
        bound_line = None
        for _op, bound in _constraint_upper_bounds(constraint):
            parsed = _version_line(bound)
            if parsed is None or parsed[0] != line[0]:
                continue
            if bound_line is None or parsed > bound_line:
                bound_line = parsed
        if bound_line is not None:
            candidates.append((bound_line, constraint))
    if not candidates:
        return []

    below = [entry for entry in candidates if entry[0] <= line]
    selected_line = (max(entry[0] for entry in below) if below
                     else min(entry[0] for entry in candidates))
    selected = []
    for candidate_line, constraint in candidates:
        if candidate_line == selected_line and constraint not in selected:
            selected.append(constraint)
    return selected


def version_verdict(products, package, version):
    """affected/unaffected for one version, from the applicable line ranges."""
    constraints = constraints_for_version(products, package, version)
    if not constraints or not version:
        return None
    if any(_version_in_range(version, constraint) for constraint in constraints):
        return "affected"
    return "unaffected"


def derive_master_status(products, package, version):
    """Use the CVE's affected range when the tracker has no master verdict.

    The tracker sometimes leaves branches.master.status as "unknown" even
    though the branch version is known. The CVE's affected_products ranges
    still let us say whether that version is inside the affected range.
    """
    verdict = version_verdict(products, package, version)
    if verdict is None:
        return None, None
    return verdict, ", ".join(product_constraints(products, package))


def package_file_path(src_position):
    """Nixpkgs-relative path from a tracker GitHub permalink."""
    if not src_position or not isinstance(src_position, str):
        return None
    match = NIXPKGS_BLOB_RE.match(src_position.strip())
    return match.group(1) if match else None


def fix_hashes_of(products):
    """Commit hashes the tracker marks as fixed (unaffected ==<hash>)."""
    result = []
    for product in products or []:
        for constraint in product.get("version_constraints") or []:
            if not isinstance(constraint, (list, tuple)) or len(constraint) != 2:
                continue
            kind, value = constraint
            if kind != "unaffected":
                continue
            value = str(value or "").strip().lstrip("=").strip()
            if COMMIT_HASH_RE.fullmatch(value):
                result.append(value.lower())
    return sorted(set(result))


def package_file_line(src_position):
    """Line anchor from a tracker GitHub permalink (#L123)."""
    if not src_position or not isinstance(src_position, str):
        return None
    match = re.search(r"#L(\d+)", src_position)
    return int(match.group(1)) if match else None


def fetch_channel_rev(channel, deadline, stop):
    """Resolve a nixpkgs channel (nixos-unstable, nixos-26.05) to a git rev."""
    if stop.is_set() or time.monotonic() >= deadline:
        return None, "skipped"
    url = "%s/%s/git-revision" % (CHANNELS_BASE, urllib.parse.quote(channel, safe=""))
    request = urllib.request.Request(
        url, headers={"User-Agent": TRACKER_USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            revision = response.read(200).decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as error:
        return None, "HTTP %d" % error.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return None, str(error)
    if not GIT_REVISION_RE.match(revision):
        return None, "bad revision"
    return revision, None


def fetch_ref_version(path, ref, deadline, stop):
    """Read the package's version literal from another nixpkgs ref.

    ``ref`` is a branch name or a commit id. This is a plain file fetch from
    raw.githubusercontent.com, not a tracker API call, so it is not part of the
    rate-limited CVE budget.
    """
    if stop.is_set() or time.monotonic() >= deadline:
        return None, None, [], "skipped"
    url = "%s/%s/%s" % (
        NIXPKGS_RAW, urllib.parse.quote(ref, safe=""), urllib.parse.quote(path, safe="/")
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": TRACKER_USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            data = response.read(2 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return None, None, [], "HTTP %d" % error.code
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return None, None, [], str(error)

    # Generated package sets (hackage-packages.nix, ...) contain thousands of
    # version assignments; a single one is the package's own version.
    matches = list(VERSION_ASSIGN_RE.finditer(data))
    if len(matches) != 1 or not SIMPLE_VERSION_RE.match(matches[0].group(1)):
        return None, None, [], "no version"
    line = data.count("\n", 0, matches[0].start()) + 1
    hashes = sorted({match.group(0).lower()
                     for match in COMMIT_HASH_RE.finditer(data)})
    return matches[0].group(1), line, hashes, None


def affected_ceiling(products, package, version=None):
    """Highest version the CVE's applicable ranges still cover, if bounded.

    Returns (version, exclusive) or (None, False). Used to tell a real fix
    apart from an older branch that is outside the range only because the
    vulnerability was introduced later.
    """
    constraints = (constraints_for_version(products, package, version)
                   if version is not None
                   else product_constraints(products, package))
    ceiling = None
    exclusive = False
    for constraint in constraints:
        for part in constraint.split(","):
            part = part.strip()
            match = re.match(r"^(<=|=<|<|=|==)\s*(\S+)$", part)
            if not match:
                continue
            if ceiling is None or _version_cmp(match.group(2), ceiling) > 0:
                ceiling = match.group(2)
                exclusive = match.group(1) == "<"
    return ceiling, exclusive


def is_fixed_version(products, package, version):
    """True when this version is outside the affected range and newer than it."""
    if version_verdict(products, package, version) != "unaffected":
        return False
    ceiling, exclusive = affected_ceiling(products, package, version)
    if ceiling is None:
        return True
    comparison = _version_cmp(version, ceiling)
    return comparison >= 0 if exclusive else comparison > 0


def ref_state(products, package, version, status=None):
    """unaffected/affected/unknown for one version on one ref."""
    if status in ("unaffected", "affected"):
        return status
    if not version:
        return "unknown"
    if version_verdict(products, package, version) is None:
        return "unknown"
    return "unaffected" if is_fixed_version(products, package, version) else "affected"


def branch_rows(entry, item, branches, probed):
    """One row per nixpkgs ref that can carry the fix, in display order."""
    products = entry.get("affected_products") or []
    package = item.get("package") or ""
    master = branches.get("master") or {}
    path = package_file_path(master.get("src_position"))
    readings = dict(probed.get(path) or {}) if path else {}
    fix_hashes = fix_hashes_of(products)

    rows = []

    def add(name, version, kind, ref=None, status=None, line=None, hashes=None):
        if not version:
            return
        url = None
        if ref and path:
            url = "https://github.com/NixOS/nixpkgs/blob/%s/%s" % (ref, path)
            if line:
                url += "#L%d" % int(line)
        patches = [str(item).lower() for item in (hashes or [])]
        patched = any(hash_value in patches for hash_value in fix_hashes)
        rows.append({
            "name": name,
            "version": version,
            "kind": kind,
            "state": "unaffected" if patched
                else ref_state(products, package, version, status),
            "patched": patched,
            "url": url,
        })

    # Channels first: they are what an update actually pulls. The probe reads
    # one version literal from the package file; a versioned attribute such as
    # ffmpeg_8 shares generic.nix with the default ffmpeg. Ignore a channel
    # reading whose major does not match the matched attribute.
    master_version = (master or {}).get("version")
    for name in sorted(
        (ref for ref in readings if ref.startswith("nixos-")),
        key=lambda ref: (ref != UNSTABLE_CHANNEL, ref),
    ):
        channel_version = (readings[name] or {}).get("version")
        if (master_version and channel_version
                and not _probe_matches(master_version, channel_version)):
            continue
        add(name, channel_version, "channel",
            (readings[name] or {}).get("ref") or name,
            line=(readings[name] or {}).get("line"),
            hashes=(readings[name] or {}).get("hashes"))
    master_reading = readings.get("master") or {}
    master_version = master_reading.get("version") or master.get("version")
    master_status = master.get("status")
    if (master_reading.get("version") and master.get("version")
            and master_reading.get("version") != master.get("version")):
        master_status = None
    add("master", master_version, "branch",
        master_reading.get("ref") or "master", master_status,
        line=master_reading.get("line")
            or package_file_line(master.get("src_position")),
        hashes=master_reading.get("hashes"))
    for name in STAGING_BRANCHES:
        if name in readings:
            staging_version = (readings[name] or {}).get("version")
            if (master_version and staging_version
                    and not _probe_matches(master_version, staging_version)):
                continue
            add(name, staging_version, "staging",
                (readings[name] or {}).get("ref") or name,
                line=(readings[name] or {}).get("line"),
                hashes=(readings[name] or {}).get("hashes"))
    for name in sorted(branches):
        if name.startswith("release-"):
            info = branches.get(name) or {}
            reading = readings.get(name) or {}
            version = reading.get("version") or info.get("version")
            status = info.get("status")
            if (reading.get("version") and info.get("version")
                    and reading.get("version") != info.get("version")):
                status = None
            add(name, version, "release",
                reading.get("ref") or name, status,
                line=reading.get("line")
                    or package_file_line(info.get("src_position")),
                hashes=reading.get("hashes"))

    # A branch that is not newer than an affected source cannot carry a
    # version-based fix.  nixos-unstable and staging* follow master; a
    # nixos-XX.YY channel follows its release-XX.YY branch.  This is how the
    # Nixpkgs fix flow works: staging -> staging-next -> master -> unstable.
    # The tracker only returns explicit master/release verdicts; the versions
    # above were probed from the other refs.
    master_row = next((row for row in rows if row["name"] == "master"), None)
    if master_row and master_row["state"] == "affected":
        master_version = master_row.get("version") or ""
        for row in rows:
            if row["state"] != "unknown" or not row.get("version"):
                continue
            if master_version and _version_cmp(row["version"], master_version) > 0:
                continue
            if row["kind"] == "channel" and row["name"] == UNSTABLE_CHANNEL:
                row["state"] = "affected"
            elif row["kind"] == "staging":
                row["state"] = "affected"
            elif row["kind"] == "channel" and row["name"].startswith("nixos-"):
                release_name = "release-" + row["name"][len("nixos-"):]
                source = next(
                    (candidate for candidate in rows
                     if candidate["name"] == release_name), None)
                if source and source["state"] == "affected":
                    row["state"] = "affected"
    return rows, path


def fix_in_progress(entry, item, branches, probed, issue_state,
                    system_channel=UNSTABLE_CHANNEL):
    """Where a fix is, relative to the channel the scanned system runs.

    fix_state answers "can an update fix this *system*?":
      fixed      — the system's channel (nixos-unstable or nixos-XX.YY) has it
      in-master  — master has it; the channel picks it up with the next bump
      in-staging — only staging-next/staging have it (next staging cycle)
      in-release — only another channel/release branch has it (e.g. 26.05)
      issue-open — nothing merged, the security issue is open
      None       — nothing known
    fix_branches carries the per-ref detail the applet shows in the tooltip.
    """
    rows, path = branch_rows(entry, item, branches, probed)

    def first_fixed(predicate):
        for row in rows:
            if predicate(row) and row["state"] == "unaffected":
                return row
        return None

    system_row = next(
        (row for row in rows if row["name"] == system_channel), None
    )
    system = system_row if system_row and system_row["state"] == "unaffected" else None
    master = first_fixed(lambda row: row["name"] == "master")
    staging = first_fixed(lambda row: row["kind"] == "staging")
    elsewhere = first_fixed(
        lambda row: row["kind"] in ("channel", "release")
        and row["name"] != system_channel
    )

    fix = {
        "fix_state": None,
        "fix_branch": None,
        "fix_version": None,
        "fix_url": None,
        "fix_branches": rows,
        "system_channel": system_channel,
        # False when the channel's package file could not be read (generated
        # or version-less files), so "the channel has it" is unknown.
        "system_known": system_row is not None,
    }
    if system:
        fix["fix_state"] = "fixed"
    elif master:
        fix["fix_state"] = "in-master"
    elif staging:
        fix["fix_state"] = "in-staging"
    elif elsewhere:
        fix["fix_state"] = "in-release"
    elif issue_state == "open":
        fix["fix_state"] = "issue-open"

    chosen = system or master or staging or elsewhere
    if chosen:
        fix["fix_branch"] = chosen["name"]
        fix["fix_version"] = chosen["version"]
        fix["fix_url"] = chosen["url"]
    return fix


def tracker_url(entry, cve):
    if entry.get("issue"):
        return "%s/issues/%s" % (TRACKER_BASE, entry["issue"])
    if entry.get("suggestion_id"):
        return "%s/suggestions/by-id/%s" % (TRACKER_BASE, entry["suggestion_id"])
    return "%s/suggestions/by-cve/%s" % (TRACKER_BASE, cve)


def status_stamp(status):
    return status.get("scanned_at_iso") or status.get("scanned_at") or ""


def select_system_channel(channel_cache, channel_refs, explicit, system_rev):
    """Pick the channel the system runs, without guessing from the release."""
    if explicit and CHANNEL_RE.fullmatch(explicit):
        return explicit
    if not system_rev:
        return ""
    for channel in channel_refs:
        revision = (channel_cache.get(channel) or {}).get("rev")
        if revision and revision == system_rev:
            return channel
    return ""


def system_source(channel):
    """The Nixpkgs source the scanned system was built from.

    The applet shows this under the CVE instead of repeating it in every
    finding: the system closure was evaluated with this Nixpkgs revision,
    which is the package source a finding can be traced to. An empty ref
    means the channel is unknown; showing only the revision is more honest
    than guessing a stable channel from the NixOS release.
    """
    if not GIT_REVISION_RE.match(SYSTEM_NIXPKGS_REV):
        return None
    return {
        "kind": "nixos" if SYSTEM_RELEASE else "nixpkgs",
        "flake": SYSTEM_NIXPKGS_FLAKE,
        "ref": channel or "",
        "rev": SYSTEM_NIXPKGS_REV,
        "short_rev": SYSTEM_NIXPKGS_REV[:7],
    }


def load_status(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save_status(path, data):
    temporary = path + ".tmp"
    with open(temporary, "w") as handle:
        json.dump(data, handle, ensure_ascii=False)
        handle.write("\n")
    os.replace(temporary, path)


def _store_basename(path):
    return os.path.basename((path or "").rstrip("/"))


def _display_name(node):
    """Package name and version without the 32-character store hash."""
    base = _store_basename(node)
    match = re.match(r"^[0-9a-z]{32}-(.+)$", base)
    return match.group(1) if match else base


def _is_scaffolding(node):
    name = _display_name(node)
    return name in SCAFFOLDING_NAMES or any(
        name.startswith(prefix) for prefix in SCAFFOLDING_PREFIXES
    )


def load_closure_graph(root):
    """Return child -> parents from nix-store's DOT closure graph.

    The edges point from a store path to the paths that reference it, so
    following them walks a vulnerable component up to the package that pulls
    it in. The graph is read once per scan; one `nix why-depends` per finding
    would be much slower.
    """
    try:
        completed = subprocess.run(
            [NIX_STORE, "--query", "--graph", root],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        print(
            "WARN     origins: cannot read the closure graph: %s" % error,
            file=sys.stderr,
        )
        return {}
    parents = {}
    for line in completed.stdout.splitlines():
        match = GRAPH_EDGE_RE.match(line)
        if not match:
            continue
        child, parent = match.group(1), match.group(2)
        # nix-store prints store paths without the /nix/store prefix, but
        # normalizing both sides keeps this working if that ever changes.
        parents.setdefault(_store_basename(child), set()).add(
            _store_basename(parent)
        )
    return parents


def _shortest_chain(parents, target):
    """Path from the first non-system parent down to the target store path."""
    target = _store_basename(target)
    if target not in parents:
        return None
    queue = [target]
    previous = {target: None}
    end = None
    head = 0
    while head < len(queue):
        node = queue[head]
        head += 1
        if _is_scaffolding(node):
            end = node
            break
        for parent in sorted(parents.get(node, ())):
            if parent not in previous:
                previous[parent] = node
                queue.append(parent)
    if end is None:
        return None
    path = []
    node = end
    while node is not None:
        path.append(node)
        node = previous[node]
    # `path` runs from the scaffolding node down to the target. Drop the
    # system wrappers (etc, user-environment, ...) so the first remaining
    # node is the package that actually introduces the vulnerable copy.
    chain = []
    started = False
    for node in path:
        if not started and _is_scaffolding(node):
            continue
        started = True
        chain.append(node)
    return chain or None


def load_evidence(path):
    """Map (vulnerability, package, version) to evidence components."""
    if not path:
        return {}
    try:
        with open(path) as handle:
            document = json.load(handle)
    except (OSError, ValueError) as error:
        print(
            "WARN     origins: cannot read evidence: %s" % error,
            file=sys.stderr,
        )
        return {}
    if not isinstance(document, dict):
        return {}
    by_finding = {}
    for component in document.get("components") or []:
        if not isinstance(component, dict):
            continue
        finding_id = component.get("finding_id")
        if finding_id:
            by_finding.setdefault(finding_id, []).append(component)
    evidence = {}
    for finding in document.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        key = (
            str(finding.get("vuln_id") or ""),
            str(finding.get("package") or ""),
            str(finding.get("version") or ""),
        )
        evidence[key] = by_finding.get(finding.get("finding_id"), [])
    return evidence


def _output_priority(path):
    base = _store_basename(path)
    if any(base.endswith(suffix) for suffix in OUTPUT_SUFFIX_PENALTY):
        return 2
    if base.endswith("-bin"):
        return 1
    return 0


def _component_paths(component):
    """Output paths for one evidence component, never the .drv path."""
    paths = component.get("output_paths") or []
    if isinstance(paths, str):
        paths = [paths]
    result = [
        path
        for path in paths
        if isinstance(path, str)
        and path.startswith("/nix/store/")
        and not path.endswith(".drv")
    ]
    if not result:
        component_id = component.get("component_id") or ""
        if component_id.startswith("/nix/store/") and not component_id.endswith(".drv"):
            result.append(component_id)
    result.sort(key=_output_priority)
    return result


def origins_for_item(item, evidence, parents, chain_cache):
    """Return the top-level introducer(s) and chain(s) for one finding."""
    key = (
        str(item.get("id") or ""),
        str(item.get("package") or ""),
        str(item.get("version") or ""),
    )
    entries = []
    seen_chains = set()
    for component in evidence.get(key) or []:
        for path in _component_paths(component):
            basename = _store_basename(path)
            if basename not in parents:
                continue
            if basename not in chain_cache:
                chain_cache[basename] = _shortest_chain(parents, basename)
            chain = chain_cache[basename]
            if not chain:
                continue
            names = [_display_name(node) for node in chain]
            signature = tuple(names)
            if signature in seen_chains:
                continue
            seen_chains.add(signature)
            entries.append((_output_priority(path), names, path))
    if not entries:
        return None
    entries.sort(key=lambda entry: (entry[0], len(entry[1]), entry[1][0]))
    chains = [entry[1] for entry in entries]
    store_paths = list(dict.fromkeys(entry[2] for entry in entries))
    introduced_by = []
    for chain in chains:
        if chain[0] not in introduced_by:
            introduced_by.append(chain[0])
    return {
        "introduced_by": introduced_by,
        "chain": chains[0],
        "chains": chains[:ORIGIN_MAX_CHAINS],
        "store_paths": store_paths[:ORIGIN_MAX_CHAINS],
    }


def annotate_origins(vulnerabilities, evidence_path):
    """Attach dependency origins to findings before status.json is written."""
    evidence = load_evidence(evidence_path)
    if not evidence:
        return 0
    parents = load_closure_graph(ORIGIN_ROOT)
    if not parents:
        return 0
    chain_cache = {}
    annotated = 0
    for item in vulnerabilities:
        origins = origins_for_item(item, evidence, parents, chain_cache)
        if origins:
            item["origins"] = origins
            annotated += 1
    print(
        "INFO     Origins: %d/%d finding(s) mapped to a top-level package"
        % (annotated, len(vulnerabilities))
    )
    return annotated


def annotate_tracker(vulnerabilities, entries, complete, fetched=0, failures=0,
                     issues=None, progress=None, probed=None):
    issues = issues or {}
    progress = progress or {}
    probed = probed or {}
    for item in vulnerabilities:
        item.pop("tracker", None)

    cves = {
        item.get("id")
        for item in vulnerabilities
        if item.get("id") and CVE_RE.fullmatch(item["id"])
    }
    summary = {
        "available": False,
        "complete": complete,
        "updated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "cves": len(cves),
        "queried": fetched,
        "failed": failures,
        "tracked": 0,
        "pending": 0,
        "rejected": 0,
        "unaffected": 0,
        "missing": 0,
        "system_channel": progress.get("system_channel") or UNSTABLE_CHANNEL,
        "fix_in_progress": 0,
        "fix_staged": 0,
        "fix_available": 0,
        "phase": progress.get("phase") or ("done" if complete else "pending"),
        "total_cves": progress.get("total_cves", len(cves)),
        "total_issues": progress.get("total_issues", 0),
        "issues_checked": progress.get("issues_checked", 0),
        "issue_failed": progress.get("issue_failed", 0),
        "total_packages": progress.get("total_packages", 0),
        "packages_checked": progress.get("packages_checked", 0),
        "package_failed": progress.get("package_failed", 0),
        "total_probes": progress.get("total_probes", 0),
        "probes_checked": progress.get("probes_checked", 0),
        "probes_failed": progress.get("probes_failed", 0),
        "fallback_total": progress.get("fallback_total", 0),
        "fallback_done": progress.get("fallback_done", 0),
        "fallback_failed": progress.get("fallback_failed", 0),
        "throttled": bool(progress.get("throttled")),
        "auth_failed": bool(progress.get("auth_failed")),
    }

    for item in vulnerabilities:
        entry = entries.get(item.get("id") or "")
        if not entry:
            continue
        summary["available"] = True
        if not entry.get("found"):
            # The tracker answered, but has no CVE-to-derivation linkage for it.
            item["tracker"] = {"found": False}
            summary["missing"] += 1
            continue
        status = entry.get("status")
        if status in ("published", "accepted"):
            summary["tracked"] += 1
        elif status == "pending":
            summary["pending"] += 1
        elif status == "rejected":
            summary["rejected"] += 1

        matched, branches = match_package(
            entry.get("packages") or {}, item.get("package"),
            item.get("version")
        )
        ignored_match = None
        if not matched and item.get("package"):
            ignored_match, _ = match_package(
                {name: {} for name in entry.get("ignored_packages") or []},
                item.get("package"),
            )
        if matched:
            applicability = "applicable"
            applicability_reason = ""
        elif ignored_match:
            applicability = "not-applicable"
            applicability_reason = "package-variant-mismatch"
        elif entry.get("packages"):
            applicability = "unknown"
            applicability_reason = "package-not-in-suggestion"
        else:
            applicability = ""
            applicability_reason = ""
        branch_status, branch_version, branch_src = master_status(branches)
        master_source = "tracker" if branch_status in ("affected", "unaffected") else None
        master_range = None
        if branch_status in (None, "unknown") and branch_version:
            derived, derived_range = derive_master_status(
                entry.get("affected_products") or [],
                item.get("package") or "",
                branch_version,
            )
            if derived:
                branch_status = derived
                master_source = "version"
                master_range = derived_range
        if status == "rejected":
            # A dismissed match is not evidence of a fix.
            branch_status, branch_version, branch_src = None, None, None
            master_source, master_range = None, None
        elif branch_status == "unaffected" and status in ("published", "accepted"):
            summary["unaffected"] += 1
        issue = (issues.get(entry.get("issue")) or {}) if entry.get("issue") else {}
        if status == "rejected":
            fix = {
                "fix_state": None,
                "fix_branch": None,
                "fix_version": None,
                "fix_url": None,
                "fix_branches": [],
            }
        else:
            fix = fix_in_progress(
                entry, item, branches or {}, probed, issue.get("state"),
                progress.get("system_channel") or UNSTABLE_CHANNEL,
            )
        if fix["fix_state"] in ("in-staging", "in-release", "issue-open"):
            summary["fix_in_progress"] += 1
        if fix["fix_state"] == "in-staging":
            summary["fix_staged"] += 1
        if fix["fix_state"] == "fixed":
            summary["fix_available"] += 1
        item["tracker"] = {
            "found": True,
            "status": status,
            "issue": entry.get("issue"),
            "issue_state": issue.get("state"),
            "url": tracker_url(entry, item.get("id") or ""),
            "matched_package": matched,
            "applicability": applicability,
            "applicability_reason": applicability_reason,
            "ignored_packages": entry.get("ignored_packages") or [],
            "master_status": branch_status,
            "master_version": branch_version,
            "master_status_source": master_source,
            "master_range": master_range,
            "master_url": branch_src,
            "github_issue_url": issue.get("github_issue_url"),
            "suggestion_packages": sorted((entry.get("packages") or {}).keys()),
            "affected_products": entry.get("affected_products") or [],
            "system_channel": fix.get("system_channel"),
            "system_known": fix.get("system_known"),
            "fix_state": fix["fix_state"],
            "fix_branch": fix["fix_branch"],
            "fix_version": fix["fix_version"],
            "fix_url": fix["fix_url"],
            "fix_branches": fix["fix_branches"],
        }
    return summary


def tracker_state_digest(status):
    """Canonical form of what a tracker write changes, minus the heartbeat.

    The pass rewrites the whole status file after every phase. Comparing this
    digest with what is already on disk lets a run where nothing changed leave
    the file untouched, which also keeps the applet from re-parsing 1.8 MB for
    no reason.
    """
    tracker = dict(status.get("tracker") or {})
    tracker.pop("updated_at", None)
    items = [
        [item.get("id"), item.get("package"), item.get("version"),
         item.get("tracker")]
        for item in (status.get("vulnerabilities") or [])
    ]
    return json.dumps(
        [status.get("source"), items, tracker], ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )


def write_tracker_status(status_path, base_status, base_stamp, vulnerabilities,
                         entries, issues, progress, complete, fetched, failures,
                         probed=None):
    # A newer scan may have replaced status.json while this check was running.
    current = load_status(status_path)
    if current is None or status_stamp(current) != base_stamp:
        return False
    previous = tracker_state_digest(current)
    base_status["vulnerabilities"] = vulnerabilities
    source = system_source(progress.get("system_channel"))
    if source is not None:
        base_status["source"] = source
    base_status["tracker"] = annotate_tracker(
        vulnerabilities, entries, complete, fetched, failures, issues, progress,
        probed
    )
    if tracker_state_digest(base_status) == previous:
        return True
    save_status(status_path, base_status)
    return True


def triage_failed_mode(status_path):
    status = load_status(status_path)
    if status is None:
        return 1
    status["triage_ready"] = True
    status["triage_failed"] = True
    save_status(status_path, status)
    return 0


def tracker_mode(status_path, cache_path):
    status = load_status(status_path)
    if status is None:
        print("WARN     Nixpkgs tracker: cannot read %s" % status_path, file=sys.stderr)
        return 1

    base_stamp = status_stamp(status)
    vulnerabilities = status.get("vulnerabilities") or []
    cves = sorted(
        {
            item.get("id")
            for item in vulnerabilities
            if item.get("id") and CVE_RE.fullmatch(item["id"])
        }
    )
    if not cves:
        return 0

    cache = load_tracker_cache(cache_path)
    entries = cache.setdefault("entries", {})
    issues = cache.setdefault("issues", {})
    probe_cache = cache.setdefault("branches", {})
    # v2 stores the master source URL and issue metadata, v4 the probed branch
    # versions, v5 the channel revisions; refresh old entries once so the
    # applet can show the fix state.
    if int(cache.get("version", 1)) < 6:
        entries.clear()
        probe_cache.clear()
        cache.pop("channels", None)
        cache["version"] = 6
    now = int(time.time())
    for cve in list(entries):
        if now - int(entries[cve].get("checked_at", 0)) > TRACKER_CACHE_MAX_AGE:
            del entries[cve]

    def needs_refresh(cve):
        entry = entries.get(cve)
        if not entry:
            return True
        ttl = TRACKER_TTL if entry.get("found") else TRACKER_MISS_TTL
        return now - int(entry.get("checked_at", 0)) > ttl

    pending = [cve for cve in cves if needs_refresh(cve)]
    token = read_tracker_token()
    if token:
        workers = TRACKER_TOKEN_WORKERS
        interval = TRACKER_TOKEN_INTERVAL
        print("INFO     Nixpkgs tracker: using API token")
    else:
        workers = TRACKER_ANON_WORKERS
        interval = TRACKER_ANON_INTERVAL
        estimate = len(pending) * interval
        estimate_text = (
            "%d min" % round(estimate / 60)
            if estimate >= 120
            else "%d s" % round(estimate)
        )
        print(
            "INFO     Nixpkgs tracker: no API token, using anonymous rate limit"
            " (~%s for %d CVEs)" % (estimate_text, len(pending))
        )

    fetched = 0
    failures = 0
    flags = {"auth_failed": False, "throttled": False}
    progress = {
        "phase": "packages" if pending else "issues",
        "total_cves": len(cves),
        "total_issues": 0,
        "issues_checked": 0,
        "issue_failed": 0,
        "throttled": False,
        "auth_failed": False,
    }

    pending_set = set(pending)
    package_by_cve = {}
    for item in vulnerabilities:
        cve = item.get("id")
        if cve in pending_set and item.get("package"):
            package_by_cve[cve] = item["package"]
    pending_packages = sorted(
        {package_by_cve[cve] for cve in pending if cve in package_by_cve}
    )

    # path -> {ref: {version, ref}}; filled by the probe pass below and read
    # when status.json is written.
    probed_versions = {}

    def publish_progress(phase, **fields):
        progress.update({
            "phase": phase,
            "throttled": flags["throttled"],
            "auth_failed": flags["auth_failed"],
        })
        progress.update(fields)
        save_tracker_cache(cache_path, cache)
        checked = len([cve for cve in cves if cve in entries])
        failed = len([cve for cve in cves if cve not in entries])
        return write_tracker_status(
            status_path, status, base_stamp, vulnerabilities, entries,
            issues, progress, False, checked, failed, probed_versions
        )

    # Package pass: the suggestions list supports ?package=, returning every
    # suggestion for that package (with its master branches and affected
    # ranges) in a few 25-item pages. One request per package instead of one
    # per CVE is the fastest bulk path the API offers.
    progress.update({
        "total_packages": len(pending_packages),
        "packages_checked": 0,
        "package_failed": 0,
        "fallback_total": 0,
        "fallback_done": 0,
        "fallback_failed": 0,
    })
    if pending_packages:
        if not publish_progress("packages"):
            return 0
        package_attempts = 0
        package_queue = list(pending_packages)
        packages_done = 0
        failed_packages = []
        while package_queue and not flags["auth_failed"] and package_attempts < 3:
            package_attempts += 1
            print(
                "INFO     Nixpkgs tracker: package pass %d (%d package(s))%s"
                % (package_attempts, len(package_queue),
                   "" if package_attempts == 1 else " [retry]")
            )
            stop = threading.Event()
            limiter = RateLimiter(interval)
            deadline = time.monotonic() + TRACKER_BUDGET
            last_write = time.monotonic()
            failed_packages = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(
                        fetch_package_suggestions, package, deadline, stop,
                        token, limiter, flags
                    ): package
                    for package in package_queue
                }
                for future in concurrent.futures.as_completed(futures):
                    package = futures[future]
                    try:
                        suggestions, error = future.result()
                    except Exception:
                        suggestions, error = [], "exception"
                    if error:
                        failed_packages.append(package)
                    for suggestion in suggestions:
                        cve = suggestion.get("cve_id")
                        if cve in pending_set:
                            entries[cve] = {
                                "checked_at": now,
                                "found": True,
                                **compact_suggestion(suggestion),
                            }
                    packages_done += 1
                    if time.monotonic() - last_write >= TRACKER_WRITE_INTERVAL:
                        progress.update({
                            "packages_checked": max(
                                0, packages_done - len(failed_packages)
                            ),
                            "package_failed": len(failed_packages),
                        })
                        if not publish_progress("packages"):
                            return 0
                        last_write = time.monotonic()
                        print(
                            "INFO     Nixpkgs tracker: %d package(s), %d failed"
                            % (packages_done, len(failed_packages))
                        )
            save_tracker_cache(cache_path, cache)
            if not failed_packages:
                break
            if flags["throttled"] and package_attempts < 3:
                if not publish_progress("waiting"):
                    return 0
                print(
                    "INFO     Nixpkgs tracker: rate limit hit; waiting 65 s before retrying %d package(s)"
                    % len(failed_packages)
                )
                time.sleep(65)
                flags["throttled"] = False
                package_queue = failed_packages
            else:
                break

        progress.update({
            "packages_checked": max(
                0, len(pending_packages) - len(failed_packages)
            ),
            "package_failed": len(failed_packages),
        })
        if not publish_progress("packages"):
            return 0

    # The package filter is exact; CVEs whose suggestion lives under a
    # different package attribute (or has no suggestion at all) still need
    # the per-CVE endpoint.
    remaining = [cve for cve in pending if cve not in entries]
    progress.update({
        "phase": "cves" if remaining else "done",
        "fallback_total": len(remaining),
        "fallback_done": 0,
        "fallback_failed": 0,
    })
    if remaining:
        if not publish_progress("cves"):
            return 0
        attempts = 0
        while remaining and not flags["auth_failed"] and attempts < 3:
            attempts += 1
            print(
                "INFO     Nixpkgs tracker: checking %d remaining CVE(s), %d cached%s"
                % (len(remaining), len(entries),
                   " (attempt %d/3)" % attempts if attempts > 1 else "")
            )
            stop = threading.Event()
            limiter = RateLimiter(interval)
            deadline = time.monotonic() + TRACKER_BUDGET
            last_write = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(
                        fetch_tracker_entry, cve, deadline, stop, token,
                        limiter, flags
                    ): cve
                    for cve in remaining
                }
                for future in concurrent.futures.as_completed(futures):
                    cve = futures[future]
                    try:
                        entry, _error = future.result()
                    except Exception:
                        entry = None
                    if entry is not None:
                        entries[cve] = entry

                    if time.monotonic() - last_write >= TRACKER_WRITE_INTERVAL:
                        failed_remaining = [
                            item for item in remaining if item not in entries
                        ]
                        progress.update({
                            "fallback_done": len(remaining) - len(failed_remaining),
                            "fallback_failed": len(failed_remaining),
                        })
                        if not publish_progress("cves"):
                            return 0
                        last_write = time.monotonic()
                        print(
                            "INFO     Nixpkgs tracker: %d/%d remaining CVE(s), %d failed"
                            % (len(remaining) - len(failed_remaining), len(remaining),
                               len(failed_remaining))
                        )
            save_tracker_cache(cache_path, cache)

            failed_remaining = [item for item in remaining if item not in entries]
            if not failed_remaining:
                break
            if flags["throttled"] and attempts < 3:
                if not publish_progress("waiting"):
                    return 0
                print(
                    "INFO     Nixpkgs tracker: rate limit hit; waiting 65 s before retrying %d CVE(s)"
                    % len(failed_remaining)
                )
                time.sleep(65)
                flags["throttled"] = False
                remaining = failed_remaining
            else:
                break

        failed_remaining = [cve for cve in remaining if cve not in entries]
        progress.update({
            "fallback_done": len(remaining) - len(failed_remaining),
            "fallback_failed": len(failed_remaining),
        })
        if not publish_progress("cves"):
            return 0

    failures = len([cve for cve in cves if cve not in entries])
    fetched = len([cve for cve in cves if cve in entries])
    progress["throttled"] = flags["throttled"]

    # The tracker evaluates master and the release branches only. Everything
    # else that decides whether an update fixes the finding has to be read
    # directly: the staging branches (merged, waiting for the cycle) and the
    # channels an update actually pulls (nixos-unstable, nixos-XX.YY), whose
    # package files are read at the channel's own git revision.
    needed_paths = {}
    staging_paths = set()
    master_paths = set()
    release_paths = set()
    for item in vulnerabilities:
        entry = entries.get(item.get("id") or "") or {}
        if not entry.get("found"):
            continue
        _matched, branches = match_package(
            entry.get("packages") or {}, item.get("package")
        )
        master = (branches or {}).get("master") or {}
        path = package_file_path(master.get("src_position"))
        if not path:
            continue
        # The channel decides whether the fix is already available, so it is
        # read even when master is fixed (the channel may lag behind master).
        needed_paths[path] = True
        master_paths.add(path)
        for branch_name in (branches or {}):
            if branch_name.startswith("release-"):
                release_paths.add((path, branch_name))
        if master.get("status") == "unaffected":
            continue
        if version_verdict(
            entry.get("affected_products") or [],
            item.get("package") or "",
            master.get("version"),
        ) == "unaffected":
            continue
        # Staging only matters while master is still affected.
        staging_paths.add(path)

    releases = sorted({
        branch
        for entry in entries.values()
        if entry.get("found")
        for branches in (entry.get("packages") or {}).values()
        for branch in branches
        if branch.startswith("release-")
    }, reverse=True)[:2]
    channel_refs = [UNSTABLE_CHANNEL] + [
        "nixos-" + release[len("release-"):] for release in releases[:1]
    ]
    # The channel the scanned system runs; a release without its own channel
    # (an unreleased one, i.e. the unstable line) falls back to nixos-unstable.
    if SYSTEM_RELEASE:
        candidate = "nixos-" + SYSTEM_RELEASE
        if candidate not in channel_refs:
            channel_refs.append(candidate)
    if SYSTEM_CHANNEL and CHANNEL_RE.fullmatch(SYSTEM_CHANNEL):
        if SYSTEM_CHANNEL not in channel_refs:
            channel_refs.append(SYSTEM_CHANNEL)

    for path in list(probe_cache):
        if path not in needed_paths:
            del probe_cache[path]
            continue
        info = probe_cache[path]
        for name in list(info):
            if name.startswith("nixos-") and name not in channel_refs:
                del info[name]

    # Channel pointers move daily; resolve them first so an unchanged channel
    # reuses the package file already cached for its revision.
    channel_cache = cache.setdefault("channels", {})
    for channel in list(channel_cache):
        if channel not in channel_refs:
            del channel_cache[channel]
    stale_channels = [
        channel for channel in channel_refs
        if now - int((channel_cache.get(channel) or {}).get("checked_at", 0)) > CHANNEL_TTL
    ]
    if stale_channels:
        stop = threading.Event()
        deadline = time.monotonic() + TRACKER_BUDGET
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(fetch_channel_rev, channel, deadline, stop): channel
                for channel in stale_channels
            }
            for future in concurrent.futures.as_completed(futures):
                channel = futures[future]
                try:
                    revision, error = future.result()
                except Exception:
                    revision, error = None, "exception"
                if revision:
                    channel_cache[channel] = {"rev": revision, "checked_at": now}
                elif error:
                    print(
                        "INFO     Nixpkgs tracker: cannot resolve %s (%s)"
                        % (channel, error)
                    )
        save_tracker_cache(cache_path, cache)

    # A channel is a NixOS concept. On a non-NixOS Nix installation only an
    # explicit channel is meaningful; otherwise keep the source channel-free
    # and let the applet show "nixpkgs (<rev>)".
    if SYSTEM_RELEASE or SYSTEM_CHANNEL:
        system_channel = select_system_channel(
            channel_cache, channel_refs, SYSTEM_CHANNEL, SYSTEM_NIXPKGS_REV
        )
    else:
        system_channel = ""
    progress["system_channel"] = system_channel

    probe_todo = []
    for path in needed_paths:
        info = probe_cache.setdefault(path, {})
        if path in staging_paths:
            for name in STAGING_BRANCHES:
                cached = info.get(name) or {}
                if (now - int(cached.get("checked_at", 0)) > PROBE_TTL
                        or "line" not in cached
                        or "hashes" not in cached):
                    probe_todo.append((path, name, name))
        if path in master_paths:
            cached = info.get("master") or {}
            if (now - int(cached.get("checked_at", 0)) > PROBE_TTL
                    or "line" not in cached
                    or "hashes" not in cached):
                probe_todo.append((path, "master", "master"))
        for release_path, release_name in sorted(release_paths):
            if release_path != path:
                continue
            cached = info.get(release_name) or {}
            if (now - int(cached.get("checked_at", 0)) > PROBE_TTL
                    or "line" not in cached
                    or "hashes" not in cached):
                probe_todo.append((path, release_name, release_name))
        for channel in channel_refs:
            revision = (channel_cache.get(channel) or {}).get("rev")
            if not revision:
                continue
            cached = info.get(channel) or {}
            if (cached.get("ref") != revision
                    or now - int(cached.get("checked_at", 0)) > PROBE_TTL
                    or "line" not in cached
                    or "hashes" not in cached):
                probe_todo.append((path, channel, revision))
    probe_todo.sort()

    progress.update({
        "total_probes": len(probe_todo),
        "probes_checked": 0,
        "probes_failed": 0,
    })
    if probe_todo:
        if not publish_progress("probes"):
            return 0
        print(
            "INFO     Nixpkgs tracker: checking %d package file(s) on %d nixpkgs ref(s)"
            % (len({path for path, _name, _ref in probe_todo}),
               len({name for _path, name, _ref in probe_todo}))
        )
        stop = threading.Event()
        deadline = time.monotonic() + TRACKER_BUDGET
        last_write = time.monotonic()
        probe_done = 0
        probe_failed = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=PROBE_WORKERS
        ) as pool:
            futures = {
                pool.submit(
                    fetch_ref_version, path, ref, deadline, stop
                ): (path, name, ref)
                for path, name, ref in probe_todo
            }
            for future in concurrent.futures.as_completed(futures):
                path, name, ref = futures[future]
                try:
                    version, line, hashes, error = future.result()
                except Exception:
                    version, line, hashes, error = None, None, [], "exception"
                # A missing file is a real answer (the package is not on that
                # ref); a network failure is not, so retry it next run.
                if error is None or error == "HTTP 404":
                    probe_cache.setdefault(path, {})[name] = {
                        "checked_at": now,
                        "ref": ref,
                        "version": version,
                        "line": line,
                        "hashes": hashes,
                    }
                probe_done += 1
                if error:
                    probe_failed += 1
                progress.update({
                    "probes_checked": probe_done - probe_failed,
                    "probes_failed": probe_failed,
                })
                if time.monotonic() - last_write >= TRACKER_WRITE_INTERVAL:
                    save_tracker_cache(cache_path, cache)
                    if not publish_progress("probes"):
                        return 0
                    last_write = time.monotonic()
        save_tracker_cache(cache_path, cache)
        print(
            "INFO     Nixpkgs tracker: %d ref file(s) fetched, %d failed"
            % (probe_done - probe_failed, probe_failed)
        )

    for path in needed_paths:
        info = probe_cache.get(path) or {}
        readings = {
            name: {
                "version": entry.get("version"),
                "ref": entry.get("ref") or name,
                "line": entry.get("line"),
                "hashes": entry.get("hashes") or [],
            }
            for name, entry in info.items()
            if entry.get("version")
        }
        if readings:
            probed_versions[path] = readings

    # Suggestion payloads carry the master branch state (fixed/affected) and a
    # source URL; the issue endpoint adds the GitHub fix/bump link.
    for code in list(issues):
        if now - int(issues[code].get("checked_at", 0)) > TRACKER_CACHE_MAX_AGE:
            del issues[code]

    issue_codes = sorted(
        {
            entry.get("issue")
            for entry in entries.values()
            if entry.get("found") and entry.get("issue")
        }
    )
    pending_issues = [
        code for code in issue_codes
        if now - int((issues.get(code) or {}).get("checked_at", 0)) > TRACKER_TTL
    ]
    fetched_issues = 0
    failed_issues = 0
    progress.update({
        "phase": "issues" if pending_issues else "done",
        "total_issues": len(pending_issues),
        "issues_checked": 0,
        "issue_failed": 0,
        "throttled": flags["throttled"],
        "auth_failed": flags["auth_failed"],
    })
    if pending_issues and not flags["auth_failed"] and not flags["throttled"]:
        print(
            "INFO     Nixpkgs tracker: checking %d issue(s) for fix links"
            % len(pending_issues)
        )
        stop = threading.Event()
        limiter = RateLimiter(interval)
        deadline = time.monotonic() + TRACKER_BUDGET
        last_write = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    fetch_issue_entry, code, deadline, stop, token, limiter, flags
                ): code
                for code in pending_issues
            }
            for future in concurrent.futures.as_completed(futures):
                code = futures[future]
                try:
                    issue, _error = future.result()
                except Exception:
                    issue = None
                if issue is not None:
                    issues[code] = issue
                    fetched_issues += 1
                else:
                    failed_issues += 1
                progress["issues_checked"] = fetched_issues
                progress["issue_failed"] = failed_issues
                progress["throttled"] = flags["throttled"]
                progress["auth_failed"] = flags["auth_failed"]
                if time.monotonic() - last_write >= TRACKER_WRITE_INTERVAL:
                    save_tracker_cache(cache_path, cache)
                    if not write_tracker_status(
                        status_path, status, base_stamp, vulnerabilities, entries,
                        issues, progress, False, fetched, failures,
                        probed_versions
                    ):
                        save_tracker_cache(cache_path, cache)
                        print(
                            "INFO     Nixpkgs tracker: a newer scan replaced status.json; stopping"
                        )
                        return 0
                    last_write = time.monotonic()
        save_tracker_cache(cache_path, cache)
        print(
            "INFO     Nixpkgs tracker: issues %d fetched, %d failed, %d cached"
            % (fetched_issues, failed_issues, len(issues))
        )

    progress.update({
        "phase": "done",
        "throttled": flags["throttled"],
        "auth_failed": flags["auth_failed"],
    })
    if not write_tracker_status(
        status_path, status, base_stamp, vulnerabilities, entries, issues,
        progress, True, fetched, failures, probed_versions
    ):
        save_tracker_cache(cache_path, cache)
        print(
            "INFO     Nixpkgs tracker: status.json changed during the check; not overwriting it"
        )
        return 0

    if flags["auth_failed"]:
        print(
            "WARN     Nixpkgs tracker rejected the API token; check %s"
            % TRACKER_TOKEN_FILE,
            file=sys.stderr,
        )
    if flags["throttled"]:
        print(
            "WARN     Nixpkgs tracker rate limit hit; remaining CVEs will be checked next run",
            file=sys.stderr,
        )
    print(
        "INFO     Nixpkgs tracker: %d checked, %d failed, %d cached"
        % (fetched, failures, len(entries))
    )
    return 0


def scan_error(log, rc):
    if rc == 0:
        return ""
    try:
        with open(log) as handle:
            lines = [line.strip() for line in handle if line.strip()]
    except OSError:
        return ""
    # Prefer a real error line; vulnxscan also logs INFO lines on success.
    errors = [
        line
        for line in lines
        if line.startswith(("ERROR", "CRITICAL", "Traceback"))
    ]
    if errors:
        return errors[-1][:300]
    return lines[-1][:300] if lines else ""


def scan_mode(report, status, log, rc, evidence_path=""):
    rows = read_report(report)
    findings, maxsev, packages_affected, severity_counts, vulnerabilities = (
        parse_findings(rows)
    )

    # A scan that did not finish must not look like a clean or complete result,
    # even when vulnxscan managed to write a partial CSV.
    if rc != 0:
        state = "unknown"
    elif findings == 0:
        state = "secure"
    elif maxsev >= 7.0:
        state = "vulnerable"
    else:
        state = "warn"

    now = datetime.datetime.now().astimezone()
    # Dependency origins make "which package pulled this in?" a first-class
    # field next to the finding, instead of something the applet has to guess
    # from package names.
    if vulnerabilities:
        annotate_origins(vulnerabilities, evidence_path)
    data = {
        "schema_version": 7,
        "state": state,
        "findings": findings,
        "max_severity": round(maxsev, 1),
        "packages_affected": packages_affected,
        "severity_counts": severity_counts,
        "scanned_at": now.strftime("%Y-%m-%d %H:%M %Z"),
        "scanned_at_iso": now.isoformat(timespec="seconds"),
        "scanned_at_epoch": int(now.timestamp()),
        "exit_code": rc,
        "vulnerabilities": vulnerabilities,
        "triage_ready": False,
        "triage_failed": False,
    }
    error = scan_error(log, rc)
    if error:
        data["error"] = error

    # The tracker service starts right after this report. Publish a pending
    # marker immediately so the applet can show progress while it runs.
    cves = {
        item.get("id")
        for item in vulnerabilities
        if item.get("id") and CVE_RE.fullmatch(item["id"])
    }
    data["tracker"] = {
        "available": False,
        "complete": False,
        "phase": "pending",
        "cves": len(cves),
        "total_cves": len(cves),
        "queried": 0,
        "failed": 0,
        "tracked": 0,
        "pending": 0,
        "rejected": 0,
        "unaffected": 0,
        "missing": 0,
        "system_channel": "",
        "fix_in_progress": 0,
        "fix_staged": 0,
        "fix_available": 0,
        "total_probes": 0,
        "probes_checked": 0,
        "probes_failed": 0,
        "total_issues": 0,
        "issues_checked": 0,
        "issue_failed": 0,
        "throttled": False,
        "auth_failed": False,
        "updated_at": now.isoformat(timespec="seconds"),
    }
    save_status(status, data)
    return 0


def usage():
    print(
        "usage: sentinel-status.py report REPORT STATUS LOG EXIT_CODE [EVIDENCE]",
        file=sys.stderr,
    )
    print(
        "       sentinel-status.py tracker STATUS TRACKER_CACHE",
        file=sys.stderr,
    )


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "tracker":
        return tracker_mode(args[1], args[2])
    if len(args) == 2 and args[0] == "triage-failed":
        return triage_failed_mode(args[1])
    if len(args) == 6 and args[0] == "report":
        return scan_mode(args[1], args[2], args[3], int(args[4]), args[5])
    if len(args) == 5 and args[0] == "report":
        return scan_mode(args[1], args[2], args[3], int(args[4]))
    # Backwards-compatible with the previous invocations.
    if len(args) == 4:
        return scan_mode(args[0], args[1], args[2], int(args[3]))
    if len(args) == 5:
        return scan_mode(args[0], args[1], args[2], int(args[3]))
    usage()
    return 2


if __name__ == "__main__":
    sys.exit(main())
