import QtQml
import QtQuick
import "../domain/time.mjs" as Time
import "../domain/tracker.mjs" as Tracker

// All user-facing copy and token-to-word mapping. Domain modules stay free of
// i18n; components receive this object explicitly.
QtObject {
    id: labels

    readonly property string masterHelpText: i18n("The Fix pill names the stage the fix currently sits in, and “fixed” once it reached the channel this system updates from (nixos-unstable or nixos-XX.YY):\n\n• fixed — the system's channel has a fixed version. Updating the channel fixes the finding.\n• staging — merged into staging-next/staging; it lands in master when the next staging cycle is merged.\n• master — master has it; the channel picks it up with the next channel bump (on a stable system a backport is still needed).\n• 26.05 — fixed on another line; it is not on the way to this system's channel.\n• issue — nothing is merged yet, but the Nixpkgs security issue is open.\n• no fix — still affected in every branch that was checked.\n• unknown / n/a / — — no verdict, no coverage, or no data.\n\nHover the Fix pill for the per-branch table (✓ fixed, ✗ affected, ? unknown), the next step, and ← marking the channel this system runs.")

    function postureLabel(state, hasReport) {
        if (!hasReport) {
            return i18n("Unknown");
        }
        switch (state) {
        case "secure":
            return i18n("Secure");
        case "vulnerable":
            return i18n("Vulnerable");
        case "warn":
            return i18n("Review");
        default:
            return i18n("Unknown");
        }
    }

    function stateIcon(state, hasReport) {
        if (!hasReport) {
            return "security-medium";
        }
        switch (state) {
        case "secure":
            return "security-high";
        case "vulnerable":
            return "security-low";
        default:
            return "security-medium";
        }
    }

    function stateSummary(report, scanning, affectedPackages, maxSeverity) {
        if (!report) {
            return scanning
                ? i18n("The first scan is running…")
                : i18n("No scan has run yet.");
        }
        if (report.state === "unknown") {
            return i18n("The last scan failed — see the scan log for details.");
        }
        const parts = [];
        if (report.state !== "secure") {
            parts.push(i18np("%1 package affected", "%1 packages affected", affectedPackages));
            parts.push(i18n("highest CVSS %1", Number(maxSeverity || 0).toFixed(1)));
        }
        return parts.join(" · ");
    }

    function stateDetail(summary, relative) {
        if (!relative) {
            return summary;
        }
        return summary.length > 0
            ? summary + " · " + i18n("scanned %1", relative)
            : i18n("scanned %1", relative);
    }

    function emptyIcon(state, hasReport) {
        return stateIcon(state, hasReport);
    }

    function emptyTitle(state, hasReport) {
        if (!hasReport) {
            return i18n("Not scanned yet");
        }
        switch (state) {
        case "secure":
            return i18n("No known vulnerabilities");
        case "unknown":
            return i18n("The last scan failed");
        default:
            return i18n("No findings to show");
        }
    }

    function emptyExplanation(state, hasReport, scanning, reportError, loadError) {
        if (loadError && loadError.length > 0) {
            return loadErrorText(loadError);
        }
        if (!hasReport) {
            return scanning
                ? i18n("The first scan can take a while: it has to download the vulnerability databases.")
                : i18n("The scan runs automatically once a day and can also be started manually.");
        }
        switch (state) {
        case "secure":
            return i18n("The last scan found no known vulnerabilities.");
        case "unknown":
            return reportError || i18n("Open the scan log for details.");
        default:
            return "";
        }
    }

    function severityBandLabel(band) {
        switch (band) {
        case "critical":
            return i18n("Critical");
        case "high":
            return i18n("High");
        case "medium":
            return i18n("Medium");
        case "low":
            return i18n("Low");
        case "unknown":
            return i18n("Unknown");
        default:
            return i18n("All");
        }
    }

    function fixBucketLabel(bucket) {
        switch (bucket) {
        case "fixed":
            return i18n("Fixed");
        case "progress":
            return i18n("Pending");
        case "none":
            return i18n("No fix");
        case "unknown":
            return i18n("Unknown");
        case "n/a":
            return i18n("n/a");
        default:
            return i18n("All");
        }
    }

    function fixFilterLabel(bucket) {
        switch (bucket) {
        case "fixed":
            return i18n("Fix available");
        case "progress":
            return i18n("Fix pending");
        case "none":
            return i18n("No fix");
        case "unknown":
            return i18n("Unknown fix state");
        case "n/a":
            return i18n("n/a");
        default:
            return i18n("All fix states");
        }
    }

    function trackerFilterLabel(key) {
        switch (key) {
        case "linked":
            return i18n("In tracker");
        case "pending":
            return i18n("Pending");
        case "missing":
            return i18n("Missing");
        case "unchecked":
            return i18n("Not checked");
        default:
            return i18n("All");
        }
    }

    function fixText(fix) {
        if (!fix) {
            return i18n("unknown");
        }
        switch (fix.labelKey) {
        case "fixed":
            return i18n("fixed");
        case "staging":
            return i18n("staging");
        case "master":
            return i18n("master");
        case "release":
            return fix.labelArg && fix.labelArg.length > 0
                ? fix.labelArg : i18n("unknown");
        case "issue":
            return i18n("issue");
        case "no fix":
            return i18n("no fix");
        case "n/a":
            return i18n("n/a");
        case "unknown":
        default:
            return i18n("unknown");
        }
    }

    function confidenceLabel(value) {
        switch (value) {
        case "component_exact":
            return i18n("exact");
        case "component_expanded":
            return i18n("expanded");
        case "component_mixed":
            return i18n("mixed");
        case "package_version_only":
            return i18n("version only");
        default:
            return value || "—";
        }
    }

    function scannersLabel(scanners) {
        return (scanners && scanners.length) ? scanners.join(", ") : "—";
    }

    function viaLabel(row) {
        return scannersLabel(row.scanners)
            + (row.confidence ? " · " + confidenceLabel(row.confidence) : "");
    }

    function trackerStatusLabel(status) {
        switch (Tracker.statusLabelKey(status)) {
        case "published":
            return i18n("published");
        case "accepted":
            return i18n("accepted");
        case "pending":
            return i18n("pending review");
        case "rejected":
            return i18n("match rejected");
        default:
            return "";
        }
    }

    function issueStateLabel(state) {
        switch (state) {
        case "open":
            return i18nc("issue state", "open");
        case "closed":
            return i18nc("issue state", "closed");
        default:
            return state || "";
        }
    }

    function originTooltip(origin) {
        if (!origin || !origin.names || origin.names.length === 0) {
            return "";
        }
        const lines = [i18n("Introduced by: %1", origin.names.join(", "))];
        if (origin.chain && origin.chain.length > 0) {
            lines.push(i18n("Chain: %1", origin.chain.join(" → ")));
        }
        if (origin.chains && origin.chains.length > 1) {
            for (let i = 1; i < origin.chains.length && i < 3; ++i) {
                lines.push("  " + origin.chains[i].join(" → "));
            }
        }
        lines.push(i18n("Click an Origin value to show all findings from this package."));
        return lines.join("\n");
    }

    function affectedProductsText(tracker) {
        const products = Tracker.affectedProductsOf(tracker);
        const parts = [];
        for (let i = 0; i < products.length; ++i) {
            const product = products[i];
            parts.push(product.name
                + (product.constraints.length > 0
                    ? " (" + product.constraints.join(", ") + ")"
                    : ""));
        }
        return parts.join(", ");
    }

    function fixTooltipLines(fix, systemChannel) {
        const lines = [];
        if (fix.rows && fix.rows.length > 0) {
            lines.push(i18n("Fix status by nixpkgs branch:"));
            for (let i = 0; i < fix.rows.length; ++i) {
                const row = fix.rows[i];
                lines.push("  " + (row.state === "unaffected" ? "✓"
                    : (row.state === "affected" ? "✗" : "?")) + " "
                    + (row.version ? row.name + " " + row.version : row.name)
                    + (row.name === systemChannel ? "  ←" : ""));
            }
            switch (fix.state) {
            case "in-staging":
                if (fix.branch === "staging-next") {
                    lines.push(i18n("Next: master, at the end of the current staging cycle (staging-next is merged into master by PR)."));
                } else {
                    lines.push(i18n("In staging but not in staging-next yet: it misses the current cycle and joins the next one, then master."));
                }
                break;
            case "in-master":
                if (!fix.systemKnown) {
                    lines.push(i18n("The channel's package file has no plain version to compare, so whether %1 already carries it is unknown.", systemChannel));
                } else if (fix.nextStep === "channel-bump") {
                    lines.push(i18n("Next: the nixos-unstable channel bump."));
                } else {
                    lines.push(i18n("Next: a backport to %1.", systemChannel));
                }
                break;
            case "in-release":
                lines.push(i18n("Not on the way to this system's channel; it is fixed on another line."));
                break;
            case "issue-open":
                lines.push(i18n("No fix merged yet."));
                break;
            }
            lines.push(i18n("Update to a branch marked ✓ to get the fix."));
            if (fix.bucket === "progress") {
                lines.push(i18n("Pending: the fix is merged, but no channel carries it yet."));
            }
            return lines;
        }
        switch (fix.state) {
        case "fixed":
            lines.push(i18n("A fixed version is available in nixpkgs."));
            break;
        case "in-staging":
            lines.push(i18n("Merged into the nixpkgs staging branches; it lands in master with the next staging cycle."));
            break;
        case "in-release":
            lines.push(i18n("Backported to the release branch while master still carries the affected version."));
            break;
        case "issue-open":
            lines.push(i18n("No fix merged yet; the Nixpkgs security issue is open."));
            break;
        }
        return lines;
    }

    function masterTooltip(row, systemChannel) {
        const fix = row.fix;
        const tracker = row.tracker || {};
        const status = fix.master.status;
        const version = fix.master.version || i18n("unknown");
        const lines = [];
        if (status === "unaffected") {
            lines.push(i18n("Fixed in nixpkgs master (version %1)", version));
        } else if (status === "affected") {
            lines.push(i18n("Still affected in nixpkgs master (version %1)", version));
        } else if (status === "unknown") {
            lines.push(i18n("Nixpkgs master status unknown (version %1)", version));
        } else if (status === "unmatched") {
            lines.push(i18n("No nixpkgs master verdict for %1.", row.package || ""));
            const covered = tracker.suggestion_packages || [];
            if (covered.length > 0) {
                const shown = covered.slice(0, 6);
                lines.push(i18n("The tracker suggestion covers: %1%2",
                    shown.join(", "),
                    covered.length > 6
                        ? i18n(" (+%1 more)", covered.length - 6)
                        : ""));
            }
            const products = affectedProductsText(tracker);
            if (products.length > 0) {
                lines.push(i18n("CVE affected products: %1", products));
            }
            if (row.version) {
                lines.push(i18n("Your version: %1", row.version));
            }
            if (tracker.status) {
                lines.push(i18n("Tracker status: %1", trackerStatusLabel(tracker.status)));
            }
            if (fix.url) {
                lines.push(i18n("Click to open the suggestion"));
            }
            return lines.join("\n");
        } else {
            lines.push(i18n("No nixpkgs master data"));
        }
        const fixLines = fixTooltipLines(fix, systemChannel);
        for (let i = 0; i < fixLines.length; ++i) {
            lines.push(fixLines[i]);
        }
        if (tracker.master_status_source === "version" && tracker.master_range) {
            if (status === "affected") {
                lines.push(i18n("Derived from the CVE's affected range (%1); the tracker has no master verdict.", tracker.master_range));
            } else if (status === "unaffected") {
                lines.push(i18n("Version %1 is outside the affected range (%2); derived from the CVE data.", version, tracker.master_range));
            }
        }
        if (tracker.issue) {
            const issueState = issueStateLabel(tracker.issue_state);
            lines.push(i18n("Security issue %1%2", tracker.issue,
                issueState ? i18n(" (%1)", issueState) : ""));
        }
        if (fix.url) {
            lines.push(i18n("Click to open the fix/bump"));
        }
        return lines.join("\n");
    }

    function fixTooltip(row, systemChannel) {
        const fix = row.fix;
        const lines = fixTooltipLines(fix, systemChannel);
        const origin = originTooltip(row.origin);
        if (lines.length === 0) {
            const fallback = masterTooltip(row, systemChannel);
            if (origin.length === 0) {
                return fallback;
            }
            return fallback.length > 0 ? fallback + "\n\n" + origin : origin;
        }
        const text = [];
        if (row.version) {
            text.push(i18n("Installed version: %1", row.version));
        }
        if (systemChannel) {
            text.push(i18n("Your channel: %1", systemChannel));
        }
        const result = text.concat(lines);
        if (origin.length > 0) {
            result.push("");
            result.push(origin);
        }
        return result.join("\n");
    }

    function relativeTime(ageSeconds) {
        const token = Time.relativeToken(ageSeconds);
        switch (token.key) {
        case "just-now":
            return i18n("just now");
        case "minutes":
            return i18np("%1 minute ago", "%1 minutes ago", token.value);
        case "hours":
            return i18np("%1 hour ago", "%1 hours ago", token.value);
        case "days":
            return i18np("%1 day ago", "%1 days ago", token.value);
        default:
            return "";
        }
    }

    function lastScanLabel(ageSeconds) {
        const relative = relativeTime(ageSeconds);
        return relative.length > 0 ? i18n("Last scan %1", relative) : "";
    }

    function lastScanTooltip(scannedAtMs) {
        if (!scannedAtMs) {
            return "";
        }
        return i18n("Last scan: %1",
            Qt.formatDateTime(new Date(scannedAtMs), "yyyy-MM-dd HH:mm"));
    }

    function trackerProgressText(progress) {
        if (!progress) {
            return "";
        }
        if (progress.authFailed) {
            return i18n("The tracker rejected the API token; check the token in the applet settings.");
        }
        if (!progress.busy) {
            if (progress.throttled) {
                return i18n("Tracker rate limit reached; %1 CVEs will be retried in the next run.", progress.failed);
            }
            if (progress.failed > 0) {
                return i18n("Tracker check finished with %1 failures.", progress.failed);
            }
            return "";
        }
        switch (progress.phase) {
        case "pending":
            return i18n("Tracker check queued…");
        case "waiting":
            return i18n("Tracker rate limit reached; waiting to retry…");
        case "packages": {
            let text = i18n("Checking tracker packages: %1/%2", progress.done, progress.total);
            if (progress.packageFailed > 0) {
                text += i18n(" (%1 failed)", progress.packageFailed);
            }
            if (progress.throttled) {
                text += i18n(" — rate limit reached");
            }
            return text;
        }
        case "cves": {
            let text = i18n("Checking remaining CVEs: %1/%2", progress.done, progress.total);
            if (progress.fallbackFailed > 0) {
                text += i18n(" (%1 failed)", progress.fallbackFailed);
            }
            if (progress.throttled) {
                text += i18n(" — rate limit reached");
            }
            return text;
        }
        case "issues": {
            let text = i18n("Checking fix links: %1/%2", progress.done, progress.total);
            if (progress.issueFailed > 0) {
                text += i18n(" (%1 failed)", progress.issueFailed);
            }
            if (progress.throttled) {
                text += i18n(" — rate limit reached");
            }
            return text;
        }
        case "probes": {
            const text = i18n("Checking nixpkgs branches: %1/%2", progress.done, progress.total);
            return progress.probeFailed > 0
                ? text + i18n(" (%1 failed)", progress.probeFailed)
                : text;
        }
        default: {
            let text = i18n("Checking security tracker: %1/%2 CVEs", progress.done, progress.total);
            if (progress.failed > 0) {
                text += i18n(" (%1 failed)", progress.failed);
            }
            if (progress.throttled) {
                text += i18n(" — rate limit reached");
            }
            return text;
        }
        }
    }

    function trackerSummaryText(vm, store) {
        const tracker = store ? store.tracker : null;
        if (!tracker) {
            return "";
        }
        if (tracker.available !== true && tracker.complete !== false) {
            return "";
        }
        const counts = vm ? vm.counts : null;
        if (!counts) {
            return "";
        }
        const missing = counts.tracker.missing;
        const linked = counts.tracker.linked;
        const pending = counts.tracker.pending;
        const unchecked = counts.tracker.unchecked;
        const fixed = counts.fix.fixed;
        const fixPending = counts.fix.progress;
        const parts = [];
        if (missing > 0) {
            parts.push(i18np("%1 finding untracked", "%1 findings untracked", missing));
        }
        if (linked > 0) {
            parts.push(i18np("%1 finding in tracker", "%1 findings in tracker", linked));
        }
        if (pending > 0) {
            parts.push(i18n("%1 pending review", pending));
        }
        if (fixed > 0) {
            parts.push(i18n("%1 with a fix available", fixed));
        }
        if (fixPending > 0) {
            parts.push(i18n("%1 with a fix pending", fixPending));
        }
        if (unchecked > 0) {
            parts.push(i18np("%1 finding not checked", "%1 findings not checked", unchecked));
        }
        if (tracker.failed > 0) {
            parts.push(i18np("%1 CVE failed", "%1 CVEs failed", tracker.failed));
        }
        const text = parts.length > 0
            ? parts.join(" · ")
            : (tracker.complete === false ? i18n("checking…") : i18n("no matching issues"));
        return i18n("Nixpkgs security tracker: %1.", text);
    }

    function resultInfoText(vm, store) {
        const parts = [];
        const summary = trackerSummaryText(vm, store);
        if (summary.length > 0) {
            parts.push(summary);
        }
        parts.push(i18n("Scores and versions come from the scanned system; NixOS may already carry a backported fix."));
        parts.push(i18n("The second line shows the dependency chain that introduced the finding. Click it to filter to that origin, or use the “Group by” menu to group the list by priority, package or origin. Right-click a row for tracker, fix and copy actions. Origin data is written by the scan service."));
        parts.push(masterHelpText);
        parts.push(i18n("The CSV report and scan log are available from the widget's context menu."));
        return parts.join("\n\n");
    }

    function toolTipSubText(store, vm) {
        if (store.scanning) {
            return i18n("Scanning for vulnerabilities…");
        }
        const relative = relativeTime(vm.lastScanAge);
        const summary = stateSummary(vm.reportModel, store.scanning,
            vm.affectedPackages, vm.maxSeverity);
        const detail = stateDetail(summary, relative);
        const tracker = trackerSummaryText(vm, store);
        return tracker.length > 0 ? detail + "\n" + tracker : detail;
    }

    function badgeText(report, badgeMode, count) {
        if (!report || (report.state !== "vulnerable" && report.state !== "warn")) {
            return "";
        }
        const findings = count === undefined || count === null
            ? Number(report.findings || 0)
            : Number(count);
        switch (badgeMode) {
        case "none":
            return "";
        case "dot":
            return findings > 0 ? "•" : "";
        default:
            if (findings <= 0) {
                return "";
            }
            return findings > 999
                ? i18nc("number of vulnerabilities", "999+")
                : i18nc("number of vulnerabilities", "%1", findings);
        }
    }

    function trackerHint(code, arg) {
        switch (code) {
        case "missing":
            return i18n("%1 is not in the Nixpkgs security tracker; this finding may be a false positive.", arg);
        case "checking":
            return i18n("Checking the Nixpkgs security tracker for %1…", arg);
        case "tracker-running":
            return i18n("The tracker check is still running; %1 will be checked shortly.", arg);
        case "rate-limit":
            return i18n("The Nixpkgs security tracker is rate-limiting requests; try again in a minute.");
        case "failed":
            return i18n("Could not check the Nixpkgs security tracker for %1.", arg);
        case "copied":
            return i18n("Copied %1 to the clipboard.", arg);
        default:
            return "";
        }
    }

    function loadErrorText(code) {
        switch (code) {
        case "missing":
            return i18n("No scan data has been written yet.");
        case "permission":
            return i18n("The scan data cannot be read: permission denied.");
        case "invalid-json":
            return i18n("The scan data is not valid JSON; the scan service may still be writing it.");
        case "unsupported-schema":
            return i18n("The scan data comes from a newer backend; some fields may be ignored.");
        case "unknown":
            return i18n("The scan data could not be read.");
        default:
            return "";
        }
    }

    function scanErrorText(code) {
        switch (code) {
        case "start-failed":
            return i18n("The scan could not be started; check the systemd unit and permissions.");
        case "timeout":
            return i18n("The scan timed out; a late result will still be shown.");
        case "service-missing":
            return i18n("The Sentinel scan service is not available.");
        default:
            return "";
        }
    }

    function schemaNewerText() {
        return i18n("The scan data comes from a newer backend; some fields may be ignored.");
    }

    function sortTooltip(key, active, descending, label) {
        if (active) {
            return descending
                ? i18n("Sorted descending — click for ascending")
                : i18n("Sorted ascending — click for descending");
        }
        return i18n("Sort by %1", label);
    }

    function countLabel(visible, total) {
        return i18n("%1 of %2", visible, total);
    }

    function triageHiddenLabel(count) {
        return i18np("%1 false positive hidden", "%1 false positives hidden", count);
    }

    function triageHiddenTooltip() {
        return i18n("The triage pass decided these findings do not describe the installed package. Turn the setting off to show them again.");
    }

    function noMatchesText() {
        return i18n("No vulnerabilities match your search or filters.");
    }

    function headerLabel(key) {
        switch (key) {
        case "severity":
            return i18n("CVSS");
        case "cve":
            return i18n("CVE");
        case "package":
            return i18n("Package");
        case "master":
            return i18n("Fix");
        default:
            return key;
        }
    }

    function groupLabel(name) {
        return name && name.length > 0 ? name : i18n("Unknown origin");
    }

    function groupColumnLabel(groupBy) {
        switch (groupBy) {
        case "priority":
            return i18n("Priority");
        case "package":
            return i18n("Package");
        case "origin":
            return i18n("Origin");
        default:
            return i18n("Group");
        }
    }

    function groupCountColumnLabel() {
        return i18n("Findings");
    }

    function groupSortTooltip(groupBy, key, active, descending) {
        const label = key === "count" ? groupCountColumnLabel() : groupColumnLabel(groupBy);
        if (active) {
            return descending
                ? i18n("Sorted descending — click for ascending")
                : i18n("Sorted ascending — click for descending");
        }
        return i18n("Sort by %1", label);
    }

    function groupTitle(groupBy, key) {
        switch (groupBy) {
        case "priority":
            return severityBandLabel(key || "unknown");
        case "package":
            return key && key.length > 0 ? key : i18n("Unknown package");
        case "origin":
            return groupLabel(key);
        default:
            return key || "";
        }
    }

    function groupCountText(count) {
        return i18np("%1 finding", "%1 findings", count);
    }

    function groupToggleTooltip(expanded) {
        return expanded
            ? i18n("Click to hide these findings")
            : i18n("Click to show these findings");
    }

    function criticalExposureTitle() {
        return i18n("CRITICAL EXPOSURE");
    }

    function potentialVulnerabilities() {
        return i18n("potential vulnerabilities");
    }

    function packagesText(count) {
        return i18np("%1 package", "%1 packages", count);
    }

    function cvesText(count) {
        return i18np("%1 CVE", "%1 CVEs", count);
    }

    function severityTitle() {
        return i18n("SEVERITY");
    }

    function readyToFixTitle() {
        return i18n("READY TO FIX");
    }

    function cvssLabel() {
        return i18n("CVSS");
    }

    function scanButtonText(scanning) {
        return scanning ? i18n("Scanning…") : i18n("Scan now");
    }

    function settingsTooltip() {
        return i18n("Open the applet settings");
    }

    function filtersButton() {
        return i18n("Filter");
    }

    function filtersTooltip() {
        return i18n("Filter by CVE, package, origin, severity or fix state");
    }

    function advancedFilterTitle() {
        return i18n("Filter findings");
    }

    function filterFieldsHint() {
        return i18n("CVE, package or origin");
    }

    function severityAndFixLabel() {
        return i18n("Severity and fix state");
    }

    function cvePlaceholder() {
        return i18n("CVE ID");
    }

    function packagePlaceholder() {
        return i18n("Package");
    }

    function originPlaceholder() {
        return i18n("Origin");
    }

    function severityLabel() {
        return i18n("Severity");
    }

    function fixStateLabel() {
        return i18n("Fix state");
    }

    function applyFiltersText() {
        return i18n("Apply");
    }

    function filterChipText(key, value) {
        switch (key) {
        case "text":
            return i18n("Search: %1", value);
        case "cve":
            return i18n("CVE: %1", value);
        case "package":
            return i18n("Package: %1", value);
        case "origin":
            return i18n("Origin: %1", value);
        case "severity":
            return i18n("Severity: %1", severityBandLabel(value));
        case "fixState":
            return i18n("Fix: %1", fixBucketLabel(value));
        default:
            return value;
        }
    }

    function removeFilterTooltip(key) {
        switch (key) {
        case "text":
            return i18n("Clear the search");
        case "cve":
            return i18n("Remove the CVE filter");
        case "package":
            return i18n("Remove the package filter");
        case "origin":
            return i18n("Remove the origin filter");
        case "severity":
            return i18n("Remove the severity filter");
        case "fixState":
            return i18n("Remove the fix-state filter");
        default:
            return i18n("Remove this filter");
        }
    }

    function searchPlaceholder() {
        return i18n("Search…");
    }

    function allSeverities() {
        return i18n("All severities");
    }

    function unknownSeverity() {
        return i18n("Unknown severity");
    }

    function allFixStates() {
        return i18n("All fix states");
    }

    function clearFiltersText() {
        return i18n("Clear filters");
    }

    function clearFiltersTooltip() {
        return i18n("Clear the search and filters");
    }

    function groupByStateLabel(groupBy) {
        return groupBy === "none" ? i18n("Flat") : groupColumnLabel(groupBy);
    }

    function groupByButton(groupBy) {
        switch (groupBy) {
        case "priority":
        case "package":
        case "origin":
            return i18n("Group by: %1", groupColumnLabel(groupBy));
        default:
            return i18n("Group by");
        }
    }

    function groupByTooltip(groupBy) {
        switch (groupBy) {
        case "priority":
            return i18n("Grouped by priority");
        case "package":
            return i18n("Grouped by package");
        case "origin":
            return i18n("Grouped by origin");
        default:
            return i18n("Group findings by priority, package or origin");
        }
    }

    function groupNone() {
        return i18n("No grouping");
    }

    function groupPriority() {
        return i18n("Priority");
    }

    function groupPackage() {
        return i18n("Package");
    }

    function groupOrigin() {
        return i18n("Origin");
    }

    function expandAllGroups() {
        return i18n("Show all findings");
    }

    function collapseAllGroups() {
        return i18n("Hide all findings");
    }

    function showAllForPackage(name) {
        return i18n("Show all findings for %1", name || "");
    }

    function filterByOrigin() {
        return i18n("Filter by origin");
    }

    function openTrackerText() {
        return i18n("Open in Nixpkgs security tracker");
    }

    function openMasterFixText() {
        return i18n("Open master fix/bump");
    }

    function openMasterSourceText() {
        return i18n("Open nixpkgs master source");
    }

    function copyCveText() {
        return i18n("Copy CVE ID");
    }

    function copyPackageText() {
        return i18n("Copy package name");
    }

    function copyFixUrlText() {
        return i18n("Copy fix/bump URL");
    }

    function searchNixpkgsText(name) {
        return i18n("Search nixpkgs unstable for %1", name || "");
    }

    function openVulnerabilityTooltip(id) {
        return id
            ? i18n("Open %1 in the vulnerability database", id)
            : "";
    }

    function filterPackageTooltip(name) {
        return name ? i18n("Show all findings for %1", name) : "";
    }

    function trackerWarningText(store) {
        if (store.trackerBusy && !store.serviceActive) {
            return i18n("The last scan did not finish. Scan again to complete it.");
        }
        return trackerProgressText(store.progress);
    }

    function rowAccessibleName(id, packageName, severityText) {
        return i18n("%1 in %2, severity %3",
            id || i18n("unknown CVE"),
            packageName || i18n("unknown package"),
            severityText);
    }

    function cveTooltip(id, hasUrl) {
        return hasUrl
            ? i18n("Open %1 in the vulnerability database", id)
            : id;
    }

    function appTitle() {
        return i18n("Sentinel");
    }

    function scanningForVulnerabilities() {
        return i18n("Scanning for vulnerabilities…");
    }

}
