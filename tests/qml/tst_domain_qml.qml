import QtQuick
import QtTest

import "../../contents/ui/domain/severity.mjs" as Severity
import "../../contents/ui/domain/table.mjs" as Table
import "../../contents/ui/domain/status.mjs" as Status

TestCase {
    name: "DomainModulesInQml"

    function test_severity_band() {
        compare(Severity.bandOf(9.9), "critical");
        compare(Severity.formatScore(0), "—");
    }

    function test_status_parses_text() {
        const result = Status.parseStatusText('{"state":"secure","findings":0}');
        compare(result.ok, true);
        compare(result.report.state, "secure");
    }

    function test_table_builds_a_row() {
        const finding = {
            id: "CVE-2026-0001",
            package: "zlib",
            version: "1.3.0",
            severity: 7.5,
            origins: { introduced_by: ["curl"], chain: ["curl", "zlib"] },
            tracker: { found: true, status: "pending" }
        };
        const row = Table.buildFindingRow(finding, { systemChannel: "nixos-unstable", checked: {} });
        compare(row.rowType, "finding");
        compare(row.severityBand, "high");
        compare(row.trackerState, "found");
        compare(row.origin.primary, "curl");
    }
}
