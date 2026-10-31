from __future__ import annotations

import unittest

from common.record import SinkId
from engine.correlate import Finding, correlate
from engine.correlate.models import Issue
from engine.report import build_coverage_report, format_text, to_sarif


def dast_record() -> Finding:
    return Finding.from_dict(
        {
            "run_id": "test-run",
            "source": "dast",
            "provenance": "zap",
            "cwe": 79,
            "type": "Cross-site scripting",
            "route": "/search",
            "method": "GET",
            "param": "q",
            "payload": "<script>",
            "evidence": [{"type": "ORACLE", "detail": {"oracle": "reflected_marker"}}],
            "severity": "medium",
        }
    )


class ReportTests(unittest.TestCase):
    def test_text_and_sarif_expose_conflict_and_flaky_hints(self) -> None:
        candidate = SinkId("src/Query.java", "Query.run", 8, 2)
        issue = Issue(
            issue_key="runtime-conflict",
            label="Runtime-only",
            cwe=89,
            type="SQL Injection",
            severity="high",
            risk_score=80.0,
            link_status="ambiguous",
            link_origin="sweep",
            conflict=True,
            oracle_flaky=True,
            candidate_sinks=(candidate,),
        )

        text = format_text([issue])
        sarif_properties = to_sarif([issue])["runs"][0]["results"][0]["properties"]

        self.assertIn("Conflict: positive replay", text)
        self.assertIn("flaky replay", text)
        self.assertIn("Candidate sink hint: src/Query.java:8", text)
        self.assertTrue(sarif_properties["conflict"])
        self.assertTrue(sarif_properties["oracle_flaky"])
        self.assertEqual(sarif_properties["candidate_sinks"], [candidate.to_dict()])

    def test_suppression_respects_status_cwe_and_unresolved_reason(self) -> None:
        negative = Finding.from_dict(
            {
                **dast_record().to_dict(),
                "source": "sast",
                "provenance": "own",
                "param": None,
                "sink_id": {
                    "file": "src/Query.java",
                    "enclosing_method": "Query.run",
                    "start_line": 8,
                    "start_col": 2,
                },
                "status": "tested_negative",
                "arg_shape": "dynamic",
            }
        )
        [suppressed] = correlate([negative])
        self.assertTrue(suppressed.suppressed)

        unresolved = Finding.from_dict(
            {
                **negative.to_dict(),
                "status": "no_http_path",
                "unlinked_reason": "walk_unresolved",
                "suppressed": False,
            }
        )
        [visible] = correlate(
            [unresolved],
            {"export.suppress_no_http_path": True, "export.suppress_cwes": (89, 79, 78, 601, 22)},
        )
        self.assertFalse(visible.suppressed)

    def test_primary_report_omits_suppressed_issues(self) -> None:
        finding = Finding.from_dict(
            {
                **dast_record().to_dict(),
                "source": "sast",
                "provenance": "own",
                "param": None,
                "sink_id": {
                    "file": "src/Query.java",
                    "enclosing_method": "Query.run",
                    "start_line": 8,
                    "start_col": 2,
                },
                "status": "safe_pattern",
                "arg_shape": "constant",
            }
        )
        [issue] = correlate([finding])
        self.assertTrue(issue.suppressed)
        self.assertEqual(format_text([issue]), "No issues found.")

    def test_coverage_reports_recall_misses_skips_and_attribution(self) -> None:
        static = Finding.from_dict(
            {
                "run_id": "test-run",
                "source": "sast",
                "provenance": "own",
                "cwe": 89,
                "type": "SQL Injection",
                "file": "src/Query.java",
                "line": 8,
                "sink_id": {
                    "file": "src/Query.java",
                    "enclosing_method": "Query.run",
                    "start_line": 8,
                    "start_col": 2,
                },
                "entry_paths": [
                    {
                        "route": "/query",
                        "method": "GET",
                        "hops": 0,
                        "call_chain": [
                            {"method": "Query.get", "file": "src/Query.java", "line": 3}
                        ],
                    }
                ],
                "arg_shape": "dynamic",
                "candidate_params": ["id"],
                "evidence": [{"type": "PATH", "detail": {}}],
            }
        )
        probe = Finding.from_dict(
            {
                **dast_record().to_dict(),
                "run_id": "test-run",
                "cwe": 89,
                "type": "SQL Injection",
                "route": "/query",
                "method": "GET",
                "param": "id",
                "hypothesis_id": "h-query",
            }
        )
        report = build_coverage_report(
            [static, probe],
            expected_pairs={
                "pairs": [
                    {
                        "route": "/query",
                        "method": "GET",
                        "params": ["id"],
                        "cwe": 89,
                        "file": "src/Query.java",
                        "line": 8,
                    },
                    {
                        "route": "/missing",
                        "method": "GET",
                        "params": ["id"],
                        "cwe": 89,
                        "file": "src/Missing.java",
                        "line": 99,
                    },
                ]
            },
            supported_cwes={89},
            skipped_by_type=[("/query", "GET", "page")],
            attribution_rate=0.9,
        )
        self.assertEqual(report["recall_by_cwe"]["CWE-89"]["found"], 1)
        self.assertEqual(
            report["recall_by_cwe"]["CWE-89"]["misses"][0]["miss"],
            "no_catalogue_entry",
        )
        self.assertEqual(report["supported_cwe_score"]["recall"], 0.5)
        self.assertEqual(report["attribution_rate"], 0.9)
        self.assertEqual(report["attribution_accuracy"], 1.0)
        self.assertEqual(report["skipped_by_type"][0]["param"], "page")

    def test_attribution_accuracy_is_unknown_without_expected_pairs(self) -> None:
        probe = Finding.from_dict(
            {
                **dast_record().to_dict(),
                "hypothesis_id": "h-query",
            }
        )

        report = build_coverage_report([probe])

        self.assertEqual(report["attribution_counts"]["attributed_hits"], 1)
        self.assertIsNone(report["attribution_counts"]["accurate_hits"])
        self.assertIsNone(report["attribution_accuracy"])

    def test_runtime_only_sarif_uses_logical_location_and_properties(self) -> None:
        issue = correlate([dast_record()])[0]
        sarif = to_sarif([issue])
        result = sarif["runs"][0]["results"][0]

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(result["ruleId"], "CWE-79")
        self.assertEqual(result["logicalLocations"][0]["name"], "/search")
        self.assertEqual(result["properties"]["label"], "Runtime-only")
        self.assertNotIn("locations", result)

    def test_text_report_includes_runtime_evidence_fields(self) -> None:
        report = format_text(correlate([dast_record()]))

        self.assertIn("Runtime-only", report)
        self.assertIn("GET /search", report)
        self.assertIn("Payload: <script>", report)
        self.assertIn("Oracle: reflected_marker", report)


if __name__ == "__main__":
    unittest.main()
