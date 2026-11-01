from __future__ import annotations

import unittest
from dataclasses import replace
from io import StringIO

from rich.console import Console

from common.record import SinkId
from engine.correlate import Finding, correlate
from engine.correlate.models import Issue
from engine.report import build_coverage_report, format_summary, format_text, render_summary, to_sarif


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
    def test_grouped_summary_uses_records_and_sorts_top_findings_deterministically(self):
        critical = Issue(
            issue_key="critical",
            label="Confirmed",
            cwe=89,
            type="SQL Injection",
            severity="critical",
            risk_score=95.0,
            confidence=0.45,
            route="/lookup",
            method="POST",
            param="name",
            ai_notes={"fix": "Use a parameterized query", "explanation": "Existing advisory text."},
        )
        high_confidence = Issue(
            issue_key="high-confidence",
            label="Confirmed",
            cwe=78,
            type="Command Injection",
            severity="high",
            risk_score=76.0,
            confidence=0.9,
            route="/execute",
            method="POST",
            param="command",
        )
        high_risk = Issue(
            issue_key="high-risk",
            label="Runtime-only",
            cwe=601,
            type="Open Redirect",
            severity="high",
            risk_score=95.0,
            confidence=0.4,
            route="/redirect",
            method="GET",
            param="next",
        )
        evidence = correlate([dast_record()])[0]
        evidence = replace(evidence, risk_score=55.0, confidence=0.6)

        report = format_summary([high_risk, evidence, high_confidence, critical])
        top_three = report.split("Top 3 findings", maxsplit=1)[1]

        self.assertIn("CWE-79 (1 issue(s))", report)
        self.assertIn("GET /search", report)
        self.assertIn("Trigger input: q (location not recorded)", report)
        self.assertIn("Risk: 55/100", report)
        self.assertIn("Evidence: ORACLE (reflected_marker); payload <script>", report)
        self.assertIn(
            "Remediation hint (existing AI advisory; not verified): Use a parameterized query",
            report,
        )
        self.assertIn("Existing AI advisory note: Existing advisory text.", report)
        self.assertIn("no AI calls", report)
        self.assertLess(top_three.index("CWE-89"), top_three.index("CWE-78"))
        self.assertLess(top_three.index("CWE-78"), top_three.index("CWE-601"))
        self.assertNotIn("CWE-79", top_three)

    def test_grouped_summary_reports_missing_remediation_and_omits_suppressed(self):
        issue = Issue(
            issue_key="suppressed",
            label="Code-only",
            cwe=79,
            type="Cross-site scripting",
            severity="medium",
            risk_score=50.0,
            suppressed=True,
        )

        self.assertEqual(format_summary([]), "No issues found.")
        self.assertEqual(format_summary([issue]), "No issues found.")

        visible = replace(issue, issue_key="visible", suppressed=False)
        report = format_summary([visible])
        self.assertIn("Remediation hint: unavailable in the finding data.", report)
        self.assertIn("no existing advisory fixes are available", report)

    def test_terminal_summary_is_compact_and_includes_key_triage_fields(self):
        issue = Issue(
            issue_key="terminal-summary",
            label="Confirmed",
            cwe=89,
            type="SQL Injection",
            severity="high",
            risk_score=82.0,
            confidence=0.9,
            route="/lookup",
            method="GET",
            param="name",
        )
        output = StringIO()
        render_summary([issue], Console(file=output, width=100, no_color=True))

        rendered = output.getvalue()
        self.assertIn("elenchus", rendered)
        self.assertIn("1 finding across 1 CWE class", rendered)
        self.assertIn("Confirmed", rendered)
        self.assertIn("CWE-89", rendered)
        self.assertIn("GET /lookup", rendered)
        self.assertIn("82/100", rendered)
        self.assertIn("0.90", rendered)
        self.assertIn("raw output for evidence", rendered)

    def test_runtime_report_shows_endpoint_input_and_static_route_to_sink_path(self):
        sast = Finding.from_dict(
            {
                "run_id": "test-run",
                "source": "sast",
                "provenance": "own",
                "cwe": 89,
                "type": "SQL Injection",
                "route": "/lookup/{id}",
                "method": "GET",
                "file": "src/Query.java",
                "line": 24,
                "sink_id": {
                    "file": "src/Query.java",
                    "enclosing_method": "Query.find",
                    "start_line": 24,
                    "start_col": 8,
                },
                "entry_paths": [
                    {
                        "route": "/lookup/{id}",
                        "method": "GET",
                        "hops": 1,
                        "call_chain": [
                            {"method": "LookupController.get", "file": "src/LookupController.java", "line": 12},
                            {"method": "Query.find", "file": "src/Query.java", "line": 24},
                        ],
                    }
                ],
                "severity": "high",
                "evidence": [],
            }
        )
        dast = Finding.from_dict(
            {
                **dast_record().to_dict(),
                "cwe": 89,
                "type": "SQL Injection",
                "route": "/lookup/{id}",
                "method": "GET",
                "param": "term",
                "param_location": "query",
            }
        )
        issue = Issue(
            issue_key="runtime-query",
            label="Confirmed",
            cwe=89,
            type="SQL Injection",
            severity="high",
            risk_score=80.0,
            route="/lookup/{id}",
            method="GET",
            param="term",
            sink=sast.sink_id,
            file=sast.file,
            line=sast.line,
            sast_findings=(sast,),
            dast_findings=(dast,),
        )

        report = format_text([issue])
        terminal = StringIO()
        render_summary([issue], Console(file=terminal, width=140, no_color=True))

        self.assertIn("Runtime endpoint: GET /lookup/{id}", report)
        self.assertIn("Trigger input: query parameter 'term'", report)
        self.assertIn("LookupController.get (src/LookupController.java:12)", report)
        self.assertIn("static, not a runtime trace", report)
        self.assertIn("query parameter 'term'", terminal.getvalue())
        self.assertIn("Query.find (src/Query.java:24)", terminal.getvalue())

    def test_runtime_parameter_report_identifies_path_parameters(self):
        path_finding = replace(
            dast_record(),
            route="/orders/{orderId}",
            param="orderId",
            param_location="path",
        )
        issue = replace(
            correlate([path_finding])[0],
            route="/orders/{orderId}",
            method="GET",
        )

        self.assertIn(
            "Trigger input: path parameter 'orderId'",
            format_text([issue]),
        )

    def test_unlinked_runtime_hit_says_static_code_path_is_unavailable(self):
        issue = correlate([dast_record()])[0]

        report = format_text([issue])

        self.assertIn("Runtime endpoint: GET /search", report)
        self.assertIn("Trigger input: q (location not recorded)", report)
        self.assertIn("Indexed route-to-sink path: unavailable", report)

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
        self.assertEqual(report["wrong_suppression_count"]["CWE-89"], 0)

    def test_wrong_suppression_count_flags_a_vulnerable_sink_marked_safe(self) -> None:
        # A ground-truth vulnerable sink that the pipeline labelled tested_negative
        # (e.g. union/blind SQLi, which the error-based oracle cannot confirm) must
        # be counted, so the CWE can be dropped from export.suppress_cwes.
        negative = Finding.from_dict(
            {
                "run_id": "test-run",
                "source": "sast",
                "provenance": "own",
                "cwe": 89,
                "type": "SQL Injection",
                "file": "src/Blind.java",
                "line": 93,
                "sink_id": {
                    "file": "src/Blind.java",
                    "enclosing_method": "Blind.run",
                    "start_line": 93,
                    "start_col": 2,
                },
                "entry_paths": [
                    {
                        "route": "/blind",
                        "method": "GET",
                        "hops": 0,
                        "call_chain": [{"method": "Blind.get", "file": "src/Blind.java", "line": 3}],
                    }
                ],
                "arg_shape": "dynamic",
                "candidate_params": ["id"],
                "status": "tested_negative",
                "evidence": [{"type": "PATH", "detail": {}}],
            }
        )
        report = build_coverage_report(
            [negative],
            expected_pairs={
                "pairs": [
                    {
                        "route": "/blind",
                        "method": "GET",
                        "params": ["id"],
                        "cwe": 89,
                        "file": "src/Blind.java",
                        "line": 93,
                    }
                ]
            },
        )
        self.assertEqual(report["wrong_suppression_count"]["CWE-89"], 1)

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
