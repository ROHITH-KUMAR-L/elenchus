from __future__ import annotations

import unittest

from engine.correlate import Finding, correlate
from engine.report import format_text, to_sarif


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
