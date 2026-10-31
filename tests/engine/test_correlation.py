from __future__ import annotations

import hashlib
import json
import unittest

from common.record import dedupe_key
from engine.correlate import Finding, correlate


def record(
    source: str,
    *,
    cwe: int = 89,
    route: str | None = "/orders/{id}",
    method: str | None = "GET",
    file: str | None = None,
    line: int | None = None,
    param: str | None = "id",
    trace: list[dict[str, object]] | None = None,
    evidence: dict[str, object] | None = None,
    handler_file: str | None = None,
    handler_line_start: int | None = None,
    handler_line_end: int | None = None,
    reached_via: list[dict[str, object]] | None = None,
    severity: str = "high",
    wasc_id: int | None = None,
) -> dict[str, object]:
    return {
        "run_id": "test-run",
        "source": source,
        "cwe": cwe,
        "type": "SQL injection",
        "route": route,
        "method": method,
        "file": file,
        "line": line,
        "param": param,
        "payload": "1'" if source == "dast" else None,
        "handler_file": handler_file,
        "handler_line_start": handler_line_start,
        "handler_line_end": handler_line_end,
        "reached_via": reached_via,
        "evidence": evidence or {},
        "taint_trace": trace,
        "label": None,
        "confidence": None,
        "risk_score": None,
        "severity": severity,
        "wasc_id": wasc_id,
    }


def finding(source: str, **kwargs: object) -> Finding:
    return Finding.from_dict(record(source, **kwargs))


class CorrelationTests(unittest.TestCase):
    def test_tier_a_matches_sink_inside_handler_span(self) -> None:
        sast = finding(
            "sast",
            file="src/OrderController.java",
            line=25,
            handler_file="src/OrderController.java",
            handler_line_start=20,
            handler_line_end=30,
        )
        dast = finding("dast")

        [issue] = correlate([sast, dast])

        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.confidence, "A")
        self.assertEqual(issue.risk_score, 85.0)

    def test_tier_b_matches_one_hop_reached_via_edge(self) -> None:
        sast = finding(
            "sast",
            file="src/OrderService.java",
            line=88,
            route=None,
            method=None,
            reached_via=[
                {
                    "route": "/orders/{id}",
                    "method": "GET",
                    "handler_file": "src/OrderController.java",
                    "handler_line_start": 39,
                    "handler_line_end": 47,
                }
            ],
            trace=[
                {"file": "src/OrderController.java", "line": 42, "role": "source"},
                {"file": "src/OrderService.java", "line": 88, "role": "sink"},
            ],
        )
        dast = finding("dast")

        [issue] = correlate([sast, dast])

        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.confidence, "B")

    def test_tier_c_matches_route_method_and_parameter(self) -> None:
        sast = finding("sast", file="src/Orders.java", line=88)
        dast = finding("dast")

        [issue] = correlate([sast, dast])

        self.assertEqual(issue.confidence, "C")
        self.assertIn("route", issue.link_reason or "")

    def test_cwe_and_parameter_mismatches_never_link(self) -> None:
        findings = [
            finding("sast", file="src/Orders.java", line=88),
            finding("dast", cwe=79),
            finding(
                "sast",
                file="src/Orders.java",
                line=90,
                cwe=79,
                param="code-param",
            ),
            finding("dast", cwe=79, param="other"),
        ]

        issues = correlate(findings)

        self.assertEqual(len(issues), 4)
        self.assertEqual(
            {issue.label for issue in issues},
            {"Code-only", "Runtime-only"},
        )

    def test_http_method_mismatch_never_links(self) -> None:
        issues = correlate(
            [
                finding("sast", file="src/Orders.java", line=88),
                finding("dast", method="POST"),
            ]
        )

        self.assertEqual(len(issues), 2)
        self.assertNotIn("Confirmed", {issue.label for issue in issues})

    def test_app_wide_header_findings_dedupe_by_header_name(self) -> None:
        first = finding(
            "dast",
            cwe=693,
            route="/first",
            param=None,
            evidence={"header_name": "X-Frame-Options"},
        )
        second = finding(
            "dast",
            cwe=693,
            route="/second",
            param=None,
            evidence={"header_name": "x-frame-options"},
        )

        [issue] = correlate([first, second])

        self.assertEqual(issue.label, "Runtime-only")
        self.assertEqual(len(issue.dast_findings), 2)

    def test_ambiguous_best_match_is_not_linked(self) -> None:
        findings = [
            finding("sast", file="src/Orders.java", line=88),
            finding("sast", file="src/Orders.java", line=90),
            finding("dast"),
        ]

        issues = correlate(findings)

        self.assertEqual(len(issues), 3)
        self.assertTrue(all(issue.label != "Confirmed" for issue in issues))

    def test_duplicate_findings_are_collapsed_and_preserved_as_members(self) -> None:
        sast = finding("sast", file="src/Orders.java", line=88)
        dast = finding("dast")

        [issue] = correlate([sast, sast, dast, dast])

        self.assertEqual(len(issue.sast_findings), 2)
        self.assertEqual(len(issue.dast_findings), 2)

    def test_runtime_only_fingerprint_uses_cwe_route_method_and_parameter(self) -> None:
        dast = finding("dast")
        first = correlate([dast])[0]
        second = correlate([finding("dast")])[0]
        third = correlate([finding("dast", method="POST")])[0]
        expected = hashlib.sha256(
            json.dumps(
                dedupe_key(dast),
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:24]

        self.assertEqual(first.issue_key, second.issue_key)
        self.assertNotEqual(first.issue_key, third.issue_key)
        self.assertEqual(first.issue_key, expected)

    def test_input_validation_rejects_malformed_trace(self) -> None:
        malformed_trace = record(
            "sast",
            file="src/Orders.java",
            line=88,
            trace=[{"file": "src/Orders.java", "line": 88, "role": "invalid"}],
        )
        with self.assertRaisesRegex(ValueError, "role"):
            Finding.from_dict(malformed_trace)

    def test_findings_from_different_runs_are_rejected(self) -> None:
        sast = finding("sast", file="src/Orders.java", line=88)
        dast = Finding.from_dict({**record("dast"), "run_id": "another-run"})

        with self.assertRaisesRegex(ValueError, "share a run_id"):
            correlate([sast, dast])


if __name__ == "__main__":
    unittest.main()
