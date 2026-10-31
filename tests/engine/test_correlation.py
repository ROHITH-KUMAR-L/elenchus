"""Lineage-based correlation: Confirmed links, Code-only, Runtime-only, ambiguity."""

from __future__ import annotations

import unittest

from common.pipeline import hypothesis_id
from common.record import Finding, SinkId
from engine.correlate import correlate

ROUTE = "/orders/{id}"
SINK = {
    "file": "src/OrderService.java",
    "enclosing_method": "OrderService.find",
    "start_line": 88,
    "start_col": 20,
}


def entry_paths(route=ROUTE, hops=1):
    chain = [{"method": "OrderController.get", "file": "src/OrderController.java", "line": 40}]
    if hops:
        chain.append({"method": "OrderService.find", "file": SINK["file"], "line": 80})
    return [{"route": route, "method": "GET", "hops": hops, "call_chain": chain}]


def static(
    sink=SINK,
    *,
    cwe=89,
    route=ROUTE,
    params=("id",),
    status="untested",
    severity="high",
    match_mode="strict",
    hops=1,
    corroborated=None,
    arg_shape="dynamic",
):
    return Finding.from_dict(
        {
            "run_id": "r", "source": "sast", "provenance": "own", "cwe": cwe,
            "type": "SQL Injection", "route": route, "method": "GET",
            "file": sink["file"] if sink else None, "line": sink["start_line"] if sink else None,
            "sink_id": sink, "arg_shape": arg_shape, "entry_paths": entry_paths(route, hops),
            "candidate_params": list(params), "status": status, "severity": severity,
            "match_mode": match_mode, "corroborated": corroborated,
            "evidence": [{"type": "PATH", "detail": {"snippet": "q(...)"}}],
        }
    )


def lineage_id(sink=SINK, route=ROUTE, cwe=89, params=("id",)):
    return hypothesis_id("directed", route, "GET", cwe, SinkId.from_value(sink), tuple(params))


def probe(
    *,
    cwe=89,
    route=ROUTE,
    param="id",
    hypothesis=None,
    payload="1'",
    job_pass=None,
    oracle_flaky=False,
    response_frames=None,
):
    job_pass = job_pass or ("directed" if hypothesis else "sweep")
    evidence = [
        {
            "type": "ORACLE",
            "detail": {
                "oracle": "sql_error",
                "hypothesis_ids": [hypothesis] if hypothesis else [],
                "fired": 3,
                "replays": 3,
                "job_pass": job_pass,
                "oracle_flaky": oracle_flaky,
            },
        }
    ]
    if response_frames is not None:
        evidence.append(
            {"type": "RESPONSE_TRACE", "detail": {"frames": response_frames}}
        )
    return Finding.from_dict(
        {
            "run_id": "r", "source": "dast", "provenance": "zap", "cwe": cwe,
            "type": "SQL Injection", "route": route, "method": "GET", "param": param,
            "payload": payload, "hypothesis_id": hypothesis,
            "evidence": evidence,
        }
    )


class CorrelationTests(unittest.TestCase):
    def test_directed_lineage_makes_a_unique_confirmed_link(self) -> None:
        [issue] = correlate([static(), probe(hypothesis=lineage_id())])
        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.link_status, "unique")
        self.assertEqual(issue.link_origin, "directed")
        self.assertEqual((issue.file, issue.line), ("src/OrderService.java", 88))
        self.assertEqual(issue.param, "id")
        self.assertAlmostEqual(issue.confidence, 0.95)
        self.assertEqual(
            {reason.factor for reason in issue.confidence_reasons},
            {"oracle_fired", "path_exists", "unique_link", "family_match"},
        )

    def test_sweep_links_by_route_and_param_when_no_sink_lineage_is_carried(self) -> None:
        [issue] = correlate([static(), probe(hypothesis=None)])
        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.link_status, "unique")
        self.assertEqual(issue.link_origin, "sweep")

    def test_cwe_or_param_mismatch_never_links(self) -> None:
        issues = correlate([static(), probe(cwe=79, hypothesis=None)])
        self.assertEqual({i.label for i in issues}, {"Code-only", "Runtime-only"})
        issues = correlate([static(), probe(param="other", hypothesis=None)])
        self.assertEqual({i.label for i in issues}, {"Code-only", "Runtime-only"})

    def test_two_sinks_on_one_route_are_ambiguous_with_alternatives(self) -> None:
        other = {**SINK, "enclosing_method": "OrderRepository.load", "start_line": 41}
        [issue] = correlate([static(), static(other), probe(hypothesis=None)])
        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.link_status, "ambiguous")
        self.assertEqual(len(issue.alternatives), 1)
        self.assertLess(issue.confidence, 0.7)

    def test_lineage_disambiguates_two_sinks_to_a_unique_link(self) -> None:
        other = {**SINK, "enclosing_method": "OrderRepository.load", "start_line": 41}
        # The probe carries only the first sink's hypothesis id, so that sink is
        # the unique Confirmed link and the other falls to Code-only.
        issues = correlate([static(), static(other), probe(hypothesis=lineage_id())])
        confirmed = [i for i in issues if i.label == "Confirmed"]
        code_only = [i for i in issues if i.label == "Code-only"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].link_status, "unique")
        self.assertEqual(confirmed[0].sink.enclosing_method, "OrderService.find")
        self.assertEqual(code_only[0].sink.enclosing_method, "OrderRepository.load")

    def test_directed_lineage_mismatch_does_not_fall_back_to_route_matching(self) -> None:
        issues = correlate([static(), probe(hypothesis="unmatched-lineage")])
        self.assertEqual({issue.label for issue in issues}, {"Code-only", "Runtime-only"})

    def test_ambiguous_primary_uses_specificity_then_path_then_source_order(self) -> None:
        relaxed = {
            **SINK,
            "file": "src/A.java",
            "enclosing_method": "A.find",
            "start_line": 1,
        }
        strict_long = {
            **SINK,
            "file": "src/B.java",
            "enclosing_method": "B.find",
            "start_line": 2,
        }
        strict_short_later = {
            **SINK,
            "file": "src/Z.java",
            "enclosing_method": "Z.find",
            "start_line": 3,
        }
        strict_short_first = {
            **SINK,
            "file": "src/C.java",
            "enclosing_method": "C.find",
            "start_line": 99,
        }
        strict_short_corroborated = {
            **SINK,
            "file": "src/Y.java",
            "enclosing_method": "Y.find",
            "start_line": 10,
        }
        [issue] = correlate(
            [
                static(relaxed, match_mode="relaxed", hops=0),
                static(strict_long, hops=2),
                static(strict_short_later, hops=1),
                static(strict_short_first, hops=1),
                static(strict_short_corroborated, hops=1, corroborated=True),
                probe(hypothesis=None),
            ]
        )
        self.assertEqual(issue.link_status, "ambiguous")
        self.assertEqual(issue.sink.file, "src/Y.java")
        self.assertEqual(
            {sink.file for sink in issue.alternatives},
            {"src/A.java", "src/B.java", "src/C.java", "src/Z.java"},
        )

    def test_tested_negative_conflict_confirms_as_ambiguous_and_unsuppresses(self) -> None:
        other = {**SINK, "file": "src/Other.java", "enclosing_method": "Other.query"}
        [issue] = correlate(
            [
                static(status="tested_negative"),
                static(other, status="untested"),
                probe(hypothesis=None),
            ]
        )

        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(issue.link_status, "ambiguous")
        self.assertEqual(issue.link_origin, "sweep")
        self.assertTrue(issue.conflict)
        self.assertFalse(issue.suppressed)
        negative = next(f for f in issue.sast_findings if f.status is None)
        untested = next(f for f in issue.sast_findings if f.status == "untested")
        self.assertTrue(negative.conflict)
        self.assertFalse(untested.conflict)
        self.assertEqual(len(issue.alternatives), 1)

    def test_low_confidence_conflict_stays_runtime_only_with_candidate_hint(self) -> None:
        [issue] = correlate(
            [static(status="tested_negative"), probe(hypothesis=None)],
            {"backguided.min_confidence_to_confirm": 0.99},
        )

        self.assertEqual(issue.label, "Runtime-only")
        self.assertEqual(issue.link_status, "ambiguous")
        self.assertEqual(issue.link_origin, "sweep")
        self.assertTrue(issue.conflict)
        self.assertEqual(len(issue.candidate_sinks), 1)
        self.assertIsNone(issue.sast_findings[0].status)

    def test_constant_safe_pattern_conflict_stays_unlinked_and_suppressed(self) -> None:
        issues = correlate(
            [
                static(status="safe_pattern", arg_shape="constant"),
                probe(hypothesis=None),
            ],
            {"export.suppress_cwes": (89,)},
        )

        runtime = next(issue for issue in issues if issue.label == "Runtime-only")
        code = next(issue for issue in issues if issue.label == "Code-only")
        self.assertTrue(runtime.conflict)
        self.assertIsNone(runtime.link_status)
        self.assertEqual(len(runtime.candidate_sinks), 1)
        self.assertEqual(code.status, "safe_pattern")
        self.assertTrue(code.suppressed)

    def test_sanitised_safe_pattern_can_be_reproduced_as_a_conflict(self) -> None:
        [issue] = correlate(
            [
                static(status="safe_pattern", arg_shape="sanitised"),
                probe(hypothesis=None),
            ]
        )

        self.assertEqual(issue.label, "Confirmed")
        self.assertTrue(issue.conflict)
        self.assertEqual(issue.link_status, "ambiguous")

    def test_flaky_replay_stays_runtime_only_and_does_not_link(self) -> None:
        issues = correlate(
            [
                static(),
                probe(hypothesis=None, oracle_flaky=True),
            ]
        )

        runtime = next(issue for issue in issues if issue.label == "Runtime-only")
        self.assertTrue(runtime.oracle_flaky)
        self.assertIsNone(runtime.link_status)
        self.assertFalse(runtime.conflict)

    def test_deepest_response_trace_frame_resolves_the_unique_candidate(self) -> None:
        other = {**SINK, "file": "src/OrderRepository.java", "enclosing_method": "OrderRepository.load"}
        frames = [
            {
                "method": "com.example.OrderRepository.load",
                "file": "src/OrderRepository.java",
                "line": 41,
                "project": True,
            },
            {
                "method": "com.example.OrderService.find",
                "file": "src/OrderService.java",
                "line": 80,
                "project": True,
            },
        ]

        [issue] = correlate(
            [static(), static(other), probe(hypothesis=None, response_frames=frames)]
        )

        self.assertEqual(issue.link_status, "unique")
        self.assertEqual(issue.sink.enclosing_method, "OrderRepository.load")
        self.assertEqual(len(issue.alternatives), 1)

    def test_unmatched_project_frame_logs_gap_and_reduces_confidence(self) -> None:
        frames = [
            {
                "method": "com.example.Uncatalogued.handle",
                "file": "src/Uncatalogued.java",
                "line": 30,
                "project": True,
            }
        ]

        with self.assertLogs("engine.correlate.core", level="WARNING") as logs:
            [issue] = correlate(
                [static(), probe(hypothesis=None, response_frames=frames)]
            )

        self.assertIn("Catalogue gap", logs.output[0])
        self.assertEqual(issue.link_status, "unique")
        self.assertLess(issue.confidence, 0.95)
        self.assertIn("catalogue_gap", {r.factor for r in issue.confidence_reasons})

    def test_unlinked_static_is_code_only_with_its_status(self) -> None:
        [issue] = correlate([static(status="no_http_path")])
        self.assertEqual(issue.label, "Code-only")
        self.assertEqual(issue.status, "no_http_path")

    def test_probe_with_no_sink_is_runtime_only(self) -> None:
        [issue] = correlate([probe(route="/unmapped", hypothesis=None)])
        self.assertEqual(issue.label, "Runtime-only")
        self.assertIsNone(issue.link_status)
        self.assertAlmostEqual(issue.confidence, 0.5)

    def test_confirmed_ranks_above_code_only_and_runtime_only(self) -> None:
        issues = correlate(
            [
                static(),
                probe(hypothesis=lineage_id()),
                static({**SINK, "enclosing_method": "Other.q", "start_line": 5}, route="/x"),
                probe(route="/y", hypothesis=None),
            ]
        )
        self.assertEqual(issues[0].label, "Confirmed")
        self.assertEqual(issues[-1].label, "Runtime-only")

    def test_findings_from_different_runs_are_rejected(self) -> None:
        other = Finding.from_dict({**probe(hypothesis=None).to_dict(), "run_id": "another"})
        with self.assertRaisesRegex(ValueError, "share a run_id"):
            correlate([static(), other])

    def test_two_params_on_one_sink_make_one_issue(self) -> None:
        # Two params reaching one sink (e.g. username and password on an auth
        # query) are one issue with both probes as evidence, not two issues that
        # share a sink. Dedupe key is (sink_id, cwe).
        sink = static(params=("username", "password"))
        issues = correlate([sink, probe(param="username"), probe(param="password")])
        self.assertEqual(len(issues), 1)
        [issue] = issues
        self.assertEqual(issue.label, "Confirmed")
        self.assertEqual(len(issue.dast_findings), 2)
        self.assertEqual({f.param for f in issue.dast_findings}, {"username", "password"})


if __name__ == "__main__":
    unittest.main()
