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
            },
        }
    ]
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
