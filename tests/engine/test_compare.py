"""Scan comparison (B-5): new, fixed and still-open issues across two runs.

The inputs here are produced by the real correlation engine (correlate) over
Finding records, not hand-written issue dicts, so the test exercises the same
Issue shape a stored run holds. A live two-run comparison against VulnerableApp
through Postgres is the end-to-end check and is recorded in docs/STATE.md.
"""

from __future__ import annotations

from common.pipeline import hypothesis_id
from common.record import Finding, SinkId
from engine.compare import compare_runs, comparison_key
from engine.correlate import correlate

ROUTE = "/orders/{id}"
SINK_A = {"file": "src/OrderService.java", "enclosing_method": "OrderService.find",
          "start_line": 88, "start_col": 20}
SINK_B = {"file": "src/LegacyDao.java", "enclosing_method": "LegacyDao.load",
          "start_line": 40, "start_col": 10}


def static(sink, route=ROUTE):
    return Finding.from_dict({
        "run_id": "r", "source": "sast", "provenance": "own", "cwe": 89, "type": "SQL Injection",
        "route": route, "method": "GET", "file": sink["file"], "line": sink["start_line"],
        "sink_id": sink, "arg_shape": "dynamic", "candidate_params": ["id"], "severity": "high",
        "entry_paths": [{"route": route, "method": "GET", "hops": 0,
                         "call_chain": [{"method": sink["enclosing_method"], "file": sink["file"],
                                         "line": sink["start_line"]}]}],
        "evidence": [{"type": "PATH", "detail": {"snippet": "q(...)"}}],
    })


def probe(sink, route=ROUTE):
    lineage = hypothesis_id("directed", route, "GET", 89, SinkId.from_value(sink), ("id",))
    return Finding.from_dict({
        "run_id": "r", "source": "dast", "provenance": "zap", "cwe": 89, "type": "SQL Injection",
        "route": route, "method": "GET", "param": "id", "payload": "1'", "hypothesis_id": lineage,
        "evidence": [{"type": "ORACLE", "detail": {"oracle": "sql_error", "hypothesis_ids": [lineage],
                     "fired": 3, "replays": 3}}],
    })


def issues_of(findings):
    return [issue.to_dict() for issue in correlate(findings)]


def test_fixed_new_and_still_open_from_real_correlation_output():
    # Run A: two code sinks. Run B: sink B is gone (fixed) and a probe confirmed
    # sink A (still open, label changed), plus a probe-only runtime hit (new).
    base = issues_of([static(SINK_A), static(SINK_B)])
    current = issues_of([static(SINK_A), probe(SINK_A), probe(sink=SINK_A, route="/search")])

    comparison = compare_runs(base, current, base_run_id="A", current_run_id="B")
    fixed = comparison.fixed
    still = comparison.still_open
    new = comparison.new

    assert [i.file for i in fixed] == ["src/LegacyDao.java"]        # sink B fixed
    assert any(i.file == "src/OrderService.java" for i in still)    # sink A still open
    open_a = next(i for i in still if i.file == "src/OrderService.java")
    assert open_a.label == "Confirmed" and open_a.previous_label == "Code-only"
    assert any(i.label == "Runtime-only" for i in new)              # the unmapped probe is new


def test_identical_runs_are_all_still_open():
    issues = issues_of([static(SINK_A), probe(SINK_A)])
    comparison = compare_runs(issues, issues)
    assert not comparison.new and not comparison.fixed
    assert len(comparison.still_open) == len(issues)


def test_comparison_key_sink_identity_ignores_issue_key():
    sink = {"file": "A.java", "enclosing_method": "A.m", "start_line": 10, "start_col": 1}
    assert comparison_key({"issue_key": "one", "cwe": 89, "sink_id": sink}) == comparison_key(
        {"issue_key": "two", "cwe": 89, "sink_id": sink}
    )


def test_empty_runs_compare_to_nothing():
    comparison = compare_runs([], [])
    assert comparison.issues == ()
    assert comparison.to_dict()["counts"] == {"new": 0, "fixed": 0, "still_open": 0}
