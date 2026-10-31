"""Scan comparison (B-5): new, fixed and still-open issues across two runs."""

from __future__ import annotations

import json
from pathlib import Path

from engine.compare import compare_runs, comparison_key

FIXTURE = Path(__file__).parents[2] / "common" / "fixtures" / "scans" / "scan-compare.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_classifies_fixed_new_and_still_open():
    data = load_fixture()
    comparison = compare_runs(
        data["base"], data["current"], base_run_id="r1", current_run_id="r2"
    )
    assert [i.issue_key for i in comparison.new] == data["expected"]["new"]
    assert [i.issue_key for i in comparison.fixed] == data["expected"]["fixed"]
    assert [i.issue_key for i in comparison.still_open] == data["expected"]["still_open"]


def test_suppressed_issue_is_not_a_fix():
    data = load_fixture()
    comparison = compare_runs(data["base"], data["current"])
    assert all(i.cwe != 601 for i in comparison.issues)


def test_still_open_tracks_a_label_change():
    sink = {"file": "A.java", "enclosing_method": "A.m", "start_line": 10, "start_col": 1}
    base = [{"issue_key": "a", "label": "Code-only", "cwe": 89, "type": "SQLi", "sink_id": sink}]
    current = [{"issue_key": "b", "label": "Confirmed", "cwe": 89, "type": "SQLi", "sink_id": sink}]
    [issue] = compare_runs(base, current).still_open
    assert issue.label == "Confirmed"
    assert issue.previous_label == "Code-only"


def test_runtime_only_issues_compare_by_route_param_cwe():
    base = [{"issue_key": "a", "label": "Runtime-only", "cwe": 79, "type": "XSS",
             "route": "/x", "method": "GET", "param": "q"}]
    current = [{"issue_key": "b", "label": "Runtime-only", "cwe": 79, "type": "XSS",
                "route": "/x", "method": "GET", "param": "q"}]
    comparison = compare_runs(base, current)
    assert len(comparison.still_open) == 1
    assert not comparison.new and not comparison.fixed


def test_comparison_key_sink_identity_ignores_issue_key():
    sink = {"file": "A.java", "enclosing_method": "A.m", "start_line": 10, "start_col": 1}
    left = {"issue_key": "one", "cwe": 89, "sink_id": sink}
    right = {"issue_key": "two", "cwe": 89, "sink_id": sink}
    assert comparison_key(left) == comparison_key(right)


def test_empty_runs_compare_to_nothing():
    comparison = compare_runs([], [])
    assert comparison.issues == ()
    assert comparison.to_dict()["counts"] == {"new": 0, "fixed": 0, "still_open": 0}
