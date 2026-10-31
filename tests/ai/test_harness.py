"""The with/without harness runs offline with AI off and produces a diff table."""

from __future__ import annotations

from dataclasses import dataclass

from ai.harness import measure, with_without
from ai.schema import valid


@dataclass
class FakeIssue:
    cwe: int
    route: str | None = None
    param: str | None = None
    label: str = "Confirmed"
    link_status: str | None = "unique"
    suppressed: bool = False


PAIRS = {"pairs": [{"route": "/a", "method": "GET", "params": ["id"], "cwe": 89, "file": "A.java", "line": 1}]}


def test_measure_counts_correct_and_wrong_links():
    issues = [
        FakeIssue(89, "/a", "id"),                 # correct link
        FakeIssue(89, "/b", "x"),                  # wrong link (no pair)
        FakeIssue(79, "/c", "q", label="Code-only", link_status=None),  # not confirmed
        FakeIssue(89, "/d", "y", suppressed=True),  # suppressed, not reported
    ]
    arm = measure(issues, PAIRS)
    assert arm.confirmed == 2
    assert arm.reported == 3
    assert arm.correct_links == 1
    assert arm.wrong_links == 1


def test_with_without_is_offline_and_reports_no_regression_when_identical():
    calls = []

    def runner(ai_enabled):
        calls.append(ai_enabled)
        # AI off makes no network call, so both arms return the same issues.
        return [FakeIssue(89, "/a", "id")]

    result = with_without(runner, PAIRS)
    assert calls == [False, True]
    assert not result.regressed
    assert result.to_dict()["safe_to_enable"] is True
    assert "correct_links" in result.table()


def test_regression_is_flagged_when_ai_loses_a_correct_link():
    def runner(ai_enabled):
        if ai_enabled:
            return [FakeIssue(89, "/b", "x")]  # lost the correct link, added a wrong one
        return [FakeIssue(89, "/a", "id")]

    result = with_without(runner, PAIRS)
    assert result.regressed
    assert "do NOT enable" in result.table()


def test_schema_validator_handles_nested_shapes():
    schema = {
        "type": "object",
        "required": ["items"],
        "properties": {"items": {"type": "array", "items": {"type": "string"}}},
    }
    assert valid({"items": ["a", "b"]}, schema)
    assert not valid({"items": [1]}, schema)
    assert not valid({}, schema)
