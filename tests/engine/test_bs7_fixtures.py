import json
import logging
from pathlib import Path

import pytest

from common.record import Finding
from engine.correlate import correlate

FIXTURES = Path(__file__).parents[2] / "common" / "fixtures"
CASES = (
    "conflict-tested-negative",
    "conflict-sanitised",
    "conflict-constant",
    "response-trace-unique",
    "response-trace-gap",
    "response-trace-multiple-matches",
)


@pytest.mark.parametrize("name", CASES)
def test_bs7_correlation_fixture_expectations(name, caplog):
    fixture = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    findings = [Finding.from_dict(raw) for raw in fixture["findings"]]
    expected = fixture["expected"]

    if name == "response-trace-gap":
        with caplog.at_level(logging.WARNING, logger="engine.correlate.core"):
            issues = correlate(findings)
        assert any("Catalogue gap" in record.message for record in caplog.records)
    else:
        issues = correlate(findings)

    issue = next(item for item in issues if item.label == expected["label"])
    for field in ("label", "status", "suppressed", "link_status", "link_origin", "conflict"):
        if field in expected:
            assert getattr(issue, field) == expected[field]
    if "candidate_sinks" in expected:
        assert [sink.to_dict() for sink in issue.candidate_sinks] == expected["candidate_sinks"]
    if "alternatives" in expected:
        assert [sink.to_dict() for sink in issue.alternatives] == expected["alternatives"]
    if name == "response-trace-gap":
        assert "catalogue_gap" in {reason.factor for reason in issue.confidence_reasons}


def test_ambiguous_directed_fixture_carries_complete_lineage():
    fixture = json.loads((FIXTURES / "ambiguous-group.json").read_text(encoding="utf-8"))
    findings = [Finding.from_dict(raw) for raw in fixture["findings"]]
    [issue] = correlate(findings)

    assert issue.label == "Confirmed"
    assert issue.link_status == "ambiguous"
    assert issue.link_origin == "directed"
    assert len(issue.alternatives) == 1
