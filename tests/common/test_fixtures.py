"""Every fixture must load through the contract, and state a usable expectation."""

import json
from pathlib import Path

import pytest

from common.record import ISSUE_LABELS, LINK_ORIGINS, LINK_STATUSES, STATUSES, Finding, dedupe_key

FIXTURES = Path(__file__).parents[2] / "common" / "fixtures"
FILES = sorted(FIXTURES.glob("*.json"))
EXPECTED_KEYS = {"label", "status", "suppressed", "link_status", "link_origin", "param", "alternatives"}


def load(path):
    return json.loads(path.read_text())


def test_required_fixture_rows_exist():
    assert {path.stem for path in FILES} == {
        "unique-directed",
        "ambiguous-group",
        "tested-negative-decoy",
        "blocked-baseline",
        "no-http-path",
        "runtime-only-header",
        "sweep-hit-matched",
        "sweep-hit-unmatched",
    }


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_fixture_loads_and_round_trips(path):
    body = load(path)
    assert body["description"]
    findings = [Finding.from_dict(raw) for raw in body["findings"]]
    assert findings
    for finding in findings:
        assert Finding.from_dict(finding.to_dict()) == finding
        dedupe_key(finding)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_fixture_expectation_uses_contract_values(path):
    expected = load(path)["expected"]
    assert expected
    assert set(expected) <= EXPECTED_KEYS
    assert expected.get("label") is None or expected["label"] in ISSUE_LABELS
    assert expected.get("status") is None or expected["status"] in STATUSES
    assert expected.get("link_status") is None or expected["link_status"] in LINK_STATUSES
    assert expected.get("link_origin") is None or expected["link_origin"] in LINK_ORIGINS


def test_static_fixture_records_never_claim_a_param():
    for path in FILES:
        for raw in load(path)["findings"]:
            if raw["source"] == "sast":
                assert raw.get("param") is None
