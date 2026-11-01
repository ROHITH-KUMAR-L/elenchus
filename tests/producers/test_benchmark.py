from __future__ import annotations

from pathlib import Path

import pytest

from producers.benchmark import (
    _load_snapshot,
    _normalize_target_url,
    _normalize_type,
    score_dast,
    score_sast,
    snapshot_ground_truth,
)

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "common" / "fixtures" / "benchmarks"


def test_full_target_snapshots_cover_all_official_ground_truth_rows():
    sast = _load_snapshot(FIXTURE_DIR / "vulnerableapp-sast.json")
    dast = _load_snapshot(FIXTURE_DIR / "vulnerableapp-dast.json")

    assert len(sast) == 105
    assert len(dast) == 168
    assert all("param" not in row and "params" not in row for row in dast)
    assert all({"route", "method", "type", "cwe", "wasc_id"} <= row.keys() for row in dast)
    assert all({"file", "line", "type", "cwe", "number_of_sources"} <= row.keys() for row in sast)


def test_dast_score_matches_runtime_evidence_by_route_method_and_target_cwe():
    expected = [
        {
            "route": "/lookup",
            "method": "GET",
            "type": "ERROR_BASED_SQL_INJECTION",
            "cwe": "CWE-89",
        },
        {
            "route": "/lookup",
            "method": "GET",
            "type": "UNION_BASED_SQL_INJECTION",
            "cwe": "CWE-89",
        },
        {
            "route": "/execute",
            "method": "GET",
            "type": "COMMAND_INJECTION",
            "cwe": "CWE-77",
        },
    ]
    issues = [
        {
            "issue_key": "runtime-sql",
            "label": "Confirmed",
            "route": "/lookup",
            "method": "GET",
            "cwe": 89,
            "type": "SQL Injection",
            "dast_findings": [{"source": "dast"}],
        },
        {
            "issue_key": "static-only",
            "label": "Code-only",
            "route": "/execute",
            "method": "GET",
            "cwe": 78,
            "type": "Command Injection",
            "dast_findings": [],
        },
        {
            "issue_key": "wrong-method",
            "label": "Runtime-only",
            "route": "/lookup",
            "method": "POST",
            "cwe": 89,
            "type": "SQL Injection",
            "dast_findings": [{"source": "dast"}],
        },
    ]

    report = score_dast(expected, issues, {"CWE-89", "CWE-77"})

    assert report["raw_score"] == {"found": 2, "expected": 3, "recall": 2 / 3}
    assert report["supported_score"] == {"found": 2, "expected": 3, "recall": 2 / 3}
    assert [(miss["route"], miss["method"]) for miss in report["misses"]] == [
        ("/execute", "GET"),
    ]
    assert report["runtime_issue_count"] == 2


def test_dast_type_fallback_and_target_url_normalization():
    assert _normalize_target_url(
        "http://127.0.0.1:9090/VulnerableApp/search?q=1",
        "/VulnerableApp",
    ) == "/search"
    assert _normalize_type("Reflected XSS") == "REFLECTED_XSS"

    report = score_dast(
        [
            {
                "route": "/search",
                "method": "GET",
                "type": "REFLECTED_XSS",
                "cwe": None,
            }
        ],
        [
            {
                "issue_key": "xss",
                "route": "/search",
                "method": "GET",
                "type": "Reflected XSS",
                "cwe": None,
                "dast_findings": [{"source": "dast"}],
            }
        ],
        set(),
    )

    assert report["raw_score"]["found"] == 1
    assert report["supported_score"]["expected"] == 0


def test_sast_score_reports_each_expected_miss():
    expected = [
        {"cwe": "CWE-89", "type": "sql injection", "file": "src/Query.java", "line": 10},
        {"cwe": "CWE-79", "type": "reflected xss", "file": "src/Page.java", "line": 20},
    ]
    reported = [
        {"cwe": "CWE-89", "type": "SQL Injection", "filePath": "src/Query.java", "line": 10}
    ]

    result = score_sast(expected, reported)

    assert result["matched"] == {0}
    assert result["unmatched"] == []


def test_snapshot_rejects_non_loopback_ground_truth_endpoint(tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        snapshot_ground_truth(
            tmp_path,
            "http://127.0.0.1:8080/app",
            Path("expected.csv"),
            Path("VulnerabilityType.java"),
            "http://example.test/scanner/dast",
        )
