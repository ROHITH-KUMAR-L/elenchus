"""Coverage and attribution measurements for one scan run."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from common.record import Finding, normalize_file


def build_coverage_report(
    findings: Sequence[Finding],
    *,
    expected_pairs: Mapping[str, Any] | None = None,
    supported_cwes: Iterable[int] = (),
    skipped_by_type: Iterable[tuple[str, str, str]] = (),
    attribution_rate: float | None = None,
    header_propagation_rate: float | None = None,
) -> dict[str, Any]:
    pairs = list(expected_pairs.get("pairs", ())) if expected_pairs is not None else []
    supported = set(supported_cwes)
    skipped = set(skipped_by_type)
    static = [finding for finding in findings if finding.source == "sast"]
    probes = [finding for finding in findings if finding.source == "dast"]

    by_cwe: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for pair in pairs:
        cwe = int(pair["cwe"])
        match = _matching_static(static, pair)
        if match is not None:
            result = {"found": True}
        else:
            tag = _miss_tag(static, pair, skipped)
            result = {
                "found": False,
                "miss": tag,
                "route": pair["route"],
                "method": pair["method"],
                "file": pair["file"],
                "line": pair["line"],
            }
        by_cwe[cwe].append(result)

    recall_by_cwe = {
        f"CWE-{cwe}": _recall(entries)
        for cwe, entries in sorted(by_cwe.items())
    }
    detected = sum(item["found"] for entries in by_cwe.values() for item in entries)
    total = sum(len(entries) for entries in by_cwe.values())
    supported_detected = sum(
        item["found"]
        for cwe, entries in by_cwe.items()
        if cwe in supported
        for item in entries
    )
    supported_total = sum(
        len(entries) for cwe, entries in by_cwe.items() if cwe in supported
    )
    attributed = [
        finding
        for finding in probes
        if finding.param is not None and _has_hypothesis(finding)
    ]
    accurate = (
        sum(_probe_matches_expected(finding, pairs) for finding in attributed)
        if pairs
        else None
    )
    accuracy = accurate / len(attributed) if attributed and accurate is not None else None

    return {
        "recall_by_cwe": recall_by_cwe,
        "raw_score": _score(detected, total),
        "supported_cwe_score": _score(supported_detected, supported_total),
        "attribution_rate": attribution_rate,
        "attribution_accuracy": accuracy,
        "attribution_counts": {
            "attributed_hits": len(attributed),
            "accurate_hits": accurate,
        },
        "header_propagation_rate": header_propagation_rate,
        "skipped_by_type": [
            {"route": route, "method": method, "param": param}
            for route, method, param in sorted(skipped)
        ],
    }


def _matching_static(
    findings: Sequence[Finding], pair: Mapping[str, Any]
) -> Finding | None:
    for finding in findings:
        if (
            finding.cwe == int(pair["cwe"])
            and normalize_file(finding.file) == normalize_file(str(pair["file"]))
            and finding.line == int(pair["line"])
            and any(
                path.route == pair["route"] and path.method == str(pair["method"]).upper()
                for path in finding.entry_paths or ()
            )
        ):
            return finding
    return None


def _miss_tag(
    findings: Sequence[Finding],
    pair: Mapping[str, Any],
    skipped: set[tuple[str, str, str]],
) -> str:
    at_sink = [
        finding
        for finding in findings
        if finding.cwe == int(pair["cwe"])
        and normalize_file(finding.file) == normalize_file(str(pair["file"]))
        and finding.line == int(pair["line"])
    ]
    if not at_sink:
        return "no_catalogue_entry"
    if any(
        finding.status == "no_http_path" and finding.unlinked_reason == "walk_unresolved"
        for finding in at_sink
    ):
        return "walk_unresolved"
    if any(
        (pair["route"], str(pair["method"]).upper(), param) in skipped
        for param in pair.get("params", ())
    ):
        return "param_unbuildable"
    return "route_missing"


def _has_hypothesis(finding: Finding) -> bool:
    if finding.hypothesis_id:
        return True
    carried = finding.detail("hypothesis_ids")
    return isinstance(carried, list) and bool(carried)


def _probe_matches_expected(finding: Finding, pairs: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        int(pair["cwe"]) == finding.cwe
        and pair["route"] == finding.route
        and str(pair["method"]).upper() == finding.method
        and finding.param in pair.get("params", ())
        for pair in pairs
    )


def _recall(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    found = sum(item["found"] for item in entries)
    total = len(entries)
    misses = [item for item in entries if not item["found"]]
    return {
        "found": found,
        "expected": total,
        "recall": found / total if total else None,
        "misses": misses,
    }


def _score(found: int, expected: int) -> dict[str, Any]:
    return {
        "found": found,
        "expected": expected,
        "recall": found / expected if expected else None,
    }
