"""Deterministic deduplication and tiered SAST/DAST correlation."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Iterable

from engine.correlate.models import (
    SEVERITY_ORDER,
    Finding,
    FindingCluster,
    Issue,
)

_CONFIDENCE_RANK = {"A": 3, "B": 2, "C": 1}
_SEVERITY_SCORE = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "moderate": 50,
    "low": 25,
    "info": 10,
    "informational": 10,
}


def correlate(findings: Iterable[Finding]) -> list[Issue]:
    records = list(findings)
    if not records:
        return []
    run_ids = {finding.run_id for finding in records}
    if len(run_ids) != 1:
        raise ValueError("all findings in one correlation run must share a run_id")

    clusters = _deduplicate(records)
    sast_clusters = [group for group in clusters if group.representative.source == "sast"]
    dast_clusters = [group for group in clusters if group.representative.source == "dast"]
    matches = _unambiguous_matches(sast_clusters, dast_clusters)
    matched_sast = {match[0] for match in matches}
    matched_dast = {match[1] for match in matches}
    issues: list[Issue] = []

    for sast_index, dast_index, confidence, reason in matches:
        sast_group = sast_clusters[sast_index]
        dast_group = dast_clusters[dast_index]
        issues.append(
            _make_issue(
                (sast_group,),
                (dast_group,),
                confidence,
                reason,
            )
        )
    for index, group in enumerate(sast_clusters):
        if index not in matched_sast:
            issues.append(_make_issue((group,), (), None, None))
    for index, group in enumerate(dast_clusters):
        if index not in matched_dast:
            issues.append(_make_issue((), (group,), None, None))
    return sorted(issues, key=_issue_sort_key)


def _deduplicate(findings: list[Finding]) -> list[FindingCluster]:
    groups: dict[tuple[object, ...], list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[_finding_identity(finding)].append(finding)
    clusters = []
    for key in sorted(groups, key=lambda value: tuple(str(part) for part in value)):
        grouped = groups[key]
        representative = max(
            grouped,
            key=lambda finding: (
                SEVERITY_ORDER.get((finding.severity or "").casefold(), 1),
                _stable_json(finding.to_dict()),
            ),
        )
        clusters.append(FindingCluster(representative, tuple(grouped)))
    return clusters


def _finding_identity(finding: Finding) -> tuple[object, ...]:
    header_name = finding.evidence.get("header_name")
    if isinstance(header_name, str) and header_name:
        identity = ("header", finding.cwe, header_name.casefold())
    elif finding.file is not None and finding.line is not None:
        identity = ("code", finding.cwe, _normalize_file(finding.file), finding.line)
    else:
        identity = (
            "route",
            finding.cwe,
            finding.route,
            finding.method,
            finding.param,
        )
    return (finding.source, *identity)


def _unambiguous_matches(
    sast_clusters: list[FindingCluster],
    dast_clusters: list[FindingCluster],
) -> list[tuple[int, int, str, str]]:
    proposals: dict[int, tuple[int, str, str]] = {}
    for dast_index, dast_group in enumerate(dast_clusters):
        candidates: list[tuple[int, str, str]] = []
        for sast_index, sast_group in enumerate(sast_clusters):
            match = _match_tier(sast_group.representative, dast_group.representative)
            if match is not None:
                candidates.append((sast_index, match[0], match[1]))
        if not candidates:
            continue
        best_rank = max(_CONFIDENCE_RANK[tier] for _, tier, _ in candidates)
        best = [candidate for candidate in candidates if _CONFIDENCE_RANK[candidate[1]] == best_rank]
        if len(best) == 1:
            proposals[dast_index] = best[0]

    by_sast: dict[int, list[tuple[int, str, str]]] = defaultdict(list)
    for dast_index, proposal in proposals.items():
        by_sast[proposal[0]].append((dast_index, proposal[1], proposal[2]))

    accepted: list[tuple[int, int, str, str]] = []
    for sast_index, candidates in by_sast.items():
        best_rank = max(_CONFIDENCE_RANK[tier] for _, tier, _ in candidates)
        best = [candidate for candidate in candidates if _CONFIDENCE_RANK[candidate[1]] == best_rank]
        if len(best) == 1:
            dast_index, tier, reason = best[0]
            accepted.append((sast_index, dast_index, tier, reason))
    return sorted(accepted, key=lambda match: (match[0], match[1]))


def _match_tier(sast: Finding, dast: Finding) -> tuple[str, str] | None:
    if sast.cwe != dast.cwe or sast.param != dast.param:
        return None

    if _same_route_and_method(sast, dast):
        if (
            sast.file is not None
            and sast.line is not None
            and sast.handler_file is not None
            and sast.handler_line_start is not None
            and sast.handler_line_end is not None
            and _same_file(sast.file, sast.handler_file)
            and sast.handler_line_start <= sast.line <= sast.handler_line_end
        ):
            return "A", "Same CWE and parameter; the SAST sink is inside its handler span."
    if dast.route is not None and dast.method is not None and any(
        edge.route == dast.route and edge.method == dast.method
        for edge in sast.reached_via or ()
    ):
        return "B", "Same CWE and parameter; the SAST method is reached by this handler."
    if _same_route_and_method(sast, dast):
        return "C", "Same CWE, route, method, and parameter."
    return None


def _same_route_and_method(sast: Finding, dast: Finding) -> bool:
    return (
        sast.route is not None
        and dast.route is not None
        and sast.route == dast.route
        and sast.method == dast.method
    )


def _normalize_file(file: str | None) -> str | None:
    if file is None:
        return None
    normalized = file.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _same_file(left: str, right: str) -> bool:
    return _normalize_file(left) == _normalize_file(right)


def _issue_key(sast: tuple[FindingCluster, ...], dast: tuple[FindingCluster, ...]) -> str:
    representative = sast[0].representative if sast else dast[0].representative
    header_name = representative.evidence.get("header_name")
    if isinstance(header_name, str) and header_name:
        identity = ("header", representative.cwe, header_name.casefold())
    elif representative.file is not None and representative.line is not None:
        identity = (
            "code",
            representative.cwe,
            _normalize_file(representative.file),
            representative.line,
        )
    else:
        identity = (
            "runtime",
            representative.cwe,
            representative.route,
            representative.method,
            representative.param,
        )
    digest = hashlib.sha256(_stable_json(identity).encode("utf-8")).hexdigest()
    return digest[:24]


def _make_issue(
    sast: tuple[FindingCluster, ...],
    dast: tuple[FindingCluster, ...],
    confidence: str | None,
    reason: str | None,
) -> Issue:
    sast_findings = tuple(item for group in sast for item in group.findings)
    dast_findings = tuple(item for group in dast for item in group.findings)
    all_findings = sast_findings + dast_findings
    severity = max(
        (finding.severity or "unknown" for finding in all_findings),
        key=lambda value: SEVERITY_ORDER.get(value.casefold(), 1),
    )
    base_score = _SEVERITY_SCORE.get(severity.casefold(), 0)
    confidence_bonus = {"A": 10, "B": 7, "C": 3}.get(confidence, 0)
    risk_score = float(min(100, base_score + confidence_bonus))
    if sast_findings and dast_findings:
        label = "Confirmed"
    elif sast_findings:
        label = "Code-only"
    else:
        label = "Runtime-only"
    return Issue(
        issue_key=_issue_key(sast, dast),
        label=label,
        confidence=confidence,
        risk_score=risk_score,
        severity=severity,
        sast_findings=sast_findings,
        dast_findings=dast_findings,
        link_reason=reason,
    )


def _issue_sort_key(issue: Issue) -> tuple[int, float, str]:
    label_order = {"Confirmed": 0, "Code-only": 1, "Runtime-only": 2}
    return label_order[issue.label], -issue.risk_score, issue.issue_key


def _stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
