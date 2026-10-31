"""Deterministic correlation: link probe hits to code by hypothesis lineage.

A probe finding fired an oracle on some (route, param, CWE). It is linked to the
static sink(s) that produced the directed hypothesis behind the job, found by the
hypothesis id the probe carries, never by matching after the fact. One candidate
sink is a unique link; several is ambiguous (BS7 adds the primary rule, the
sweep and back-guided origins, and the conflict rule). Confidence is a float from
config weights, with every factor stored in confidence_reasons.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from common.config import DEFAULTS
from common.pipeline import hypothesis_id
from common.record import ConfidenceReason, Finding, dedupe_key
from engine.correlate.models import SEVERITY_ORDER, Issue

_SEVERITY_SCORE = {
    "critical": 90, "high": 75, "medium": 50, "moderate": 50, "low": 25, "info": 10,
    "informational": 10, "unknown": 10,
}
_CODE_ONLY_STATUSES = {"no_http_path", "blocked", "untested", "safe_pattern", "tested_negative"}


def _weight(config: Mapping[str, Any] | None, key: str) -> float:
    if config is not None and key in config:
        return float(config[key])
    return float(DEFAULTS[key])


def correlate(findings: Iterable[Finding], config: Mapping[str, Any] | None = None) -> list[Issue]:
    records = list(findings)
    if not records:
        return []
    run_ids = {finding.run_id for finding in records}
    if len(run_ids) != 1:
        raise ValueError("all findings in one correlation run must share a run_id")

    static = [f for f in records if f.source == "sast"]
    probes = [f for f in records if f.source == "dast"]

    issues: list[Issue] = []
    linked_static: set[int] = set()

    # Resolve candidate sinks per (route, param, CWE): the param decides which
    # sinks on the route a hit can reach. But the issue identity is the sink, not
    # the param, so hits that resolve to the same sink (e.g. username and password
    # both reaching one auth query) are one issue with several evidence entries,
    # per the (sink_id, cwe) dedupe key. Group by resolved identity, then build one
    # issue per identity.
    probe_groups: dict[tuple[str | None, str | None, int], list[Finding]] = defaultdict(list)
    for probe in probes:
        probe_groups[(probe.route, probe.param, probe.cwe)].append(probe)

    linked: dict[str, tuple[list[Finding], list[int]]] = {}
    runtime: list[list[Finding]] = []
    for key, group in sorted(probe_groups.items(), key=lambda item: str(item[0])):
        route, param, cwe = key
        lineage = _lineage_ids(group)
        candidates = _candidate_sinks(static, route, param, cwe, lineage)
        if not candidates:
            runtime.append(group)
            continue
        linked_static.update(candidates)
        identity = _sink_key(static[candidates[0]])
        probes_acc, sinks_acc = linked.setdefault(identity, ([], []))
        probes_acc.extend(group)
        for index in candidates:
            if index not in sinks_acc:
                sinks_acc.append(index)

    for probes_acc, sinks_acc in linked.values():
        issues.append(_linked_issue(probes_acc, [static[i] for i in sinks_acc], config))
    for group in runtime:
        issues.append(_linked_issue(group, [], config))

    for index, finding in enumerate(static):
        if index not in linked_static:
            issues.append(_code_only_issue(finding, config))

    return sorted(issues, key=_issue_sort_key)


def _lineage_ids(group: list[Finding]) -> set[str]:
    ids: set[str] = set()
    for probe in group:
        carried = probe.detail("hypothesis_ids")
        if isinstance(carried, list):
            ids.update(str(h) for h in carried)
        if probe.hypothesis_id:
            ids.add(probe.hypothesis_id)
    return ids


def _static_hypothesis_ids(finding: Finding) -> set[str]:
    if finding.sink_id is None or not finding.entry_paths:
        return set()
    params = finding.candidate_params or ()
    return {
        hypothesis_id("directed", path.route, path.method, finding.cwe, finding.sink_id, params)
        for path in finding.entry_paths
    }


def _candidate_sinks(
    static: list[Finding], route: str | None, param: str | None, cwe: int, lineage: set[str]
) -> list[int]:
    """Indices of the static sinks a probe hit links to, preferring lineage."""
    by_route: list[int] = []
    for index, finding in enumerate(static):
        if finding.cwe != cwe or finding.sink_id is None:
            continue
        reaches = any(path.route == route for path in finding.entry_paths or ())
        if reaches and (param is None or param in (finding.candidate_params or ())):
            by_route.append(index)
    if lineage:
        linked = [i for i in by_route if _static_hypothesis_ids(static[i]) & lineage]
        if linked:
            return linked
    return by_route


def _linked_issue(
    probes: list[Finding], sinks: list[Finding], config: Mapping[str, Any] | None
) -> Issue:
    probe = probes[0]
    severity = _max_severity(probes + sinks)
    if not sinks:
        confidence, reasons = _confidence(
            config, oracle=True, path=False, unique=False, ambiguous=False
        )
        return Issue(
            issue_key=_runtime_key(probe),
            label="Runtime-only",
            cwe=probe.cwe,
            type=probe.type,
            severity=severity,
            risk_score=_risk(severity, confidence),
            confidence=confidence,
            confidence_reasons=reasons,
            route=probe.route,
            method=probe.method,
            param=probe.param,
            dast_findings=tuple(probes),
            link_reason="Oracle fired but no code path was found for this route.",
        )
    unique = len(sinks) == 1
    primary = sinks[0]
    confidence, reasons = _confidence(
        config, oracle=True, path=True, unique=unique, ambiguous=not unique
    )
    confidence, reasons = _with_family(probes, config, confidence, reasons)
    return Issue(
        issue_key=_sink_key(primary),
        label="Confirmed",
        cwe=probe.cwe,
        type=probe.type,
        severity=severity,
        risk_score=_risk(severity, confidence),
        link_status="unique" if unique else "ambiguous",
        link_origin="directed",
        confidence=confidence,
        confidence_reasons=reasons,
        route=probe.route,
        method=probe.method,
        param=probe.param,
        sink=primary.sink_id,
        alternatives=tuple(s.sink_id for s in sinks[1:] if s.sink_id is not None),
        file=primary.file,
        line=primary.line,
        link_reason=(
            "Directed hypothesis fired: the probe's lineage matches this sink."
            if unique
            else "Directed hypotheses fired for several sinks on this route; link is ambiguous."
        ),
        sast_findings=tuple(sinks),
        dast_findings=tuple(probes),
    )


def _code_only_issue(
    finding: Finding, config: Mapping[str, Any] | None = None
) -> Issue:
    status = finding.status if finding.status in _CODE_ONLY_STATUSES else "untested"
    suppress_cwes = (
        config.get("export.suppress_cwes", DEFAULTS["export.suppress_cwes"])
        if config is not None
        else DEFAULTS["export.suppress_cwes"]
    )
    suppressed = status in {"safe_pattern", "tested_negative"} and finding.cwe in suppress_cwes
    if status == "no_http_path":
        suppressible_injection_cwes = {22, 78, 79, 89, 601}
        suppressed = (
            config is not None
            and bool(config.get("export.suppress_no_http_path", False))
            and finding.cwe in suppressible_injection_cwes
            and finding.unlinked_reason == "no_callers"
        )
    return Issue(
        issue_key=_sink_key(finding),
        label="Code-only",
        cwe=finding.cwe,
        type=finding.type,
        severity=finding.severity or "unknown",
        risk_score=_risk(finding.severity or "unknown", None),
        route=finding.route,
        method=finding.method,
        sink=finding.sink_id,
        file=finding.file,
        line=finding.line,
        status=status,
        suppressed=suppressed,
        link_reason=finding.unlinked_reason,
        sast_findings=(finding,),
    )


def _confidence(
    config: Mapping[str, Any] | None, *, oracle: bool, path: bool, unique: bool, ambiguous: bool
) -> tuple[float, tuple[ConfidenceReason, ...]]:
    reasons: list[ConfidenceReason] = []
    total = 0.0
    for active, key, factor in (
        (oracle, "confidence.weight.oracle_fired", "oracle_fired"),
        (path, "confidence.weight.path_exists", "path_exists"),
        (unique, "confidence.weight.unique_link", "unique_link"),
        (ambiguous, "confidence.weight.ambiguous_penalty", "ambiguous_link"),
    ):
        if active:
            delta = _weight(config, key)
            reasons.append(ConfidenceReason(factor, delta))
            total += delta
    return _clamp(total), tuple(reasons)


def _with_family(
    probes: list[Finding],
    config: Mapping[str, Any] | None,
    confidence: float,
    reasons: tuple[ConfidenceReason, ...],
) -> tuple[float, tuple[ConfidenceReason, ...]]:
    if not any(probe.payload for probe in probes):
        return confidence, reasons
    delta = _weight(config, "confidence.weight.family_match")
    return _clamp(confidence + delta), (*reasons, ConfidenceReason("family_match", delta))


def _clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 3)


def _risk(severity: str, confidence: float | None) -> float:
    base = _SEVERITY_SCORE.get(severity.casefold(), 10)
    return float(min(100, base + round((confidence or 0.0) * 10)))


def _max_severity(findings: list[Finding]) -> str:
    return max(
        (finding.severity or "unknown" for finding in findings),
        key=lambda value: SEVERITY_ORDER.get(value.casefold(), 1),
        default="unknown",
    )


def _sink_key(finding: Finding) -> str:
    return _digest(dedupe_key(finding))


def _runtime_key(finding: Finding) -> str:
    return _digest(("runtime", finding.cwe, finding.route, finding.method, finding.param))


def _digest(identity: tuple[object, ...]) -> str:
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def _issue_sort_key(issue: Issue) -> tuple[int, float, str]:
    label_order = {"Confirmed": 0, "Code-only": 1, "Runtime-only": 2}
    return label_order[issue.label], -(issue.risk_score or 0.0), issue.issue_key
