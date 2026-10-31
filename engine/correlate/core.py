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
import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

from common.config import DEFAULTS
from common.pipeline import hypothesis_id
from common.record import ConfidenceReason, Finding, dedupe_key, normalize_file
from engine.correlate.models import SEVERITY_ORDER, Issue

_SEVERITY_SCORE = {
    "critical": 90, "high": 75, "medium": 50, "moderate": 50, "low": 25, "info": 10,
    "informational": 10, "unknown": 10,
}
_CODE_ONLY_STATUSES = {"no_http_path", "blocked", "untested", "safe_pattern", "tested_negative"}
_LOGGER = logging.getLogger(__name__)


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
    probe_groups: dict[
        tuple[str | None, str | None, str | None, int], list[Finding]
    ] = defaultdict(list)
    for probe in probes:
        probe_groups[(probe.route, probe.method, probe.param, probe.cwe)].append(probe)

    linked: dict[str, tuple[list[Finding], list[int]]] = {}
    conflict_links: dict[str, tuple[list[Finding], list[int]]] = {}
    constant_conflicts: dict[str, tuple[list[Finding], list[int]]] = {}
    runtime: list[list[Finding]] = []
    for key, group in sorted(probe_groups.items(), key=lambda item: str(item[0])):
        route, method, param, cwe = key
        lineage = _lineage_ids(group)
        origin = _link_origin(group)
        candidates = _candidate_sinks(
            static,
            route,
            method,
            param,
            cwe,
            lineage,
            origin,
        )
        if any(probe.detail("oracle_flaky") is True for probe in group):
            runtime.append(group)
            continue
        if not candidates:
            runtime.append(group)
            continue
        conflict_sinks = [
            index
            for index in candidates
            if _is_conflict_sink(static[index])
        ]
        if conflict_sinks:
            constant_sinks = [
                index
                for index in conflict_sinks
                if static[index].status == "safe_pattern"
                and static[index].arg_shape == "constant"
            ]
            if constant_sinks:
                identity = _runtime_key(group[0])
                probes_acc, sinks_acc = constant_conflicts.setdefault(
                    identity, ([], [])
                )
                probes_acc.extend(group)
                sinks_acc.extend(index for index in constant_sinks if index not in sinks_acc)
                continue
            linked_static.update(candidates)
            identity = _sink_key(
                min((static[index] for index in candidates), key=_primary_rank)
            )
            probes_acc, sinks_acc = conflict_links.setdefault(identity, ([], []))
            probes_acc.extend(group)
            sinks_acc.extend(index for index in candidates if index not in sinks_acc)
            continue
        linked_static.update(candidates)
        identity = _sink_key(
            min((static[index] for index in candidates), key=_primary_rank)
        )
        probes_acc, sinks_acc = linked.setdefault(identity, ([], []))
        probes_acc.extend(group)
        for index in candidates:
            if index not in sinks_acc:
                sinks_acc.append(index)

    for probes_acc, sinks_acc in linked.values():
        issues.append(_linked_issue(probes_acc, [static[i] for i in sinks_acc], config))
    for probes_acc, sinks_acc in conflict_links.values():
        issues.append(_conflict_issue(probes_acc, [static[i] for i in sinks_acc], config))
    for probes_acc, sinks_acc in constant_conflicts.values():
        issues.append(
            _conflict_issue(
                probes_acc,
                [static[i] for i in sinks_acc],
                config,
                confirmed=False,
                constant=True,
            )
        )
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


def _link_origin(group: list[Finding]) -> str | None:
    if any(probe.detail("job_pass") == "directed" for probe in group):
        return "directed"
    if any(probe.detail("job_pass") == "sweep" for probe in group):
        return "sweep"
    return "directed" if _lineage_ids(group) else None


def _static_hypothesis_ids(finding: Finding) -> set[str]:
    if finding.sink_id is None or not finding.entry_paths:
        return set()
    params = finding.candidate_params or ()
    return {
        hypothesis_id("directed", path.route, path.method, finding.cwe, finding.sink_id, params)
        for path in finding.entry_paths
    }


def _candidate_sinks(
    static: list[Finding],
    route: str | None,
    method: str | None,
    param: str | None,
    cwe: int,
    lineage: set[str],
    origin: str | None,
) -> list[int]:
    """Resolve directed hits only by lineage and sweep hits by route and param."""
    by_route: list[int] = []
    for index, finding in enumerate(static):
        if finding.cwe != cwe or finding.sink_id is None:
            continue
        reaches = any(
            path.route == route and path.method == method
            for path in finding.entry_paths or ()
        )
        if reaches and (param is None or param in (finding.candidate_params or ())):
            by_route.append(index)
    if origin == "directed":
        return [i for i in by_route if _static_hypothesis_ids(static[i]) & lineage]
    return by_route if origin == "sweep" else []


def _linked_issue(
    probes: list[Finding], sinks: list[Finding], config: Mapping[str, Any] | None
) -> Issue:
    probe = probes[0]
    severity = _max_severity(probes + sinks)
    if not sinks:
        oracle_flaky = any(
            probe.detail("oracle_flaky") is True for probe in probes
        )
        confidence, reasons = _confidence(
            config,
            oracle=not oracle_flaky,
            path=False,
            unique=False,
            ambiguous=False,
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
            link_reason=(
                "The candidate did not meet the replay threshold; it remains Runtime-only."
                if oracle_flaky
                else "Oracle fired but no code path was found for this route."
            ),
            oracle_flaky=oracle_flaky,
        )
    ordered_sinks = sorted(sinks, key=_primary_rank)
    trace_primary, catalogue_gap = _response_trace_primary(probes, ordered_sinks)
    trace_resolved = trace_primary is not None
    if trace_primary is not None:
        ordered_sinks = [
            trace_primary,
            *(sink for sink in ordered_sinks if sink is not trace_primary),
        ]
    unique = trace_resolved or len(ordered_sinks) == 1
    primary = ordered_sinks[0]
    origin = _link_origin(probes) or "directed"
    confidence, reasons = _confidence(
        config, oracle=True, path=True, unique=unique, ambiguous=not unique
    )
    confidence, reasons = _with_family(probes, config, confidence, reasons)
    if catalogue_gap:
        delta = _weight(config, "confidence.weight.catalogue_gap_penalty")
        confidence = _clamp(confidence + delta)
        reasons = (*reasons, ConfidenceReason("catalogue_gap", delta))
    return Issue(
        issue_key=_sink_key(primary),
        label="Confirmed",
        cwe=probe.cwe,
        type=probe.type,
        severity=severity,
        risk_score=_risk(severity, confidence),
        link_status="unique" if unique else "ambiguous",
        link_origin=origin,
        confidence=confidence,
        confidence_reasons=reasons,
        route=probe.route,
        method=probe.method,
        param=probe.param,
        sink=primary.sink_id,
        alternatives=tuple(
            s.sink_id for s in ordered_sinks[1:] if s.sink_id is not None
        ),
        file=primary.file,
        line=primary.line,
        link_reason=(
            "RESPONSE_TRACE identified the deepest project frame's unique candidate."
            if trace_resolved
            else (
                "Directed hypothesis fired: the probe's lineage matches this sink."
                if origin == "directed"
                else "Sweep probe matched this sink by its route and parameter."
            )
            if unique
            else f"{origin.capitalize()} probes matched several sinks on this route; link is ambiguous."
        ),
        sast_findings=tuple(ordered_sinks),
        dast_findings=tuple(probes),
    )


def _response_trace_primary(
    probes: list[Finding], sinks: list[Finding]
) -> tuple[Finding | None, bool]:
    catalogue_gap = False
    for probe in probes:
        for evidence in probe.evidence:
            if evidence.type != "RESPONSE_TRACE":
                continue
            frames = evidence.detail.get("frames")
            if not isinstance(frames, list):
                continue
            project_frames = [
                frame
                for frame in frames
                if isinstance(frame, dict) and frame.get("project") is True
            ]
            if not project_frames:
                continue
            deepest = project_frames[0]
            file = deepest.get("file")
            method = deepest.get("method")
            if not isinstance(file, str) or not isinstance(method, str):
                continue
            matching = [
                sink
                for sink in sinks
                if sink.sink_id is not None
                and normalize_file(sink.sink_id.file) == normalize_file(file)
                and (
                    method == sink.sink_id.enclosing_method
                    or method.endswith(f".{sink.sink_id.enclosing_method}")
                )
            ]
            if len(matching) == 1:
                return matching[0], catalogue_gap
            if not matching:
                _LOGGER.warning(
                    "Catalogue gap: RESPONSE_TRACE deepest project frame %s:%s (%s) "
                    "matches no candidate sink",
                    file,
                    deepest.get("line", "?"),
                    method,
                )
                catalogue_gap = True
    return None, catalogue_gap


def _is_conflict_sink(finding: Finding) -> bool:
    return finding.status == "tested_negative" or (
        finding.status == "safe_pattern"
        and finding.arg_shape in {"constant", "sanitised"}
    )


def _conflict_issue(
    probes: list[Finding],
    sinks: list[Finding],
    config: Mapping[str, Any] | None,
    *,
    confirmed: bool | None = None,
    constant: bool = False,
) -> Issue:
    probe = probes[0]
    ordered_sinks = sorted(sinks, key=_primary_rank)
    primary = ordered_sinks[0]
    severity = _max_severity(probes + sinks)
    confidence, reasons = _confidence(
        config, oracle=True, path=not constant, unique=False, ambiguous=not constant
    )
    confidence, reasons = _with_family(probes, config, confidence, reasons)
    threshold = (
        float(config.get("backguided.min_confidence_to_confirm", DEFAULTS["backguided.min_confidence_to_confirm"]))
        if config is not None
        else float(DEFAULTS["backguided.min_confidence_to_confirm"])
    )
    is_confirmed = confidence >= threshold if confirmed is None else confirmed
    cleared_sinks = tuple(
        replace(sink, status=None, suppressed=False, conflict=True)
        if _is_conflict_sink(sink)
        else sink
        for sink in ordered_sinks
    )
    if constant or not is_confirmed:
        return Issue(
            issue_key=_runtime_key(probe),
            label="Runtime-only",
            cwe=probe.cwe,
            type=probe.type,
            severity=severity,
            risk_score=_risk(severity, confidence),
            link_status="ambiguous" if not constant else None,
            link_origin="sweep" if not constant else None,
            confidence=confidence,
            confidence_reasons=reasons,
            route=probe.route,
            method=probe.method,
            param=probe.param,
            status=None,
            conflict=True,
            candidate_sinks=tuple(
                sink.sink_id for sink in ordered_sinks if sink.sink_id is not None
            ),
            link_reason=(
                "A positive replay conflicts with a constant safe-pattern sink; "
                "the sink is a candidate hint and is not linked."
                if constant
                else "A replay reproduced a hit against negative evidence, but "
                "the ambiguity confidence is below the confirmation threshold."
            ),
            sast_findings=tuple(ordered_sinks if constant else cleared_sinks),
            dast_findings=tuple(probes),
        )
    return Issue(
        issue_key=_sink_key(primary),
        label="Confirmed",
        cwe=probe.cwe,
        type=probe.type,
        severity=severity,
        risk_score=_risk(severity, confidence),
        link_status="ambiguous",
        link_origin="sweep",
        confidence=confidence,
        confidence_reasons=reasons,
        route=probe.route,
        method=probe.method,
        param=probe.param,
        sink=primary.sink_id,
        alternatives=tuple(
            sink.sink_id for sink in ordered_sinks[1:] if sink.sink_id is not None
        ),
        file=primary.file,
        line=primary.line,
        conflict=True,
        link_reason="A positive replay reproduced a hit against negative evidence.",
        sast_findings=cleared_sinks,
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
        suppressible_cwes = (
            config.get(
                "export.no_http_path_suppress_cwes",
                DEFAULTS["export.no_http_path_suppress_cwes"],
            )
            if config is not None
            else DEFAULTS["export.no_http_path_suppress_cwes"]
        )
        suppressed = (
            config is not None
            and bool(config.get("export.suppress_no_http_path", False))
            and finding.cwe in suppressible_cwes
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


def _primary_rank(finding: Finding) -> tuple[int, int, int, str, int, int]:
    specificity = {"strict": 0, "relaxed": 1}.get(finding.match_mode or "", 2)
    hops = min((path.hops for path in finding.entry_paths or ()), default=10**9)
    corroboration = 0 if finding.corroborated is True else 1
    sink = finding.sink_id
    return (
        specificity,
        hops,
        corroboration,
        sink.file.casefold() if sink else "",
        sink.start_line if sink else 0,
        sink.start_col if sink else 0,
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
