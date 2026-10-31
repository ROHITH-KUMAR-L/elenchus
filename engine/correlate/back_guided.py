"""Back-guided search (Should, off until measured).

For a Runtime-only hit (an oracle fired, but no directed hypothesis and no linked
sink), walk forward from the route handler through the call graph and collect call
sites whose name matches a catalogue method for the hit's CWE, including calls
whose receiver type never resolved. This is relaxed matching, so it runs only
behind backguided.enabled and only in relaxed mode.

One candidate sink is a unique back_guided link with low confidence, confirmed
only at or above backguided.min_confidence_to_confirm. Several candidates stay
Runtime-only, ambiguous, with the sinks listed in candidate_sinks as hints. It is
never run on header, cookie or info-leak findings.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping
from typing import Any

from common.config import DEFAULTS
from common.pipeline import CodeIndex
from common.record import ConfidenceReason, SinkId
from engine.correlate.models import Issue
from producers.sast.sink_finder import Catalogue


def _methods_for_cwe(catalogue: Catalogue, cwe: int) -> set[str]:
    return {name for entry in catalogue.entries if entry.cwe == cwe for name in entry.methods}


def _handlers_for_route(index: CodeIndex, route: str, method: str) -> set[str]:
    return {
        entry.func
        for entry in index.routes
        if entry.route == route and entry.method == (method or entry.method)
    }


def candidate_sinks(
    index: CodeIndex, catalogue: Catalogue, route: str, method: str, cwe: int, max_hops: int
) -> list[tuple[SinkId, int]]:
    """(sink, unresolved hop count) for each relaxed sink reachable from the route,
    within max_hops unresolved hops. Deduplicated by sink identity."""
    names = _methods_for_cwe(catalogue, cwe)
    if not names:
        return []
    by_caller: dict[str, list[Any]] = defaultdict(list)
    for edge in index.call_graph:
        by_caller[edge.caller].append(edge)

    found: dict[tuple[str, str, int, int], tuple[SinkId, int]] = {}
    for handler in _handlers_for_route(index, route, method):
        queue: deque[tuple[str, int]] = deque([(handler, 0)])
        seen = {handler}
        while queue:
            current, hops = queue.popleft()
            for edge in by_caller.get(current, ()):
                callee_simple = edge.callee.rsplit(".", 1)[-1]
                if callee_simple in names and not edge.resolved:
                    sink = SinkId(edge.file, current, edge.line, edge.col)
                    found[(edge.file, current, edge.line, edge.col)] = (sink, hops + 1)
                next_hops = hops + (0 if edge.resolved else 1)
                if next_hops <= max_hops and edge.callee not in seen:
                    seen.add(edge.callee)
                    queue.append((edge.callee, next_hops))
    return list(found.values())


def apply_back_guided(
    issues: list[Issue], index: CodeIndex, catalogue: Catalogue, config: Mapping[str, Any]
) -> list[Issue]:
    """Augment Runtime-only issues with relaxed back-guided candidate sinks."""
    max_hops = int(config.get("backguided.max_unresolved_hops", DEFAULTS["backguided.max_unresolved_hops"]))
    start = float(config.get("backguided.start_confidence", DEFAULTS["backguided.start_confidence"]))
    penalty = float(config.get("backguided.hop_penalty", DEFAULTS["backguided.hop_penalty"]))
    confirm = float(config.get("backguided.min_confidence_to_confirm", DEFAULTS["backguided.min_confidence_to_confirm"]))

    out: list[Issue] = []
    for issue in issues:
        if issue.label != "Runtime-only" or issue.route is None:
            out.append(issue)
            continue
        candidates = candidate_sinks(index, catalogue, issue.route, issue.method or "", issue.cwe, max_hops)
        if not candidates:
            out.append(issue)
            continue
        if len(candidates) == 1:
            sink, hops = candidates[0]
            confidence = round(max(0.0, start - penalty * hops), 3)
            confirmed = confidence >= confirm
            out.append(
                _replace_issue(
                    issue,
                    label="Confirmed" if confirmed else "Runtime-only",
                    link_status="unique",
                    link_origin="back_guided",
                    confidence=confidence,
                    confidence_reasons=(ConfidenceReason("back_guided_relaxed", confidence),),
                    sink=sink if confirmed else None,
                    candidate_sinks=() if confirmed else (sink,),
                    match_mode="relaxed",
                    unresolved_hops=hops,
                    link_reason="Back-guided relaxed search found one candidate sink.",
                )
            )
        else:
            out.append(
                _replace_issue(
                    issue,
                    link_status="ambiguous",
                    link_origin="back_guided",
                    candidate_sinks=tuple(sink for sink, _ in candidates),
                    match_mode="relaxed",
                    link_reason="Back-guided relaxed search found several candidate sinks.",
                )
            )
    return out


def _replace_issue(issue: Issue, **changes: Any) -> Issue:
    from dataclasses import replace

    fields = {k: v for k, v in changes.items() if hasattr(issue, k)}
    return replace(issue, **fields)
