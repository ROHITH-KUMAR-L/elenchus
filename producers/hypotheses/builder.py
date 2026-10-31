"""Stage 3: hypotheses. One record type for the directed and sweep sets."""

from __future__ import annotations

from collections.abc import Iterable

from common.pipeline import CodeIndex, Hypothesis
from common.record import CallHop, Finding, RouteParam

# Java types that cannot carry a payload past Spring's binding. The sweep skips
# them. Directed hypotheses never do: a probe still confirms the rejection.
UNINJECTABLE_TYPES = {
    "int", "Integer", "long", "Long", "short", "Short", "byte", "Byte", "double", "Double",
    "float", "Float", "boolean", "Boolean", "BigDecimal", "BigInteger", "UUID",
}
# The sweep covers these locations. Header and cookie params stay with directed.
SWEEP_LOCATIONS = {"query", "path", "body"}


def build_directed(findings: Iterable[Finding], index: CodeIndex) -> list[Hypothesis]:
    """One directed hypothesis per entry path of each dynamic sink."""
    params_by_route = {(r.route, r.method): tuple(p.name for p in r.params) for r in index.routes}
    hypotheses = []
    for finding in findings:
        if finding.arg_shape != "dynamic" or not finding.entry_paths or finding.sink_id is None:
            continue
        for path in finding.entry_paths:
            hypotheses.append(
                Hypothesis(
                    kind="directed",
                    route=path.route,
                    method=path.method,
                    cwe=finding.cwe,
                    candidate_params=params_by_route.get((path.route, path.method), ()),
                    sink_id=finding.sink_id,
                    call_path=tuple(CallHop(h.method, h.file, h.line) for h in path.call_chain),
                )
            )
    return sorted(hypotheses, key=lambda h: h.hypothesis_id)


def is_sweepable(param: RouteParam, enum_types: frozenset[str]) -> bool:
    if param.source not in SWEEP_LOCATIONS:
        return False
    return param.java_type not in UNINJECTABLE_TYPES and param.java_type not in enum_types


def build_sweep(index: CodeIndex, classes: Iterable[int]) -> list[Hypothesis]:
    """Every injectable param by every supported class, for bugs static analysis missed."""
    cwes = tuple(classes)
    hypotheses = [
        Hypothesis(kind="sweep", route=r.route, method=r.method, cwe=cwe, candidate_params=(p.name,))
        for r in index.routes
        for p in r.params
        if is_sweepable(p, index.enum_types)
        for cwe in cwes
    ]
    return sorted(hypotheses, key=lambda h: h.hypothesis_id)


def skipped_by_type(index: CodeIndex) -> list[tuple[str, str, str]]:
    """(route, method, param) the sweep skipped. Listed in the coverage report."""
    return [
        (r.route, r.method, p.name)
        for r in index.routes
        for p in r.params
        if p.source in SWEEP_LOCATIONS and not is_sweepable(p, index.enum_types)
    ]
