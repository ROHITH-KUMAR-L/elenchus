"""Pipeline objects shared across stages: hypotheses, probe jobs, the code index.

These are not findings. They share the record's freeze rules. Changes are
stop-the-world contract changes (CONTRIBUTING.md). docs/finding-schema.md
describes each shape.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from common.record import CallHop, RouteMap, SinkId

HYPOTHESIS_KINDS = {"directed", "sweep"}
JOB_PASSES = {"directed", "sweep"}
JOB_OUTCOMES = {
    "finished",
    "stopped_at_limit",
    "skipped_budget",
    "skipped_drift",
    "all_blocked",
    "errored",
}
PARAM_OUTCOMES = {"adequate", "type_rejected", "blocked_by_validation"}
BLOCKED_SUB_CODES = {"validation", "auth", "not_found", "server_error", "other"}
SINK_KINDS = {"call", "return_value", "annotation", "template", "xml"}


def hypothesis_id(
    kind: str,
    route: str,
    method: str,
    cwe: int,
    sink_id: SinkId | None,
    candidate_params: tuple[str, ...],
) -> str:
    """Stable id. A sweep unit has no sink, so its one param is part of its identity."""
    sweep_param = candidate_params if kind == "sweep" else ()
    identity = [
        kind,
        route,
        method.upper(),
        cwe,
        sink_id.to_dict() if sink_id is not None else None,
        list(sweep_param),
    ]
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "h-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Hypothesis:
    kind: str
    route: str
    method: str
    cwe: int
    candidate_params: tuple[str, ...]
    sink_id: SinkId | None = None
    call_path: tuple[CallHop, ...] | None = None

    def __post_init__(self) -> None:
        if self.kind not in HYPOTHESIS_KINDS:
            raise ValueError("kind must be directed or sweep")
        if self.kind == "directed" and (self.sink_id is None or self.call_path is None):
            raise ValueError("a directed hypothesis needs sink_id and call_path")
        if self.kind == "sweep":
            if self.sink_id is not None or self.call_path is not None:
                raise ValueError("a sweep hypothesis has no sink_id or call_path")
            if len(self.candidate_params) != 1:
                raise ValueError("a sweep hypothesis has exactly one param")

    @property
    def hypothesis_id(self) -> str:
        return hypothesis_id(
            self.kind, self.route, self.method, self.cwe, self.sink_id, self.candidate_params
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Hypothesis:
        sink = value.get("sink_id")
        path = value.get("call_path")
        return cls(
            kind=value["kind"],
            route=value["route"],
            method=value["method"].upper(),
            cwe=value["cwe"],
            candidate_params=tuple(value["candidate_params"]),
            sink_id=SinkId.from_value(sink) if sink is not None else None,
            call_path=(
                tuple(CallHop.from_value(hop, f"call_path[{i}]") for i, hop in enumerate(path))
                if path is not None
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "kind": self.kind,
            "route": self.route,
            "method": self.method,
            "cwe": self.cwe,
            "candidate_params": list(self.candidate_params),
            "sink_id": self.sink_id.to_dict() if self.sink_id is not None else None,
            "call_path": (
                [hop.to_dict() for hop in self.call_path] if self.call_path is not None else None
            ),
        }


@dataclass(frozen=True)
class ExcludedParam:
    name: str
    sub_code: str

    def __post_init__(self) -> None:
        if self.sub_code not in BLOCKED_SUB_CODES:
            raise ValueError(f"sub_code must be one of {', '.join(sorted(BLOCKED_SUB_CODES))}")


@dataclass(frozen=True)
class SeedRequest:
    """The request ZAP mutates. Attribution diffs each message against it."""

    url: str
    method: str
    body: str = ""
    content_type: str = ""


@dataclass(frozen=True)
class ProbeJob:
    """One ZAP active-scan job. Recorded before the scan starts, so a hit's lineage
    never depends on matching afterwards."""

    job_id: str
    route: str
    method: str
    job_pass: str
    hypothesis_ids: tuple[str, ...]
    cwes: tuple[int, ...]
    seed_request: SeedRequest
    canary: str
    excluded_params: tuple[ExcludedParam, ...] = ()
    scan_id: str | None = None
    outcome: str | None = None
    after_drift: bool = False

    def __post_init__(self) -> None:
        if self.job_pass not in JOB_PASSES:
            raise ValueError("job_pass must be directed or sweep")
        if self.outcome is not None and self.outcome not in JOB_OUTCOMES:
            raise ValueError(f"outcome must be one of {', '.join(sorted(JOB_OUTCOMES))}")
        if not self.cwes:
            raise ValueError("a probe job needs at least one CWE")


@dataclass(frozen=True)
class CallGraphEdge:
    caller: str
    callee: str  # The callee's name as written when the receiver did not resolve.
    file: str
    line: int
    resolved: bool  # True when the receiver type is known, in the source or not.
    callee_file: str | None = None  # Set when the callee's body is in the source.
    col: int = 0
    receiver_type: str | None = None


@dataclass(frozen=True)
class SinkSite:
    sink_id: SinkId
    cwe: int
    kind: str
    arg_shape: str
    catalogue_entry: str
    match_mode: str = "strict"
    line: int = 0  # The dangerous argument's line. sink_id keeps the call site.
    type_name: str = ""
    severity: str = ""
    snippet: str = ""

    def __post_init__(self) -> None:
        if self.kind not in SINK_KINDS:
            raise ValueError(f"kind must be one of {', '.join(sorted(SINK_KINDS))}")


@dataclass(frozen=True)
class SecretSite:
    """A hard-coded secret or weak-crypto site. Code-only, no route, no dataflow."""

    cwe: int
    type_name: str
    severity: str
    file: str
    line: int
    rule: str
    snippet: str = ""


@dataclass(frozen=True)
class CodeIndex:
    """Stage 1 output. Unresolved calls stay in call_graph, flagged, never dropped."""

    routes: RouteMap
    call_graph: tuple[CallGraphEdge, ...] = ()
    sinks: tuple[SinkSite, ...] = ()
    enum_types: frozenset[str] = frozenset()
    secrets: tuple[SecretSite, ...] = ()
