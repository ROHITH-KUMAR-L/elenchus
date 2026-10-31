"""Canonical finding-record contract shared by producers and engine.

This file is the source of truth for the record shape. docs/finding-schema.md
describes it. Changes are stop-the-world contract changes (CONTRIBUTING.md).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from typing import Any

FINDING_SOURCES = {"sast", "dast"}
PROVENANCES = {"own", "semgrep", "llm", "zap"}
ISSUE_LABELS = {"Confirmed", "Code-only", "Runtime-only"}
TRACE_ROLES = {"source", "step", "sink"}
EVIDENCE_TYPES = {"PATH", "ORACLE", "TRACE", "RESPONSE_TRACE", "FAMILY", "ADEQUACY"}
ARG_SHAPES = {"constant", "sanitised", "dynamic"}
LINK_STATUSES = {"unique", "ambiguous"}
LINK_ORIGINS = {"directed", "sweep", "back_guided"}
MATCH_MODES = {"strict", "relaxed"}
PARAM_LOCATIONS = {"query", "path", "header", "cookie", "body"}
STATUSES = {"safe_pattern", "no_http_path", "blocked", "tested_negative", "untested"}
SUPPRESSIBLE_STATUSES = {"safe_pattern", "tested_negative", "no_http_path"}
HEADER_COUNT_MODES = {"per_app", "per_url"}

_REQUIRED_FIELDS = {"run_id", "source", "provenance", "cwe", "type", "evidence"}
_OPTIONAL_FIELDS = {
    "corroborated",
    "route",
    "method",
    "file",
    "line",
    "sink_id",
    "arg_shape",
    "entry_paths",
    "hypothesis_id",
    "candidate_params",
    "param",
    "param_location",
    "param_path",
    "payload",
    "taint_trace",
    "link_status",
    "link_origin",
    "ambiguity_group_id",
    "alternatives",
    "candidate_sinks",
    "match_mode",
    "unresolved_hops",
    "conflict",
    "status",
    "suppressed",
    "unlinked_reason",
    "injected_route",
    "observed_route",
    "source_rev",
    "severity",
    "wasc_id",
    "label",
    "confidence",
    "confidence_reasons",
    "risk_score",
}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS


def _optional_string(name: str, value: Any, allow_empty: bool = False) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or (value == "" and not allow_empty):
        raise ValueError(f"{name} must be a non-empty string or null")
    return value


def _positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _optional_choice(name: str, value: Any, choices: set[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{name} must be one of {', '.join(sorted(choices))}, or null")
    return value


def _optional_number(name: str, value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number or null")
    return float(value)


@dataclass(frozen=True)
class TraceStep:
    file: str
    line: int
    role: str

    @classmethod
    def from_value(cls, value: Any, index: int) -> TraceStep:
        if not isinstance(value, dict):
            raise ValueError(f"taint_trace[{index}] must be an object")
        if set(value) != {"file", "line", "role"}:
            raise ValueError(
                f"taint_trace[{index}] must contain exactly file, line, and role"
            )
        file = value["file"]
        line = value["line"]
        role = value["role"]
        if not isinstance(file, str) or not file:
            raise ValueError(f"taint_trace[{index}].file must be a non-empty string")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError(f"taint_trace[{index}].line must be a positive integer")
        if not isinstance(role, str) or role not in TRACE_ROLES:
            raise ValueError(f"taint_trace[{index}].role must be source, step, or sink")
        return cls(file=file, line=line, role=role)

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "role": self.role}


@dataclass(frozen=True)
class SinkId:
    """Identity of one sink site. Hashable, so it can sit in a dedupe key."""

    file: str
    enclosing_method: str
    start_line: int
    start_col: int

    @classmethod
    def from_value(cls, value: Any, name: str = "sink_id") -> SinkId:
        expected = {"file", "enclosing_method", "start_line", "start_col"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError(f"{name} must contain {', '.join(sorted(expected))}")
        file = value["file"]
        method = value["enclosing_method"]
        if not isinstance(file, str) or not file:
            raise ValueError(f"{name}.file must be a non-empty string")
        if not isinstance(method, str) or not method:
            raise ValueError(f"{name}.enclosing_method must be a non-empty string")
        line = _positive_int(f"{name}.start_line", value["start_line"])
        col = value["start_col"]
        if isinstance(col, bool) or not isinstance(col, int) or col < 0:
            raise ValueError(f"{name}.start_col must be a non-negative integer")
        return cls(normalize_file(file) or file, method, line, col)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "enclosing_method": self.enclosing_method,
            "start_line": self.start_line,
            "start_col": self.start_col,
        }


@dataclass(frozen=True)
class CallHop:
    method: str
    file: str | None  # Null when the receiver type did not resolve.
    line: int

    @classmethod
    def from_value(cls, value: Any, name: str) -> CallHop:
        if not isinstance(value, dict) or set(value) != {"method", "file", "line"}:
            raise ValueError(f"{name} must contain exactly method, file, and line")
        method = value["method"]
        if not isinstance(method, str) or not method:
            raise ValueError(f"{name}.method must be a non-empty string")
        return cls(
            method,
            _optional_string(f"{name}.file", value["file"]),
            _positive_int(f"{name}.line", value["line"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "file": self.file, "line": self.line}


@dataclass(frozen=True)
class EntryPath:
    """A route that reaches a sink. The handler is the first hop of call_chain."""

    route: str
    method: str
    hops: int
    call_chain: tuple[CallHop, ...]

    @classmethod
    def from_value(cls, value: Any, index: int) -> EntryPath:
        name = f"entry_paths[{index}]"
        if not isinstance(value, dict) or set(value) != {"route", "method", "hops", "call_chain"}:
            raise ValueError(f"{name} must contain exactly route, method, hops, and call_chain")
        route = value["route"]
        method = value["method"]
        hops = value["hops"]
        chain = value["call_chain"]
        if not isinstance(route, str) or not route:
            raise ValueError(f"{name}.route must be a non-empty string")
        if not isinstance(method, str) or not method:
            raise ValueError(f"{name}.method must be a non-empty string")
        if isinstance(hops, bool) or not isinstance(hops, int) or hops < 0:
            raise ValueError(f"{name}.hops must be a non-negative integer")
        if not isinstance(chain, list) or not chain:
            raise ValueError(f"{name}.call_chain must be a non-empty array")
        return cls(
            route,
            method.upper(),
            hops,
            tuple(
                CallHop.from_value(hop, f"{name}.call_chain[{position}]")
                for position, hop in enumerate(chain)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "method": self.method,
            "hops": self.hops,
            "call_chain": [hop.to_dict() for hop in self.call_chain],
        }


@dataclass(frozen=True)
class EvidenceEntry:
    type: str
    detail: dict[str, Any]

    @classmethod
    def from_value(cls, value: Any, index: int) -> EvidenceEntry:
        if not isinstance(value, dict) or set(value) != {"type", "detail"}:
            raise ValueError(f"evidence[{index}] must contain exactly type and detail")
        if value["type"] not in EVIDENCE_TYPES:
            raise ValueError(
                f"evidence[{index}].type must be one of {', '.join(sorted(EVIDENCE_TYPES))}"
            )
        if not isinstance(value["detail"], dict):
            raise ValueError(f"evidence[{index}].detail must be an object")
        return cls(value["type"], value["detail"])

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "detail": self.detail}


@dataclass(frozen=True)
class ConfidenceReason:
    factor: str
    delta: float

    @classmethod
    def from_value(cls, value: Any, index: int) -> ConfidenceReason:
        if not isinstance(value, dict) or set(value) != {"factor", "delta"}:
            raise ValueError(f"confidence_reasons[{index}] must contain exactly factor and delta")
        factor = value["factor"]
        if not isinstance(factor, str) or not factor:
            raise ValueError(f"confidence_reasons[{index}].factor must be a non-empty string")
        delta = _optional_number(f"confidence_reasons[{index}].delta", value["delta"])
        if delta is None:
            raise ValueError(f"confidence_reasons[{index}].delta must be a number")
        return cls(factor, delta)

    def to_dict(self) -> dict[str, Any]:
        return {"factor": self.factor, "delta": self.delta}


def _optional_sinks(name: str, value: Any) -> tuple[SinkId, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array or null")
    return tuple(SinkId.from_value(item, f"{name}[{i}]") for i, item in enumerate(value))


def _optional_tuple_dicts(items: tuple[Any, ...] | None) -> list[dict[str, Any]] | None:
    return [item.to_dict() for item in items] if items is not None else None


@dataclass(frozen=True)
class Finding:
    """The internal finding record. docs/finding-schema.md describes each field."""

    run_id: str
    source: str
    provenance: str
    cwe: int
    type: str
    evidence: tuple[EvidenceEntry, ...]
    corroborated: bool | None = None
    route: str | None = None
    method: str | None = None
    file: str | None = None
    line: int | None = None
    sink_id: SinkId | None = None
    arg_shape: str | None = None
    entry_paths: tuple[EntryPath, ...] | None = None
    hypothesis_id: str | None = None
    candidate_params: tuple[str, ...] | None = None
    param: str | None = None
    param_location: str | None = None
    param_path: str | None = None
    payload: str | None = None
    taint_trace: tuple[TraceStep, ...] | None = None
    link_status: str | None = None
    link_origin: str | None = None
    ambiguity_group_id: str | None = None
    alternatives: tuple[SinkId, ...] | None = None
    candidate_sinks: tuple[SinkId, ...] | None = None
    match_mode: str | None = None
    unresolved_hops: int | None = None
    conflict: bool = False
    status: str | None = None
    suppressed: bool = False
    unlinked_reason: str | None = None
    injected_route: str | None = None
    observed_route: str | None = None
    source_rev: str | None = None
    severity: str | None = None
    wasc_id: int | None = None
    label: str | None = None
    confidence: float | None = None
    confidence_reasons: tuple[ConfidenceReason, ...] | None = field(default=None)
    risk_score: float | None = None

    @classmethod
    def from_dict(cls, value: Any) -> Finding:
        if not isinstance(value, dict):
            raise ValueError("each finding must be a JSON object")
        missing = _REQUIRED_FIELDS - value.keys()
        unknown = value.keys() - _ALLOWED_FIELDS
        if missing:
            raise ValueError(f"finding is missing required fields: {', '.join(sorted(missing))}")
        if unknown:
            raise ValueError(f"finding has unsupported fields: {', '.join(sorted(unknown))}")

        get = value.get
        run_id = value["run_id"]
        source = value["source"]
        provenance = value["provenance"]
        cwe = value["cwe"]
        finding_type = value["type"]
        evidence = value["evidence"]
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if not isinstance(source, str) or source not in FINDING_SOURCES:
            raise ValueError("source must be 'sast' or 'dast'")
        if not isinstance(provenance, str) or provenance not in PROVENANCES:
            raise ValueError(f"provenance must be one of {', '.join(sorted(PROVENANCES))}")
        _positive_int("cwe", cwe)
        if not isinstance(finding_type, str) or not finding_type:
            raise ValueError("type must be a non-empty string")
        if not isinstance(evidence, list):
            raise ValueError("evidence must be an array")

        method = _optional_string("method", get("method"))
        line = get("line")
        if line is not None:
            _positive_int("line", line)
        param = _optional_string("param", get("param"), allow_empty=True)
        if source == "sast" and param is not None:
            # The static stage never claims a param. The oracle resolves it.
            raise ValueError("a sast finding must not set param; use candidate_params")

        entry_paths = get("entry_paths")
        if entry_paths is not None:
            if not isinstance(entry_paths, list):
                raise ValueError("entry_paths must be an array or null")
            entry_paths = tuple(EntryPath.from_value(p, i) for i, p in enumerate(entry_paths))
        candidate_params = get("candidate_params")
        if candidate_params is not None:
            if not isinstance(candidate_params, list) or not all(
                isinstance(name, str) and name for name in candidate_params
            ):
                raise ValueError("candidate_params must be an array of strings or null")
            candidate_params = tuple(candidate_params)
        taint_trace = get("taint_trace")
        if taint_trace is not None:
            if not isinstance(taint_trace, list):
                raise ValueError("taint_trace must be an array or null")
            taint_trace = tuple(TraceStep.from_value(s, i) for i, s in enumerate(taint_trace))
        sink_id = get("sink_id")
        if sink_id is not None:
            sink_id = SinkId.from_value(sink_id)

        link_status = _optional_choice("link_status", get("link_status"), LINK_STATUSES)
        link_origin = _optional_choice("link_origin", get("link_origin"), LINK_ORIGINS)
        if (link_status is None) != (link_origin is None):
            raise ValueError("link_status and link_origin must both be set or both be null")

        unresolved_hops = get("unresolved_hops")
        if unresolved_hops is not None and (
            isinstance(unresolved_hops, bool)
            or not isinstance(unresolved_hops, int)
            or unresolved_hops < 0
        ):
            raise ValueError("unresolved_hops must be a non-negative integer or null")
        conflict = get("conflict", False)
        suppressed = get("suppressed", False)
        if not isinstance(conflict, bool):
            raise ValueError("conflict must be a boolean")
        if not isinstance(suppressed, bool):
            raise ValueError("suppressed must be a boolean")
        status = _optional_choice("status", get("status"), STATUSES)
        if suppressed and status not in SUPPRESSIBLE_STATUSES:
            raise ValueError(
                f"suppressed requires status {', '.join(sorted(SUPPRESSIBLE_STATUSES))}"
            )
        corroborated = get("corroborated")
        if corroborated is not None and not isinstance(corroborated, bool):
            raise ValueError("corroborated must be a boolean or null")

        wasc_id = get("wasc_id")
        if wasc_id is not None and (
            isinstance(wasc_id, bool) or not isinstance(wasc_id, int) or wasc_id < 0
        ):
            raise ValueError("wasc_id must be a non-negative integer or null")
        confidence = _optional_number("confidence", get("confidence"))
        if confidence is not None and not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        reasons = get("confidence_reasons")
        if reasons is not None:
            if not isinstance(reasons, list):
                raise ValueError("confidence_reasons must be an array or null")
            reasons = tuple(ConfidenceReason.from_value(r, i) for i, r in enumerate(reasons))

        return cls(
            run_id=run_id,
            source=source,
            provenance=provenance,
            cwe=cwe,
            type=finding_type,
            evidence=tuple(EvidenceEntry.from_value(e, i) for i, e in enumerate(evidence)),
            corroborated=corroborated,
            route=_optional_string("route", get("route")),
            method=method.upper() if method is not None else None,
            file=_optional_string("file", get("file")),
            line=line,
            sink_id=sink_id,
            arg_shape=_optional_choice("arg_shape", get("arg_shape"), ARG_SHAPES),
            entry_paths=entry_paths,
            hypothesis_id=_optional_string("hypothesis_id", get("hypothesis_id")),
            candidate_params=candidate_params,
            param=param,
            param_location=_optional_choice(
                "param_location", get("param_location"), PARAM_LOCATIONS
            ),
            param_path=_optional_string("param_path", get("param_path")),
            payload=_optional_string("payload", get("payload"), allow_empty=True),
            taint_trace=taint_trace,
            link_status=link_status,
            link_origin=link_origin,
            ambiguity_group_id=_optional_string("ambiguity_group_id", get("ambiguity_group_id")),
            alternatives=_optional_sinks("alternatives", get("alternatives")),
            candidate_sinks=_optional_sinks("candidate_sinks", get("candidate_sinks")),
            match_mode=_optional_choice("match_mode", get("match_mode"), MATCH_MODES),
            unresolved_hops=unresolved_hops,
            conflict=conflict,
            status=status,
            suppressed=suppressed,
            unlinked_reason=_optional_string("unlinked_reason", get("unlinked_reason")),
            injected_route=_optional_string("injected_route", get("injected_route")),
            observed_route=_optional_string("observed_route", get("observed_route")),
            source_rev=_optional_string("source_rev", get("source_rev")),
            severity=_optional_string("severity", get("severity")),
            wasc_id=wasc_id,
            label=_optional_choice("label", get("label"), ISSUE_LABELS),
            confidence=confidence,
            confidence_reasons=reasons,
            risk_score=_optional_number("risk_score", get("risk_score")),
        )

    def with_run_id(self, run_id: str) -> Finding:
        if not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        return replace(self, run_id=run_id)

    def detail(self, key: str) -> Any:
        """First value of key across evidence details, or None."""
        for entry in self.evidence:
            if key in entry.detail:
                return entry.detail[key]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "source": self.source,
            "provenance": self.provenance,
            "corroborated": self.corroborated,
            "cwe": self.cwe,
            "type": self.type,
            "route": self.route,
            "method": self.method,
            "file": self.file,
            "line": self.line,
            "sink_id": self.sink_id.to_dict() if self.sink_id is not None else None,
            "arg_shape": self.arg_shape,
            "entry_paths": _optional_tuple_dicts(self.entry_paths),
            "hypothesis_id": self.hypothesis_id,
            "candidate_params": (
                list(self.candidate_params) if self.candidate_params is not None else None
            ),
            "param": self.param,
            "param_location": self.param_location,
            "param_path": self.param_path,
            "payload": self.payload,
            "evidence": [entry.to_dict() for entry in self.evidence],
            "taint_trace": _optional_tuple_dicts(self.taint_trace),
            "link_status": self.link_status,
            "link_origin": self.link_origin,
            "ambiguity_group_id": self.ambiguity_group_id,
            "alternatives": _optional_tuple_dicts(self.alternatives),
            "candidate_sinks": _optional_tuple_dicts(self.candidate_sinks),
            "match_mode": self.match_mode,
            "unresolved_hops": self.unresolved_hops,
            "conflict": self.conflict,
            "status": self.status,
            "suppressed": self.suppressed,
            "unlinked_reason": self.unlinked_reason,
            "injected_route": self.injected_route,
            "observed_route": self.observed_route,
            "source_rev": self.source_rev,
            "severity": self.severity,
            "wasc_id": self.wasc_id,
            "label": self.label,
            "confidence": self.confidence,
            "confidence_reasons": _optional_tuple_dicts(self.confidence_reasons),
            "risk_score": self.risk_score,
        }


# --- Scan input -----------------------------------------------------------

LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class ScanTarget:
    """Immutable input config for one run (D-16). Built once by the CLI."""

    source_path: str
    base_url: str
    run_id: str
    framework: str

    def __post_init__(self) -> None:
        from urllib.parse import urlsplit

        if not self.run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("http", "https") or parts.hostname not in LOCALHOST_NAMES:
            # Scanning anything but the local test app is disqualification.
            raise ValueError("base_url must be an http(s) URL on localhost")

    @property
    def base_path(self) -> str:
        """Path prefix of base_url, e.g. a servlet context path like /VulnerableApp."""
        from urllib.parse import urlsplit

        return urlsplit(self.base_url).path.rstrip("/")


# --- Route map --------------------------------------------------------------


@dataclass(frozen=True)
class RouteParam:
    name: str  # A nested body field is dotted, e.g. "address.city".
    source: str  # A location from PARAM_LOCATIONS.
    java_type: str | None = None
    body_format: str | None = None  # "json" or "form". Null unless source is "body".


@dataclass(frozen=True)
class CallEdge:
    """A project method a handler reaches (feeds reached_via, D-07)."""

    type_name: str
    method: str
    file: str
    line_start: int
    line_end: int


@dataclass(frozen=True)
class RouteEntry:
    route: str
    method: str
    file: str
    func: str
    line_start: int
    line_end: int
    params: tuple[RouteParam, ...]
    calls: tuple[CallEdge, ...]
    route_origin: str = "source"  # "source" or "discovered"
    params_status: str = "unknown"  # "complete", "partial" or "unknown"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RouteEntry:
        return cls(
            route=value["route"],
            method=value["method"],
            file=value["file"],
            func=value["func"],
            line_start=value["line_start"],
            line_end=value["line_end"],
            params=tuple(
                RouteParam(p["name"], p["source"], p.get("java_type"), p.get("body_format"))
                for p in value["params"]
            ),
            calls=tuple(
                CallEdge(c["class"], c["method"], c["file"], c["line_start"], c["line_end"])
                for c in value["calls"]
            ),
            route_origin=value.get("route_origin", "source"),
            params_status=value.get("params_status", "unknown"),
        )


RouteMap = tuple[RouteEntry, ...]


def normalise_route(url: str, route_map: RouteMap, base_path: str = "") -> str | None:
    """Template for a concrete URL, e.g. /orders/5 -> /orders/{id}.

    base_path (ScanTarget.base_path) is stripped first. Returns None when no
    route matches. When several templates match, the one with the most literal
    segments wins, as in Spring.
    """
    from urllib.parse import unquote, urlsplit

    path = urlsplit(url).path
    if base_path and (path == base_path or path.startswith(base_path + "/")):
        path = path[len(base_path):]
    segments = [unquote(s) for s in path.split("/") if s]
    best: tuple[int, str] | None = None
    for entry in route_map:
        template = [s for s in entry.route.split("/") if s]
        if len(template) != len(segments):
            continue
        literals = 0
        for expected, actual in zip(template, segments):
            if (expected.startswith("{") and expected.endswith("}")) or expected == "*":
                continue
            if expected != actual:
                break
            literals += 1
        else:
            if best is None or literals > best[0]:
                best = (literals, entry.route)
    return best[1] if best else None


# --- Identity keys -----------------------------------------------------------


def normalize_file(file: str | None) -> str | None:
    if file is None:
        return None
    normalized = file.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def dedupe_key(finding: Finding, header_count_mode: str = "per_app") -> tuple[object, ...]:
    """Identity of one finding: (sink_id, cwe), else the fallback keys.

    Fallbacks, from docs/finding-schema.md: header findings by header_count_mode,
    secrets by (cwe, file, line), runtime-only injection by route and param.
    """
    header = _header_key(finding, header_count_mode)
    if header is not None:
        return header
    if finding.sink_id is not None:
        sink = finding.sink_id
        return "sink", finding.cwe, sink.file, sink.enclosing_method, sink.start_line, sink.start_col
    if finding.file is not None and finding.line is not None:
        return "code", finding.cwe, normalize_file(finding.file), finding.line
    return route_key(finding, header_count_mode)


def route_key(finding: Finding, header_count_mode: str = "per_app") -> tuple[object, ...]:
    """Route identity, used to merge a newly linked pair into a stored
    Runtime-only issue."""
    header = _header_key(finding, header_count_mode)
    if header is not None:
        return header
    return "route", finding.cwe, finding.route, finding.method, finding.param


def _header_key(finding: Finding, header_count_mode: str) -> tuple[object, ...] | None:
    if header_count_mode not in HEADER_COUNT_MODES:
        raise ValueError(f"header_count_mode must be one of {', '.join(sorted(HEADER_COUNT_MODES))}")
    header_name = finding.detail("header_name")
    if not isinstance(header_name, str) or not header_name:
        return None
    if header_count_mode == "per_url":
        return "header", finding.cwe, header_name.casefold(), finding.route
    return "header", finding.cwe, header_name.casefold()
