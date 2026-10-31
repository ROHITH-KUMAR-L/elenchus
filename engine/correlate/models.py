"""Typed consumer-side representations of the finding contract."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


CONFIDENCE_LEVELS = {"A", "B", "C"}
ISSUE_LABELS = {"Confirmed", "Code-only", "Runtime-only"}
FINDING_SOURCES = {"sast", "dast"}
TRACE_ROLES = {"source", "step", "sink"}
SEVERITY_ORDER = {
    "critical": 6,
    "high": 5,
    "medium": 4,
    "moderate": 4,
    "low": 3,
    "info": 2,
    "informational": 2,
    "unknown": 1,
}

_REQUIRED_FIELDS = {
    "run_id",
    "source",
    "cwe",
    "type",
    "route",
    "method",
    "file",
    "line",
    "param",
    "payload",
    "handler_file",
    "handler_line_start",
    "handler_line_end",
    "reached_via",
    "evidence",
    "taint_trace",
    "label",
    "confidence",
    "risk_score",
    "severity",
    "wasc_id",
}
_ALLOWED_FIELDS = _REQUIRED_FIELDS


def _is_optional_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


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
class ReachedVia:
    route: str
    method: str
    handler_file: str
    handler_line_start: int
    handler_line_end: int

    @classmethod
    def from_value(cls, value: Any, index: int) -> ReachedVia:
        expected = {
            "route",
            "method",
            "handler_file",
            "handler_line_start",
            "handler_line_end",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError(
                f"reached_via[{index}] must contain route, method, handler_file, "
                "handler_line_start, and handler_line_end"
            )
        route = value["route"]
        method = value["method"]
        file = value["handler_file"]
        start = value["handler_line_start"]
        end = value["handler_line_end"]
        if not isinstance(route, str) or not route:
            raise ValueError(f"reached_via[{index}].route must be a non-empty string")
        if not isinstance(method, str) or not method:
            raise ValueError(f"reached_via[{index}].method must be a non-empty string")
        if not isinstance(file, str) or not file:
            raise ValueError(
                f"reached_via[{index}].handler_file must be a non-empty string"
            )
        if any(isinstance(line, bool) or not isinstance(line, int) for line in (start, end)):
            raise ValueError(f"reached_via[{index}] line bounds must be integers")
        if start < 1 or end < start:
            raise ValueError(f"reached_via[{index}] must have valid positive line bounds")
        return cls(route, method.upper(), file, start, end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "method": self.method,
            "handler_file": self.handler_file,
            "handler_line_start": self.handler_line_start,
            "handler_line_end": self.handler_line_end,
        }


@dataclass(frozen=True)
class Finding:
    run_id: str
    source: str
    cwe: int
    type: str
    route: str | None
    method: str | None
    file: str | None
    line: int | None
    param: str | None
    payload: str | None
    handler_file: str | None
    handler_line_start: int | None
    handler_line_end: int | None
    reached_via: tuple[ReachedVia, ...] | None
    evidence: dict[str, Any]
    taint_trace: tuple[TraceStep, ...] | None
    label: str | None
    confidence: str | None
    risk_score: float | None
    severity: str | None = None
    wasc_id: int | None = None

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

        run_id = value["run_id"]
        source = value["source"]
        cwe = value["cwe"]
        finding_type = value["type"]
        route = value["route"]
        method = value["method"]
        file = value["file"]
        line = value["line"]
        param = value["param"]
        payload = value["payload"]
        handler_file = value["handler_file"]
        handler_line_start = value["handler_line_start"]
        handler_line_end = value["handler_line_end"]
        reached_via = value["reached_via"]
        evidence = value["evidence"]
        taint_trace = value["taint_trace"]
        label = value["label"]
        confidence = value["confidence"]
        risk_score = value["risk_score"]
        severity = value["severity"]
        wasc_id = value["wasc_id"]

        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if not isinstance(source, str) or source not in FINDING_SOURCES:
            raise ValueError("source must be 'sast' or 'dast'")
        if isinstance(cwe, bool) or not isinstance(cwe, int) or cwe < 1:
            raise ValueError("cwe must be a positive integer")
        if not isinstance(finding_type, str) or not finding_type:
            raise ValueError("type must be a non-empty string")
        if not _is_optional_string(route) or route == "":
            raise ValueError("route must be a non-empty string or null")
        if not _is_optional_string(method) or method == "":
            raise ValueError("method must be a non-empty string or null")
        if not _is_optional_string(file) or file == "":
            raise ValueError("file must be a non-empty string or null")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line < 1
        ):
            raise ValueError("line must be a positive integer or null")
        for field_name, field_value in (("param", param), ("payload", payload)):
            if not _is_optional_string(field_value):
                raise ValueError(f"{field_name} must be a string or null")
        if not _is_optional_string(handler_file) or handler_file == "":
            raise ValueError("handler_file must be a non-empty string or null")
        handler_bounds = (handler_line_start, handler_line_end)
        if any(
            bound is not None and (
                isinstance(bound, bool) or not isinstance(bound, int) or bound < 1
            )
            for bound in handler_bounds
        ):
            raise ValueError("handler line bounds must be positive integers or null")
        if (handler_line_start is None) != (handler_line_end is None):
            raise ValueError("handler line bounds must both be set or both be null")
        if (
            handler_line_start is not None
            and handler_line_end is not None
            and handler_line_end < handler_line_start
        ):
            raise ValueError("handler_line_end must be at least handler_line_start")
        if handler_file is None and handler_line_start is not None:
            raise ValueError("handler_file is required when handler line bounds are set")
        if reached_via is not None:
            if not isinstance(reached_via, list):
                raise ValueError("reached_via must be an array or null")
            reached_via = tuple(
                ReachedVia.from_value(edge, index)
                for index, edge in enumerate(reached_via)
            )
        if not isinstance(evidence, dict):
            raise ValueError("evidence must be an object")
        if taint_trace is not None:
            if not isinstance(taint_trace, list):
                raise ValueError("taint_trace must be an array or null")
            taint_trace = tuple(
                TraceStep.from_value(step, index)
                for index, step in enumerate(taint_trace)
            )
        if label is not None and (
            not isinstance(label, str) or label not in ISSUE_LABELS
        ):
            raise ValueError("label must be Confirmed, Code-only, Runtime-only, or null")
        if confidence is not None and (
            not isinstance(confidence, str) or confidence not in CONFIDENCE_LEVELS
        ):
            raise ValueError("confidence must be A, B, C, or null")
        if risk_score is not None and (
            isinstance(risk_score, bool)
            or not isinstance(risk_score, (int, float))
        ):
            raise ValueError("risk_score must be a number or null")
        if risk_score is not None and not math.isfinite(risk_score):
            raise ValueError("risk_score must be finite")
        if not _is_optional_string(severity) or severity == "":
            raise ValueError("severity must be a string or null")
        if wasc_id is not None and (
            isinstance(wasc_id, bool) or not isinstance(wasc_id, int) or wasc_id < 0
        ):
            raise ValueError("wasc_id must be a non-negative integer or null")

        return cls(
            run_id=run_id,
            source=source,
            cwe=cwe,
            type=finding_type,
            route=route,
            method=method.upper() if method is not None else None,
            file=file,
            line=line,
            param=param,
            payload=payload,
            handler_file=handler_file,
            handler_line_start=handler_line_start,
            handler_line_end=handler_line_end,
            reached_via=reached_via,
            evidence=evidence,
            taint_trace=taint_trace,
            label=label,
            confidence=confidence,
            risk_score=float(risk_score) if risk_score is not None else None,
            severity=severity,
            wasc_id=wasc_id,
        )

    def with_run_id(self, run_id: str) -> Finding:
        from dataclasses import replace

        if not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        return replace(self, run_id=run_id)

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "run_id": self.run_id,
            "source": self.source,
            "cwe": self.cwe,
            "type": self.type,
            "route": self.route,
            "method": self.method,
            "file": self.file,
            "line": self.line,
            "param": self.param,
            "payload": self.payload,
            "handler_file": self.handler_file,
            "handler_line_start": self.handler_line_start,
            "handler_line_end": self.handler_line_end,
            "reached_via": (
                [edge.to_dict() for edge in self.reached_via]
                if self.reached_via is not None
                else None
            ),
            "evidence": self.evidence,
            "taint_trace": (
                [step.to_dict() for step in self.taint_trace]
                if self.taint_trace is not None
                else None
            ),
            "label": self.label,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "wasc_id": self.wasc_id,
        }
        return record


@dataclass(frozen=True)
class FindingCluster:
    representative: Finding
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Issue:
    issue_key: str
    label: str
    confidence: str | None
    risk_score: float
    severity: str
    sast_findings: tuple[Finding, ...]
    dast_findings: tuple[Finding, ...]
    link_reason: str | None

    @property
    def primary_finding(self) -> Finding:
        if self.sast_findings:
            return self.sast_findings[0]
        return self.dast_findings[0]

    @property
    def route_finding(self) -> Finding:
        return next(
            (
                finding
                for finding in self.dast_findings + self.sast_findings
                if finding.route is not None
            ),
            self.primary_finding,
        )

    @property
    def param(self) -> str | None:
        return next(
            (
                finding.param
                for finding in self.dast_findings + self.sast_findings
                if finding.param is not None
            ),
            None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_key": self.issue_key,
            "label": self.label,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "finding": self.primary_finding.to_dict(),
            "sast_findings": [item.to_dict() for item in self.sast_findings],
            "dast_findings": [item.to_dict() for item in self.dast_findings],
            "link_reason": self.link_reason,
        }
