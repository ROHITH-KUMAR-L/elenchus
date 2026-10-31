"""Engine-only types built from canonical findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.record import ConfidenceReason, Finding, SinkId

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


@dataclass(frozen=True)
class Issue:
    """One correlated finding: the SAST and DAST records for a single bug, with
    the label, link fields, confidence and score the report and export read."""

    issue_key: str
    label: str
    cwe: int
    type: str
    severity: str
    risk_score: float | None
    link_status: str | None = None
    link_origin: str | None = None
    confidence: float | None = None
    confidence_reasons: tuple[ConfidenceReason, ...] = ()
    route: str | None = None
    method: str | None = None
    param: str | None = None
    sink: SinkId | None = None
    alternatives: tuple[SinkId, ...] = ()
    file: str | None = None
    line: int | None = None
    status: str | None = None
    suppressed: bool = False
    link_reason: str | None = None
    sast_findings: tuple[Finding, ...] = ()
    dast_findings: tuple[Finding, ...] = ()

    @property
    def primary_finding(self) -> Finding:
        if self.sast_findings:
            return self.sast_findings[0]
        return self.dast_findings[0]

    @property
    def route_finding(self) -> Finding:
        for finding in self.dast_findings + self.sast_findings:
            if finding.route is not None:
                return finding
        return self.primary_finding

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_key": self.issue_key,
            "label": self.label,
            "cwe": self.cwe,
            "type": self.type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "link_status": self.link_status,
            "link_origin": self.link_origin,
            "confidence": self.confidence,
            "confidence_reasons": [reason.to_dict() for reason in self.confidence_reasons],
            "route": self.route,
            "method": self.method,
            "param": self.param,
            "sink_id": self.sink.to_dict() if self.sink is not None else None,
            "alternatives": [sink.to_dict() for sink in self.alternatives],
            "file": self.file,
            "line": self.line,
            "status": self.status,
            "suppressed": self.suppressed,
            "link_reason": self.link_reason,
            "sast_findings": [finding.to_dict() for finding in self.sast_findings],
            "dast_findings": [finding.to_dict() for finding in self.dast_findings],
        }
