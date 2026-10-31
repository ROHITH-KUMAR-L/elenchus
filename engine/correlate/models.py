"""Engine-only types built from canonical findings."""

from __future__ import annotations

from dataclasses import dataclass

from common.record import Finding

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
