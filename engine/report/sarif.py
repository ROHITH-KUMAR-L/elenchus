"""SARIF 2.1.0 export for correlated issues."""

from __future__ import annotations

from typing import Any

from common.record import Finding
from engine.correlate.models import Issue


def to_sarif(issues: list[Issue]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for issue in issues:
        finding = issue.primary_finding
        route_finding = issue.route_finding
        rule_id = f"CWE-{finding.cwe}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.type,
                "shortDescription": {"text": finding.type},
                "properties": {"cwe": finding.cwe},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(issue.severity),
            "message": {
                "text": f"{finding.type} (CWE-{finding.cwe}). {issue.label}."
            },
            "properties": {
                "issue_key": issue.issue_key,
                "cwe": finding.cwe,
                "label": issue.label,
                "confidence": issue.confidence,
                "risk_score": issue.risk_score,
                "severity": issue.severity,
                "run_id": finding.run_id,
                "route": route_finding.route,
                "method": route_finding.method,
                "param": issue.param,
                "payloads": [
                    item.payload
                    for item in issue.dast_findings
                    if item.payload is not None
                ],
                "sast_findings": [item.to_dict() for item in issue.sast_findings],
                "dast_findings": [item.to_dict() for item in issue.dast_findings],
                "link_reason": issue.link_reason,
                "wasc_id": finding.wasc_id,
                "sink_id": finding.sink_id.to_dict() if finding.sink_id else None,
                "entry_paths": [
                    path.to_dict()
                    for item in issue.sast_findings
                    for path in item.entry_paths or ()
                ],
                "evidence": [
                    entry.to_dict()
                    for item in issue.sast_findings + issue.dast_findings
                    for entry in item.evidence
                ],
            },
        }

        primary_location = _physical_location(finding)
        if primary_location is not None:
            result["locations"] = [{"physicalLocation": primary_location}]
        elif route_finding.route is not None:
            result["logicalLocations"] = [
                {"name": route_finding.route, "kind": "resource"}
            ]

        related_locations = []
        for item in issue.dast_findings:
            physical_location = _physical_location(item)
            if physical_location is not None:
                related_locations.append(
                    {
                        "id": len(related_locations) + 1,
                        "message": {"text": "DAST route-map source location"},
                        "physicalLocation": physical_location,
                    }
                )
        for item in issue.sast_findings:
            for path in item.entry_paths or ():
                handler = path.call_chain[0]
                if handler.file is None:
                    continue
                related_locations.append(
                    {
                        "id": len(related_locations) + 1,
                        "message": {"text": "Handler reaches the SAST sink"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": handler.file},
                            "region": {"startLine": handler.line},
                        },
                    }
                )
        if related_locations:
            result["relatedLocations"] = related_locations
        result["properties"]["taint_trace"] = [
            [step.to_dict() for step in item.taint_trace]
            for item in issue.sast_findings
            if item.taint_trace
        ]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Elenchus",
                        "informationUri": "https://github.com/ROHITH-KUMAR-L/elenchus",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _physical_location(finding: Finding) -> dict[str, Any] | None:
    if finding.file is None or finding.line is None:
        return None
    return {
        "artifactLocation": {"uri": finding.file},
        "region": {"startLine": finding.line},
    }


def _sarif_level(severity: str) -> str:
    normalized = severity.casefold()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized in {"medium", "moderate"}:
        return "warning"
    if normalized in {"low", "info", "informational"}:
        return "note"
    return "none"
