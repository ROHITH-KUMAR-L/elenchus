"""SARIF 2.1.0 export for correlated issues. Lossy; the record is the source of truth."""

from __future__ import annotations

from typing import Any

from engine.correlate.models import Issue


def to_sarif(issues: list[Issue]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for issue in issues:
        rule_id = f"CWE-{issue.cwe}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": issue.type,
                "shortDescription": {"text": issue.type},
                "properties": {"cwe": issue.cwe},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(issue.severity),
            "message": {"text": f"{issue.type} (CWE-{issue.cwe}). {issue.label}."},
            "properties": {
                "issue_key": issue.issue_key,
                "cwe": issue.cwe,
                "label": issue.label,
                "link_status": issue.link_status,
                "link_origin": issue.link_origin,
                "confidence": issue.confidence,
                "confidence_reasons": [reason.to_dict() for reason in issue.confidence_reasons],
                "risk_score": issue.risk_score,
                "severity": issue.severity,
                "status": issue.status,
                "route": issue.route,
                "method": issue.method,
                "param": issue.param,
                "payloads": [f.payload for f in issue.dast_findings if f.payload is not None],
                "sink_id": issue.sink.to_dict() if issue.sink is not None else None,
                "alternatives": [sink.to_dict() for sink in issue.alternatives],
                "entry_paths": [
                    path.to_dict() for f in issue.sast_findings for path in f.entry_paths or ()
                ],
                "evidence": [
                    entry.to_dict()
                    for f in issue.sast_findings + issue.dast_findings
                    for entry in f.evidence
                ],
                "link_reason": issue.link_reason,
            },
        }
        if issue.file is not None and issue.line is not None:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.file},
                        "region": {"startLine": issue.line},
                    }
                }
            ]
        elif issue.route is not None:
            result["logicalLocations"] = [{"name": issue.route, "kind": "resource"}]

        related = []
        for sink in issue.alternatives:
            related.append(
                {
                    "id": len(related) + 1,
                    "message": {"text": "Alternative sink on the same route"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": sink.file},
                        "region": {"startLine": sink.start_line},
                    },
                }
            )
        if related:
            result["relatedLocations"] = related
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


def _sarif_level(severity: str) -> str:
    normalized = severity.casefold()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized in {"medium", "moderate"}:
        return "warning"
    if normalized in {"low", "info", "informational"}:
        return "note"
    return "none"
