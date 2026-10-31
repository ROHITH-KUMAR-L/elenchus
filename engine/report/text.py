"""Plain-text issue report formatting."""

from __future__ import annotations

from engine.correlate.models import Issue


def format_text(issues: list[Issue]) -> str:
    if not issues:
        return "No issues found."

    lines = [f"Found {len(issues)} issue(s):"]
    for index, issue in enumerate(issues, start=1):
        primary = issue.primary_finding
        route_finding = issue.route_finding
        location = (
            f"{primary.file}:{primary.line}"
            if primary.file is not None and primary.line is not None
            else "no source location"
        )
        lines.extend(
            [
                "",
                (
                    f"{index}. {issue.label} | CWE-{primary.cwe} {primary.type} "
                    f"| risk {issue.risk_score:.0f}/100 | {location}"
                ),
                f"   Route: {route_finding.method or 'any method'} {route_finding.route or 'application-wide'}",
                f"   Parameter: {issue.param or 'none'}",
                f"   Severity: {issue.severity}",
                f"   Confidence: {issue.confidence or 'none'}",
            ]
        )
        for finding in issue.dast_findings:
            if finding.payload is not None:
                lines.append(f"   Payload: {finding.payload}")
            oracle = finding.evidence.get("oracle")
            if isinstance(oracle, str) and oracle:
                lines.append(f"   Oracle: {oracle}")
            request = finding.evidence.get("request")
            if isinstance(request, str) and request:
                lines.append(f"   Request: {request}")
            response_excerpt = finding.evidence.get("response_excerpt")
            if isinstance(response_excerpt, str) and response_excerpt:
                lines.append(f"   Response: {response_excerpt}")
        for finding in issue.sast_findings:
            snippet = finding.evidence.get("snippet")
            if isinstance(snippet, str) and snippet:
                lines.append(f"   Code: {snippet}")
        if issue.link_reason:
            lines.append(f"   Link: {issue.link_reason}")
        lines.append(f"   Issue key: {issue.issue_key}")
    return "\n".join(lines)
