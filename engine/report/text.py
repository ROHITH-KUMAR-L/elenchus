"""Plain-text issue report formatting."""

from __future__ import annotations

from engine.correlate.models import Issue


def format_text(issues: list[Issue]) -> str:
    issues = [issue for issue in issues if not issue.suppressed]
    if not issues:
        return "No issues found."

    lines = [f"Found {len(issues)} issue(s):"]
    for index, issue in enumerate(issues, start=1):
        location = f"{issue.file}:{issue.line}" if issue.file and issue.line else "no source location"
        confidence = f"{issue.confidence:.2f}" if issue.confidence is not None else "none"
        link = issue.link_status or issue.status or "none"
        lines.extend(
            [
                "",
                (
                    f"{index}. {issue.label} | CWE-{issue.cwe} {issue.type} "
                    f"| risk {issue.risk_score:.0f}/100 | {location}"
                ),
                f"   Route: {issue.method or 'any method'} {issue.route or 'application-wide'}",
                f"   Parameter: {issue.param or 'none'}",
                f"   Severity: {issue.severity} | Confidence: {confidence} | Link: {link}",
            ]
        )
        if issue.link_origin:
            lines.append(f"   Link origin: {issue.link_origin}")
        for sink in issue.alternatives:
            lines.append(f"   Alternative sink: {sink.file}:{sink.start_line}")
        for finding in issue.dast_findings:
            if finding.payload is not None:
                lines.append(f"   Payload: {finding.payload}")
            oracle = finding.detail("oracle")
            if isinstance(oracle, str) and oracle:
                fired, replays = finding.detail("fired"), finding.detail("replays")
                suffix = f" ({fired}/{replays} replays)" if fired is not None else ""
                lines.append(f"   Oracle: {oracle}{suffix}")
        for finding in issue.sast_findings:
            snippet = finding.detail("snippet")
            if isinstance(snippet, str) and snippet:
                lines.append(f"   Code: {snippet}")
        if issue.link_reason:
            lines.append(f"   Link: {issue.link_reason}")
        lines.append(f"   Issue key: {issue.issue_key}")
    return "\n".join(lines)
