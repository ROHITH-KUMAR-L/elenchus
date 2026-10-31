"""Plain-text issue report formatting."""

from __future__ import annotations

from engine.compare import ScanComparison
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
        if issue.conflict:
            lines.append("   Conflict: positive replay against negative evidence")
        if issue.oracle_flaky:
            lines.append("   Oracle: flaky replay; verdict remains Runtime-only")
        for sink in issue.alternatives:
            lines.append(f"   Alternative sink: {sink.file}:{sink.start_line}")
        for sink in issue.candidate_sinks:
            lines.append(f"   Candidate sink hint: {sink.file}:{sink.start_line}")
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
        for label, key in (("Advisory fix", "fix"), ("Advisory note", "explanation")):
            text = (issue.ai_notes or {}).get(key)
            if text:
                lines.append(f"   {label} (AI, advisory): {text}")
        lines.append(f"   Issue key: {issue.issue_key}")
    return "\n".join(lines)


def format_comparison(comparison: ScanComparison) -> str:
    """Scan comparison (B-5): new, fixed and still-open issues between two runs."""
    counts = {change: len(comparison.of(change)) for change in ("new", "fixed", "still_open")}
    lines = [
        f"Comparing run {comparison.base_run_id or '?'} -> {comparison.current_run_id or '?'}",
        f"New: {counts['new']} | Fixed: {counts['fixed']} | Still open: {counts['still_open']}",
    ]
    headings = {"new": "New issues", "fixed": "Fixed issues", "still_open": "Still open"}
    for change, heading in headings.items():
        entries = comparison.of(change)
        if not entries:
            continue
        lines.append("")
        lines.append(f"{heading}:")
        for entry in entries:
            location = f"{entry.file}:{entry.line}" if entry.file and entry.line else (entry.route or "application-wide")
            label = entry.label
            if entry.previous_label:
                label = f"{entry.previous_label} -> {entry.label}"
            lines.append(f"  - {label} | CWE-{entry.cwe} {entry.type} | {location}")
    return "\n".join(lines)
