"""Plain-text issue report formatting, with an optional colored terminal UI.

Color is used only when stdout is a real terminal and NO_COLOR is unset, so piped
or captured output (and judging logs) stay plain. The detail lines are stable text
the SARIF/JSON outputs do not replace.
"""

from __future__ import annotations

import os
import sys
from collections import Counter

from engine.compare import ScanComparison
from engine.correlate.models import Issue

_RESET = "\033[0m"
_STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}
_LABEL_STYLE = {"Confirmed": "red", "Code-only": "yellow", "Runtime-only": "magenta"}
_SEVERITY_STYLE = {
    "critical": "red", "high": "red", "medium": "yellow", "moderate": "yellow",
    "low": "cyan", "info": "dim", "informational": "dim",
}


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(text: str, *styles: str, color: bool) -> str:
    if not color or not styles:
        return text
    codes = "".join(_STYLES[s] for s in styles if s in _STYLES)
    return f"{codes}{text}{_RESET}" if codes else text


def _rule(color: bool, char: str = "─", width: int = 64) -> str:
    return _paint(char * width, "dim", color=color)


def format_text(issues: list[Issue]) -> str:
    color = _use_color()
    issues = [issue for issue in issues if not issue.suppressed]
    if not issues:
        return "No issues found."

    lines = _summary(issues, color)
    for index, issue in enumerate(issues, start=1):
        lines.extend(_issue_block(index, issue, color))
    return "\n".join(lines)


def _summary(issues: list[Issue], color: bool) -> list[str]:
    labels = Counter(issue.label for issue in issues)
    by_cwe = Counter(f"CWE-{issue.cwe}" for issue in issues if issue.label == "Confirmed")
    header = _paint(f"elenchus — {len(issues)} issue(s)", "bold", "cyan", color=color)
    tally = "  ".join(
        _paint(f"{labels.get(label, 0)} {label}", _LABEL_STYLE.get(label, "dim"), color=color)
        for label in ("Confirmed", "Code-only", "Runtime-only")
    )
    lines = [header, tally]
    if by_cwe:
        confirmed = ", ".join(f"{cwe} ×{n}" for cwe, n in sorted(by_cwe.items()))
        lines.append(_paint(f"Confirmed classes: {confirmed}", "green", color=color))
    lines.append(_rule(color))
    return lines


def _issue_block(index: int, issue: Issue, color: bool) -> list[str]:
    location = f"{issue.file}:{issue.line}" if issue.file and issue.line else "no source location"
    confidence = f"{issue.confidence:.2f}" if issue.confidence is not None else "none"
    link = issue.link_status or issue.status or "none"
    label = _paint(issue.label, _LABEL_STYLE.get(issue.label, "bold"), "bold", color=color)
    severity = _paint(issue.severity, _SEVERITY_STYLE.get(issue.severity.casefold(), "dim"), color=color)
    risk = f"{issue.risk_score:.0f}/100" if issue.risk_score is not None else "n/a"
    lines = [
        "",
        f"{index}. {label} | CWE-{issue.cwe} {issue.type} | risk {risk} | {location}",
        f"   Route: {issue.method or 'any method'} {issue.route or 'application-wide'}",
        f"   Parameter: {issue.param or 'none'}",
        f"   Severity: {severity} | Confidence: {confidence} | Link: {link}",
    ]
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
        lines.append(_paint(f"   Link: {issue.link_reason}", "dim", color=color))
    for display, key in (("Advisory fix", "fix"), ("Advisory note", "explanation")):
        text = (issue.ai_notes or {}).get(key)
        if text:
            lines.append(_paint(f"   {display} (AI, advisory): {text}", "blue", color=color))
    lines.append(_paint(f"   Issue key: {issue.issue_key}", "dim", color=color))
    return lines


def format_comparison(comparison: ScanComparison) -> str:
    """Scan comparison (B-5): new, fixed and still-open issues between two runs."""
    color = _use_color()
    counts = {change: len(comparison.of(change)) for change in ("new", "fixed", "still_open")}
    lines = [
        _paint(
            f"Comparing run {comparison.base_run_id or '?'} -> {comparison.current_run_id or '?'}",
            "bold", "cyan", color=color,
        ),
        "  ".join(
            (
                _paint(f"New: {counts['new']}", "red", color=color),
                _paint(f"Fixed: {counts['fixed']}", "green", color=color),
                _paint(f"Still open: {counts['still_open']}", "yellow", color=color),
            )
        ),
    ]
    headings = {"new": "New issues", "fixed": "Fixed issues", "still_open": "Still open"}
    styles = {"new": "red", "fixed": "green", "still_open": "yellow"}
    for change, heading in headings.items():
        entries = comparison.of(change)
        if not entries:
            continue
        lines.append("")
        lines.append(_paint(f"{heading}:", styles[change], "bold", color=color))
        for entry in entries:
            location = (
                f"{entry.file}:{entry.line}"
                if entry.file and entry.line
                else (entry.route or "application-wide")
            )
            label = entry.label
            if entry.previous_label:
                label = f"{entry.previous_label} -> {entry.label}"
            lines.append(f"  - {label} | CWE-{entry.cwe} {entry.type} | {location}")
    return "\n".join(lines)
