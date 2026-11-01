"""Plain-text issue report formatting, with an optional colored terminal UI.

Color is used only when stdout is a real terminal and NO_COLOR is unset, so piped
or captured output (and judging logs) stay plain. The detail lines are stable text
the SARIF/JSON outputs do not replace.
"""

from __future__ import annotations

import os
import sys
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from engine.compare import ScanComparison
from engine.correlate.models import SEVERITY_ORDER, Issue

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


def format_summary(issues: list[Issue]) -> str:
    """Summarize existing issue records without making an AI request."""
    visible = [issue for issue in issues if not issue.suppressed]
    if not visible:
        return "No issues found."

    by_cwe: dict[int, list[Issue]] = {}
    for issue in visible:
        by_cwe.setdefault(issue.cwe, []).append(issue)

    color = _use_color()
    lines = [
        _paint("elenchus — grouped summary (deterministic)", "bold", "cyan", color=color),
        f"{len(visible)} issue(s) across {len(by_cwe)} CWE group(s)",
    ]
    for cwe, group in sorted(by_cwe.items()):
        lines.extend(("", _paint(f"CWE-{cwe} ({len(group)} issue(s))", "blue", "bold", color=color)))
        for issue in sorted(group, key=_summary_priority):
            lines.extend(_summary_issue(issue))

    lines.extend(("", "Top 3 findings by severity, confidence, then risk score:"))
    for index, issue in enumerate(sorted(visible, key=_summary_priority)[:3], start=1):
        location = f"{issue.method or 'any method'} {issue.route or 'application-wide'}"
        lines.append(
            f"{index}. CWE-{issue.cwe} {issue.type} | {issue.severity} | "
            f"risk {_risk_text(issue)} | {location}"
        )

    has_advisory_fix = any(
        isinstance((issue.ai_notes or {}).get("fix"), str) and (issue.ai_notes or {}).get("fix")
        for issue in visible
    )
    advisory_status = (
        "existing advisory fixes are included above"
        if has_advisory_fix
        else "no existing advisory fixes are available"
    )
    lines.append(f"AI advisory: {advisory_status}; this summary made no AI calls.")
    return "\n".join(lines)


def render_summary(issues: list[Issue], console: Console) -> None:
    """Render a compact terminal overview; use the text formatter for details."""
    visible = [issue for issue in issues if not issue.suppressed]
    if not visible:
        console.print(Panel("No findings.", title="elenchus", border_style="green"))
        return

    labels = Counter(issue.label for issue in visible)
    cwe_count = len({issue.cwe for issue in visible})
    finding_word = "finding" if len(visible) == 1 else "findings"
    class_word = "CWE class" if cwe_count == 1 else "CWE classes"
    counts = (
        f"[red]{labels['Confirmed']} confirmed[/]  "
        f"[yellow]{labels['Code-only']} code-only[/]  "
        f"[magenta]{labels['Runtime-only']} runtime-only[/]"
    )
    console.print(
        Panel(
            f"[bold]{len(visible)}[/] {finding_word} across [bold]{cwe_count}[/] {class_word}\n{counts}",
            title="elenchus · scan results",
            border_style="cyan",
            expand=False,
        )
    )

    table = Table(box=None, expand=True, header_style="bold")
    table.add_column("Status", no_wrap=True)
    table.add_column("CWE", justify="right", no_wrap=True)
    table.add_column("Finding", overflow="fold")
    table.add_column("Runtime endpoint", overflow="fold")
    table.add_column("Trigger input", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Confidence", justify="right", no_wrap=True)
    for issue in sorted(visible, key=lambda item: (item.cwe, *_summary_priority(item))):
        endpoint = _runtime_endpoint(issue)
        parameter = _runtime_parameter(issue)
        severity_style = _SEVERITY_STYLE.get(issue.severity.casefold(), "dim")
        status_style = _LABEL_STYLE.get(issue.label, "dim")
        confidence = f"{issue.confidence:.2f}" if issue.confidence is not None else "n/a"
        table.add_row(
            Text(issue.label, style=status_style),
            Text(f"CWE-{issue.cwe}"),
            Text(issue.type),
            Text(endpoint),
            Text(parameter),
            Text(issue.severity, style=severity_style),
            Text(_risk_text(issue)),
            Text(confidence),
        )
    console.print(table)
    path_table = Table(box=None, expand=True, header_style="bold")
    path_table.add_column("Endpoint", overflow="fold")
    path_table.add_column("Trigger input", overflow="fold")
    path_table.add_column("Route-to-sink path", overflow="fold")
    has_runtime = False
    for issue in visible:
        if not issue.dast_findings:
            continue
        has_runtime = True
        paths = _route_to_sink_paths(issue)
        if not paths:
            path_table.add_row(
                Text(_runtime_endpoint(issue)),
                Text(_runtime_parameter(issue)),
                Text("No linked static path available", style="dim"),
            )
        for sink, chain in paths:
            path_table.add_row(
                Text(_runtime_endpoint(issue)),
                Text(_runtime_parameter(issue)),
                Text(f"{chain} -> sink {sink}"),
            )
    if has_runtime:
        console.print(
            Panel(
                path_table,
                title="Runtime reachability",
                subtitle="Indexed paths are static candidates; runtime evidence confirms route/input/CWE, not the exact sink.",
                border_style="blue",
                expand=False,
            )
        )
    console.print("[dim]Choose raw output for evidence, source locations, and link details.[/]")


def _summary_priority(issue: Issue) -> tuple[int, float, float, int, str, str]:
    severity = SEVERITY_ORDER.get(issue.severity.casefold(), 1)
    confidence = issue.confidence if issue.confidence is not None else -1.0
    risk = issue.risk_score if issue.risk_score is not None else -1.0
    return (-severity, -confidence, -risk, issue.cwe, issue.route or "", issue.issue_key)


def _risk_text(issue: Issue) -> str:
    return f"{issue.risk_score:.0f}/100" if issue.risk_score is not None else "n/a"


def _summary_issue(issue: Issue) -> list[str]:
    confidence = f"{issue.confidence:.2f}" if issue.confidence is not None else "none"
    location = f"{issue.file}:{issue.line}" if issue.file and issue.line else "no source location"
    lines = [
        (
            f"  - {issue.label} | {issue.type} | {issue.method or 'any method'} "
            f"{issue.route or 'application-wide'}"
        ),
        f"    Runtime endpoint: {_runtime_endpoint(issue)}",
        f"    Trigger input: {_runtime_parameter(issue)}",
        f"    Severity: {issue.severity} | Risk: {_risk_text(issue)} | Confidence: {confidence}",
        f"    Evidence: {_summary_evidence(issue)}",
        f"    Source: {location}",
    ]
    lines.extend(_route_to_sink_path_lines(issue, "    "))
    notes = issue.ai_notes or {}
    fix = notes.get("fix")
    if fix:
        lines.append(f"    Remediation hint (existing AI advisory; not verified): {fix}")
    else:
        lines.append("    Remediation hint: unavailable in the finding data.")
    explanation = notes.get("explanation")
    if explanation:
        lines.append(f"    Existing AI advisory note: {explanation}")
    return lines


def _summary_evidence(issue: Issue) -> str:
    entries: list[str] = []
    payloads: list[str] = []
    for finding in issue.sast_findings + issue.dast_findings:
        if finding.payload:
            payloads.append(f"payload {finding.payload}")
        for evidence in finding.evidence:
            detail = evidence.detail
            description = evidence.type
            oracle = detail.get("oracle")
            if isinstance(oracle, str) and oracle:
                description += f" ({oracle})"
            snippet = detail.get("snippet")
            if isinstance(snippet, str) and snippet:
                description += f": {snippet}"
            entries.append(description)
    evidence = list(dict.fromkeys((*entries, *payloads)))
    return "; ".join(evidence) if evidence else "no evidence details recorded"


def _runtime_endpoint(issue: Issue) -> str:
    if issue.route is None:
        return "not recorded"
    return f"{issue.method or 'any method'} {issue.route}"


def _runtime_parameter(issue: Issue) -> str:
    if issue.param is None:
        return "not identified"
    probe = next(
        (
            finding
            for finding in issue.dast_findings
            if finding.param == issue.param and finding.param_location is not None
        ),
        None,
    )
    if probe is None:
        return f"{issue.param} (location not recorded)"
    if probe.param_location == "path":
        return f"path parameter '{issue.param}'"
    if probe.param_location == "query":
        return f"query parameter '{issue.param}'"
    if probe.param_location == "body":
        field = probe.param_path or issue.param
        return f"request body field '{field}'"
    return f"{probe.param_location} parameter '{issue.param}'"


def _route_to_sink_path_lines(issue: Issue, indent: str) -> list[str]:
    paths = _route_to_sink_paths(issue)
    if not paths:
        if issue.dast_findings:
            return [f"{indent}Indexed route-to-sink path: unavailable (no linked static path)."]
        return []
    lines = [f"{indent}Indexed route-to-sink path (static, not a runtime trace):"]
    for sink, chain in paths:
        lines.append(f"{indent}  {chain} -> sink {sink}")
    return lines


def _route_to_sink_paths(issue: Issue) -> list[tuple[str, str]]:
    paths: list[tuple[str, str]] = []
    for finding in issue.sast_findings:
        for entry in finding.entry_paths or ():
            if issue.route is not None and entry.route != issue.route:
                continue
            if issue.method is not None and entry.method != issue.method:
                continue
            chain = " -> ".join(
                f"{hop.method} ({hop.file}:{hop.line})" if hop.file else f"{hop.method} (unresolved)"
                for hop in entry.call_chain
            )
            sink = (
                f"{finding.sink_id.file}:{finding.sink_id.start_line}"
                if finding.sink_id is not None
                else f"{finding.file}:{finding.line}"
            )
            item = (sink, chain)
            if chain and item not in paths:
                paths.append(item)
    return paths


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
        f"   Runtime endpoint: {_runtime_endpoint(issue)}",
        f"   Trigger input: {_runtime_parameter(issue)}",
        f"   Severity: {severity} | Confidence: {confidence} | Link: {link}",
    ]
    lines.extend(_route_to_sink_path_lines(issue, "   "))
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
