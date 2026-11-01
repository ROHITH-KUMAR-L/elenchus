"""Advisory AI over correlated issues: fix text (B-4) and link explanations (B-3).

This is zero-metric-risk advice. It only attaches text to `Issue.ai_notes`; it
never changes a label, link, status or confidence, and never creates or deletes
an issue. When AI is off (the default and in judging mode) or a task's switch is
off, `annotate` returns the issues unchanged and makes no network call.

Each task is gated behind a with/without run (ai/harness.py) before it may be
turned on. Because the advice is only text, the with/without run shows no change
in correct links or false alarms by construction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from engine.correlate.models import Issue

FIX_TASK = "fix_text"
EXPLAIN_TASK = "link_explanation"
SUMMARY_TASK = "report_summary"

_SUMMARY_SCHEMA = {
    "type": "object",
    "required": ["summary"],
    "properties": {"summary": {"type": "string"}},
}


def summarise_report(issues: Sequence[Issue], client) -> str | None:
    """A prose executive summary of the correlated issues, or None when the task
    is off, the client is unavailable or the AI makes no valid reply.

    Advisory only: it reads the deterministic verdicts and describes them. It never
    changes a label, link, status or confidence, and never creates an issue."""
    if client is None:
        return None
    answer = client.complete(SUMMARY_TASK, _summary_prompt(issues), _SUMMARY_SCHEMA)
    return answer["summary"] if answer is not None else None


def _summary_prompt(issues: Sequence[Issue]) -> str:
    lines = [
        f"- {issue.label} CWE-{issue.cwe} ({issue.type}), severity {issue.severity}, "
        f"route {issue.method or ''} {issue.route or ''}, param {issue.param or 'n/a'}, "
        f"at {issue.file or '?'}:{issue.line or '?'}, confidence {issue.confidence}"
        for issue in issues[:60]
    ]
    listing = "\n".join(lines) or "(no issues)"
    return (
        "You are writing an executive summary of a security scan for an engineering "
        "team. The deterministic scanner already decided every verdict; describe them, "
        "do not change them. Below are its issues (Confirmed = proven exploitable at "
        "runtime, Code-only = static only, Runtime-only = runtime hit with no code "
        f"link):\n{listing}\n\n"
        "Reply with JSON {\"summary\": \"<a readable report>\"}. In the summary give: a "
        "one-paragraph overview with the counts by label; the most urgent issues to fix "
        "first and why; and a short note per CWE class present. Plain text, no markdown "
        "headings. Do not invent issues or claim anything the list does not show."
    )

_FIX_SCHEMA = {"type": "object", "required": ["fix"], "properties": {"fix": {"type": "string"}}}
_EXPLAIN_SCHEMA = {
    "type": "object",
    "required": ["explanation"],
    "properties": {"explanation": {"type": "string"}},
}


def annotate(issues: Sequence[Issue], client) -> list[Issue]:
    """Attach fix text and a link explanation where the task is on. The issues
    come back in the same order, with the same verdicts."""
    if client is None:
        return list(issues)
    annotated: list[Issue] = []
    for issue in issues:
        notes = dict(issue.ai_notes or {})
        if issue.label in {"Confirmed", "Code-only"}:
            fix = client.complete(FIX_TASK, _fix_prompt(issue), _FIX_SCHEMA)
            if fix is not None:
                notes["fix"] = fix["fix"]
        if issue.link_status is not None:
            explanation = client.complete(EXPLAIN_TASK, _explain_prompt(issue), _EXPLAIN_SCHEMA)
            if explanation is not None:
                notes["explanation"] = explanation["explanation"]
        annotated.append(replace(issue, ai_notes=notes or None))
    return annotated


def _fix_prompt(issue: Issue) -> str:
    location = f"{issue.file}:{issue.line}" if issue.file and issue.line else (issue.route or "the app")
    return (
        f"A {issue.label} CWE-{issue.cwe} ({issue.type}) issue is at {location}, "
        f"route {issue.method or ''} {issue.route or ''}, parameter {issue.param or 'n/a'}. "
        "Reply with JSON {\"fix\": \"<one or two sentences of remediation advice>\"}. "
        "Advice only; do not claim the issue is real or not."
    )


def _explain_prompt(issue: Issue) -> str:
    return (
        f"A probe linked a CWE-{issue.cwe} runtime hit to a code sink with "
        f"link_status={issue.link_status}, link_origin={issue.link_origin}, "
        f"confidence={issue.confidence}. The deterministic reason is: {issue.link_reason}. "
        "Reply with JSON {\"explanation\": \"<one or two plain sentences explaining the link>\"}. "
        "Explain only; do not change the verdict."
    )
