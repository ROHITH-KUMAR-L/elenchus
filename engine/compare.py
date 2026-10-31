"""Compare two stored scan runs (PRD B-5).

Two runs are compared by the same identity the dedupe key uses: a code or
Confirmed issue is keyed by its sink and CWE, a Runtime-only issue by its route,
method, param and CWE. An issue present in both runs is still-open, one only in
the base run is fixed, one only in the current run is new. Suppressed issues are
left out of both sides, so suppression never shows up as a fix or a regression.

This module is pure: it takes the issue dicts the store holds and classifies
them. It never reads the database or decides a verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

CHANGES = ("new", "fixed", "still_open")


def comparison_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    """The cross-run identity of an issue. A sink-bearing issue is keyed by its
    sink and CWE (the dedupe key); a Runtime-only issue by route, method, param
    and CWE (the runtime fallback key)."""
    sink = issue.get("sink_id")
    cwe = issue.get("cwe")
    if isinstance(sink, Mapping):
        return (
            "sink",
            sink.get("file"),
            sink.get("enclosing_method"),
            sink.get("start_line"),
            sink.get("start_col"),
            cwe,
        )
    return ("route", cwe, issue.get("route"), issue.get("method"), issue.get("param"))


@dataclass(frozen=True)
class ComparedIssue:
    change: str  # one of CHANGES
    cwe: int
    type: str
    label: str
    severity: str
    route: str | None
    file: str | None
    line: int | None
    issue_key: str | None
    previous_label: str | None = None  # set on still_open when the label changed

    def to_dict(self) -> dict[str, Any]:
        record = {
            "change": self.change,
            "cwe": self.cwe,
            "type": self.type,
            "label": self.label,
            "severity": self.severity,
            "route": self.route,
            "file": self.file,
            "line": self.line,
            "issue_key": self.issue_key,
        }
        if self.previous_label is not None:
            record["previous_label"] = self.previous_label
        return record


@dataclass(frozen=True)
class ScanComparison:
    base_run_id: str
    current_run_id: str
    issues: tuple[ComparedIssue, ...]

    def of(self, change: str) -> tuple[ComparedIssue, ...]:
        return tuple(issue for issue in self.issues if issue.change == change)

    @property
    def new(self) -> tuple[ComparedIssue, ...]:
        return self.of("new")

    @property
    def fixed(self) -> tuple[ComparedIssue, ...]:
        return self.of("fixed")

    @property
    def still_open(self) -> tuple[ComparedIssue, ...]:
        return self.of("still_open")

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_run_id": self.base_run_id,
            "current_run_id": self.current_run_id,
            "counts": {change: len(self.of(change)) for change in CHANGES},
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _reported(issues: Iterable[Mapping[str, Any]]) -> dict[tuple[Any, ...], Mapping[str, Any]]:
    """Index non-suppressed issues by comparison key. A later duplicate key keeps
    the first, so one bug reported under two entries counts once."""
    indexed: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    for issue in issues:
        if issue.get("suppressed"):
            continue
        indexed.setdefault(comparison_key(issue), issue)
    return indexed


def _compared(change: str, issue: Mapping[str, Any], previous_label: str | None = None) -> ComparedIssue:
    return ComparedIssue(
        change=change,
        cwe=int(issue.get("cwe", 0)),
        type=str(issue.get("type", "")),
        label=str(issue.get("label", "")),
        severity=str(issue.get("severity", "unknown")),
        route=issue.get("route"),
        file=issue.get("file"),
        line=issue.get("line"),
        issue_key=issue.get("issue_key"),
        previous_label=previous_label,
    )


def compare_runs(
    base_issues: Sequence[Mapping[str, Any]],
    current_issues: Sequence[Mapping[str, Any]],
    *,
    base_run_id: str = "",
    current_run_id: str = "",
) -> ScanComparison:
    """Classify every reported issue as new, fixed or still-open.

    base is the earlier run, current the later one. An issue only in base is
    fixed, one only in current is new, one in both is still-open (its label is
    carried from current, with the base label recorded when it changed).
    """
    base = _reported(base_issues)
    current = _reported(current_issues)
    compared: list[ComparedIssue] = []
    for key, issue in current.items():
        if key in base:
            previous = str(base[key].get("label", ""))
            label = str(issue.get("label", ""))
            compared.append(_compared("still_open", issue, previous if previous != label else None))
        else:
            compared.append(_compared("new", issue))
    for key, issue in base.items():
        if key not in current:
            compared.append(_compared("fixed", issue))
    compared.sort(key=_sort_key)
    return ScanComparison(base_run_id, current_run_id, tuple(compared))


_CHANGE_ORDER = {"new": 0, "still_open": 1, "fixed": 2}
_LABEL_ORDER = {"Confirmed": 0, "Code-only": 1, "Runtime-only": 2}


def _sort_key(issue: ComparedIssue) -> tuple[int, int, int, str]:
    return (
        _CHANGE_ORDER.get(issue.change, 9),
        _LABEL_ORDER.get(issue.label, 9),
        issue.cwe,
        issue.issue_key or "",
    )
