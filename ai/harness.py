"""The AI with/without measurement harness.

Built before any AI task. It runs the pipeline with AI off and with AI on and
diffs the two on correct links and false alarms, so no AI task goes default-on
until a run shows no loss. The runner is injected: `runner(ai_enabled)` returns
the correlated issues for that setting. With AI off (disabled, or no credentials)
the AI client makes no network call, so the harness runs fully offline.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# An issue is anything with these attributes; the engine's Issue satisfies it.
IssueLike = Any
Runner = Callable[[bool], Sequence[IssueLike]]


@dataclass(frozen=True)
class ArmMeasure:
    confirmed: int
    reported: int
    correct_links: int
    wrong_links: int

    def to_dict(self) -> dict[str, int]:
        return {
            "confirmed": self.confirmed,
            "reported": self.reported,
            "correct_links": self.correct_links,
            "wrong_links": self.wrong_links,
        }


@dataclass(frozen=True)
class HarnessResult:
    without_ai: ArmMeasure
    with_ai: ArmMeasure

    @property
    def regressed(self) -> bool:
        """True if AI lost a correct link or added a wrong link (a false alarm)."""
        return (
            self.with_ai.correct_links < self.without_ai.correct_links
            or self.with_ai.wrong_links > self.without_ai.wrong_links
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "without_ai": self.without_ai.to_dict(),
            "with_ai": self.with_ai.to_dict(),
            "regressed": self.regressed,
            "safe_to_enable": not self.regressed,
        }

    def table(self) -> str:
        rows = [
            ("metric", "without_ai", "with_ai", "delta"),
            ("confirmed", self.without_ai.confirmed, self.with_ai.confirmed, None),
            ("reported", self.without_ai.reported, self.with_ai.reported, None),
            ("correct_links", self.without_ai.correct_links, self.with_ai.correct_links, None),
            ("wrong_links", self.without_ai.wrong_links, self.with_ai.wrong_links, None),
        ]
        lines = []
        for name, *_ in rows[:1]:
            lines.append(f"{name:<16}{'without_ai':>12}{'with_ai':>12}{'delta':>8}")
        for name, left, right, _ in rows[1:]:
            lines.append(f"{name:<16}{left:>12}{right:>12}{right - left:>+8}")
        verdict = "regressed: do NOT enable" if self.regressed else "no loss: safe to enable"
        lines.append(verdict)
        return "\n".join(lines)


def measure(issues: Sequence[IssueLike], expected_pairs: Mapping[str, Any] | None) -> ArmMeasure:
    pairs = list(expected_pairs.get("pairs", ())) if expected_pairs else []
    reported = [issue for issue in issues if not getattr(issue, "suppressed", False)]
    confirmed = [issue for issue in reported if getattr(issue, "label", None) == "Confirmed"]
    correct = sum(_matches_a_pair(issue, pairs) for issue in confirmed)
    wrong = sum(
        1
        for issue in confirmed
        if getattr(issue, "link_status", None) is not None and not _matches_a_pair(issue, pairs)
    )
    return ArmMeasure(len(confirmed), len(reported), correct, wrong)


def with_without(runner: Runner, expected_pairs: Mapping[str, Any] | None) -> HarnessResult:
    return HarnessResult(
        without_ai=measure(runner(False), expected_pairs),
        with_ai=measure(runner(True), expected_pairs),
    )


def _matches_a_pair(issue: IssueLike, pairs: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        int(pair["cwe"]) == getattr(issue, "cwe", None)
        and pair["route"] == getattr(issue, "route", None)
        and getattr(issue, "param", None) in pair.get("params", ())
        for pair in pairs
    )
