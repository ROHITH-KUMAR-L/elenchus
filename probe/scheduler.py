"""Two-pass deadline scheduler for ZAP jobs (BS6).

Directed jobs run first, then sweep jobs, all inside one zap_jobs budget.
Directed jobs carry a static hypothesis, so they are the higher-value pass and
are not sub-capped: they run until the budget is spent. Sweep jobs use whatever
time is left, which still covers the classes that have no static catalogue (XSS,
open redirect) as long as the directed set fits well inside the budget. A job not
started before the deadline is skipped with a reason, so a skipped job is never
read as a negative result.

The clock is injected, so the schedule is deterministic under test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from common.pipeline import ProbeJob


@dataclass
class Schedule[T]:
    ran: list[T] = field(default_factory=list)
    skipped: list[tuple[ProbeJob, str]] = field(default_factory=list)  # (job, reason)


def run_two_pass[T](
    jobs: list[ProbeJob],
    budget_seconds: float,
    clock: Callable[[], float],
    run: Callable[[ProbeJob], T],
) -> Schedule[T]:
    """Run directed jobs first, then sweep, until the one budget is spent."""
    deadline = clock() + budget_seconds
    schedule: Schedule[T] = Schedule()
    # Directed first, whatever order the caller listed them in.
    for job in sorted(jobs, key=lambda j: j.job_pass != "directed"):
        if clock() >= deadline:
            schedule.skipped.append((job, "zap_jobs budget spent"))
            continue
        schedule.ran.append(run(job))
    return schedule
