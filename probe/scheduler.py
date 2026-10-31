"""Two-pass deadline scheduler for ZAP jobs (BS6).

Directed jobs run first, inside a share of the zap_jobs budget. Sweep jobs use
what is left. A job that has not started by its pass's deadline is skipped and
recorded with the reason, so a skipped job is never read as a negative result.

The clock is injected, so the schedule is deterministic under test. The pass
share is [proposed]: it is tuned on VulnerableApp in BS8.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from common.pipeline import ProbeJob

DIRECTED_SHARE = 0.6  # [proposed]: share of the budget the directed pass may use


@dataclass
class Schedule[T]:
    ran: list[T] = field(default_factory=list)
    skipped: list[tuple[ProbeJob, str]] = field(default_factory=list)  # (job, reason)


def run_two_pass[T](
    jobs: list[ProbeJob],
    budget_seconds: float,
    clock: Callable[[], float],
    run: Callable[[ProbeJob], T],
    directed_share: float = DIRECTED_SHARE,
) -> Schedule[T]:
    """Run directed jobs, then sweep jobs, each inside its own deadline."""
    start = clock()
    directed_deadline = start + budget_seconds * directed_share
    overall_deadline = start + budget_seconds
    schedule: Schedule[T] = Schedule()
    # Directed first, whatever order the caller listed them in.
    for job in sorted(jobs, key=lambda j: j.job_pass != "directed"):
        if job.job_pass == "directed":
            deadline, reason = directed_deadline, "directed pass budget spent"
        else:
            deadline, reason = overall_deadline, "zap_jobs budget spent"
        if clock() >= deadline:
            schedule.skipped.append((job, reason))
            continue
        schedule.ran.append(run(job))
    return schedule
