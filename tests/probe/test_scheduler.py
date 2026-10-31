"""The two-pass scheduler runs directed jobs first and records every skip."""

from common.pipeline import ProbeJob, SeedRequest
from probe.scheduler import run_two_pass


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def job(job_id: str, job_pass: str) -> ProbeJob:
    seed = SeedRequest(url="http://127.0.0.1:9090/x", method="GET")
    return ProbeJob(
        job_id=job_id, route="/x", method="GET", job_pass=job_pass,
        hypothesis_ids=(), cwes=(89,), seed_request=seed, canary="c",
    )


def test_directed_jobs_run_before_sweep_even_when_listed_last():
    clock = Clock()
    order: list[str] = []

    def run(j: ProbeJob) -> str:
        order.append(j.job_id)
        return j.job_id

    schedule = run_two_pass([job("s1", "sweep"), job("d1", "directed")], 100, clock, run)
    assert order == ["d1", "s1"]
    assert schedule.skipped == []


def test_sweep_jobs_wait_until_directed_jobs_are_done_and_budget_remains():
    clock = Clock()
    jobs = [job("d1", "directed"), job("s1", "sweep"), job("s2", "sweep")]

    def run(j: ProbeJob) -> str:
        clock.now += 30  # each job takes 30 seconds
        return j.job_id

    schedule = run_two_pass(jobs, 100, clock, run)
    assert schedule.ran == ["d1", "s1", "s2"]


def test_directed_uses_the_whole_budget_and_sweep_takes_the_rest():
    clock = Clock()
    jobs = [job(f"d{i}", "directed") for i in range(3)] + [job("s1", "sweep")]

    def run(j: ProbeJob) -> str:
        clock.now += 40  # each job takes 40 of the 100-second budget
        return j.job_id

    schedule = run_two_pass(jobs, 100, clock, run)
    # d0 at 0, d1 at 40, d2 at 80 all start before 100 and run. s1 would start at
    # 120, past the deadline, so it is skipped: directed is not sub-capped.
    assert schedule.ran == ["d0", "d1", "d2"]
    assert {j.job_id: reason for j, reason in schedule.skipped} == {
        "s1": "zap_jobs budget spent"
    }


def test_a_full_budget_skips_everything_and_runs_nothing():
    clock = Clock()
    clock.now = 0.0
    schedule = run_two_pass([job("d1", "directed")], 0, clock, lambda j: j.job_id)
    assert schedule.ran == []
    assert [j.job_id for j, _ in schedule.skipped] == ["d1"]
