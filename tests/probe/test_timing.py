"""Time-based blind SQL wiring: off by default, fires on a measured slowdown."""

from __future__ import annotations

from common.config import load_config
from common.pipeline import ProbeJob, SeedRequest
from probe.coordinator import Coordinator
from probe.oracles import Response, timing_slower
from probe.preflight import ContextPath

BASE = "http://127.0.0.1:9090/VulnerableApp"
ROUTE = "/BlindSQLInjectionVulnerability/LEVEL_1"


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t


class TimingZap:
    """Advances a shared clock on each request: slow for a sleep payload, fast
    otherwise. The coordinator reads the same clock, so a timed replay sees the
    slowdown."""

    base_url = "http://127.0.0.1:8090"

    def __init__(self, clock, *, slow_payload=True):
        self._clock = clock
        self._slow_payload = slow_payload

    def send_request(self, raw_request, follow_redirects=False):
        sleeps = any(marker in raw_request for marker in ("SLEEP", "WAITFOR", "PG_SLEEP"))
        self._clock.t += 5.0 if (sleeps and self._slow_payload) else 0.01
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "ok"}


def job():
    return ProbeJob(
        job_id="run-j0", route=ROUTE, method="GET", job_pass="directed",
        hypothesis_ids=("h-1",), cwes=(89,),
        seed_request=SeedRequest(url=f"{BASE}{ROUTE}?id=1", method="GET"), canary="elx-run-j0",
    )


def coordinator(fake, *, timing_repeats):
    config = load_config(
        overrides={"target.base_url": BASE, "probe.timing_repeats": timing_repeats}
        if timing_repeats is not None
        else {"target.base_url": BASE},
        environ={"ZAP_API_KEY": "k"},
    )
    coord = Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))
    return coord


def seed():
    return SeedRequest(url=f"{BASE}{ROUTE}?id=1", method="GET")


BASELINE = Response(status=200, headers="HTTP/1.1 200 OK\r\n", body="ok")


def test_timing_is_off_without_probe_timing_repeats():
    coord = coordinator(TimingZap(Clock()), timing_repeats=None)
    assert coord._confirm_timing("run", job(), seed(), BASELINE, set()) == []


def test_slow_payload_confirms_time_based_blind_sql():
    clock = Clock()
    coord = coordinator(TimingZap(clock), timing_repeats=3)
    coord._now = clock.now
    findings = coord._confirm_timing("run", job(), seed(), BASELINE, set())
    assert len(findings) == 1
    assert findings[0].cwe == 89
    assert findings[0].param == "id"
    assert findings[0].detail("oracle") == "timing_slower"
    assert findings[0].detail("fired") >= 2


def test_no_slowdown_makes_no_finding():
    clock = Clock()
    coord = coordinator(TimingZap(clock, slow_payload=False), timing_repeats=3)
    coord._now = clock.now
    assert coord._confirm_timing("run", job(), seed(), BASELINE, set()) == []


def test_already_confirmed_param_is_skipped():
    clock = Clock()
    coord = coordinator(TimingZap(clock), timing_repeats=3)
    coord._now = clock.now
    assert coord._confirm_timing("run", job(), seed(), BASELINE, {"id"}) == []


def test_timing_slower_oracle_threshold():
    assert timing_slower(0.1, 5.0, 2.5)
    assert not timing_slower(0.1, 1.0, 2.5)
