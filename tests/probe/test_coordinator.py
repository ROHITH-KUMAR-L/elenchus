"""Coordinator behaviour against a scripted fake ZAP. No network, no sleeping.

The fake returns fixed scan messages and scripted replay responses. Tests pin down
positive lineage, flaky replay evidence, adequacy observations, and attribution.
"""

from __future__ import annotations

from common.config import load_config
from common.pipeline import Hypothesis, SeedRequest
from common.record import CallHop, RouteEntry, RouteParam, SinkId
from probe.coordinator import Coordinator, plan_directed_jobs
from probe.preflight import ContextPath

BASE = "http://127.0.0.1:9090/VulnerableApp"
ROUTE = "/ErrorBasedSQLInjectionVulnerability/LEVEL_1"
SINK = SinkId("Svc.java", "Svc.find", 83, 20)

ROUTES = (
    RouteEntry(ROUTE, "GET", "C.java", "C.get", 70, 90, (RouteParam("id", "query", "String"),), ()),
)


def hypothesis():
    return Hypothesis(
        kind="directed", route=ROUTE, method="GET", cwe=89, candidate_params=("id",),
        sink_id=SINK, call_path=(CallHop("C.get", "C.java", 70),),
    )


def seed_request_message():
    return {
        "requestHeader": f"GET {BASE}{ROUTE}?id=1 HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n\r\n",
        "requestBody": "",
        "responseHeader": "HTTP/1.1 200 OK\r\n",
        "responseBody": '{"isCarPresent": true}',
    }


def scan_message(param_query, *, rule="40018", probe="present", canary="elx-run-j0", error=True):
    header = f"GET {BASE}{ROUTE}?{param_query} HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
    if probe == "present":
        header += f"X-Elenchus-Probe: {canary}\r\n"
    if rule is not None:
        header += f"X-ZAP-Scan-ID: {rule}\r\n"
    body = "bad SQL grammar; JdbcSQLSyntaxErrorException" if error else '{"isCarPresent": false}'
    return {
        "requestHeader": header + "\r\n",
        "requestBody": "",
        "responseHeader": "HTTP/1.1 200 OK\r\n",
        "responseBody": body,
    }


class FakeZap:
    base_url = "http://127.0.0.1:8090"

    def __init__(self, scan_messages, replay_bodies, hosts=("127.0.0.1",)):
        self._scan_messages = {str(i): m for i, m in enumerate(scan_messages)}
        self._replay_bodies = list(replay_bodies)
        self._hosts = list(hosts)
        self.started_scans = []
        self.removed_context = None
        self.replacer = {}

    def set_option(self, *a): pass
    def ensure_scan_policy(self, *a): pass
    def create_context(self, name, regex): return "7"
    def remove_context(self, name): self.removed_context = name
    def replacer_rules(self): return [{"description": d} for d in self.replacer]
    def add_replacer_request_header(self, description, header, value): self.replacer[description] = value
    def remove_replacer_rule(self, description): self.replacer.pop(description, None)
    def prime_site_tree(self, *a): pass

    def send_request(self, raw_request, follow_redirects=False):
        if "X-ZAP-Scan-ID" not in raw_request and "id=1 " in raw_request or raw_request.endswith("?id=1\r\n\r\n"):
            return seed_request_message()
        if "id=1 HTTP" in raw_request:
            return seed_request_message()
        body = self._replay_bodies.pop(0) if self._replay_bodies else '{"isCarPresent": true}'
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": body}

    def start_scan(self, url, method, post_data, context_id, policy):
        self.started_scans.append(policy)
        return "11"

    def stop_scan(self, scan_id): pass
    def active_scan_status(self, scan_id): return 100
    def scan_message_ids(self, scan_id): return list(self._scan_messages)
    def message(self, message_id): return self._scan_messages[message_id]
    def hosts(self): return self._hosts


def coordinator(fake):
    config = load_config(overrides={"target.base_url": BASE}, environ={"ZAP_API_KEY": "k"})
    return Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))


def run(fake):
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")
    return coordinator(fake).run("run", jobs, ROUTES)


def test_plan_makes_one_job_per_route_with_its_lineage():
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")
    assert len(jobs) == 1
    assert jobs[0].cwes == (89,)
    assert jobs[0].hypothesis_ids == (hypothesis().hypothesis_id,)


def test_reproduced_hit_becomes_one_confirmed_finding_with_lineage():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["JdbcSQLSyntaxErrorException", "JdbcSQLSyntaxErrorException", "ok"],
    )
    result = run(fake)
    sqli = [f for f in result.findings if f.cwe == 89]
    assert len(sqli) == 1
    finding = sqli[0]
    assert (finding.source, finding.cwe, finding.param) == ("dast", 89, "id")
    assert finding.hypothesis_id == hypothesis().hypothesis_id
    assert finding.detail("fired") == 2
    assert finding.detail("hypothesis_ids") == [hypothesis().hypothesis_id]
    assert result.header_propagation_rate == 1.0
    assert result.attribution_rate == 1.0
    assert result.foreign_hosts == []
    assert fake.removed_context == "elenchus-run"


def test_probe_records_rule_and_validation_outcomes_for_each_parameter():
    fake = FakeZap(scan_messages=[scan_message("id=2", error=False)], replay_bodies=[])
    config = load_config(
        overrides={"target.base_url": BASE, "zap.rule_map.89": ["40018"]},
        environ={"ZAP_API_KEY": "k"},
    )
    coord = Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")

    result = coord.run("run", jobs, ROUTES)

    [row] = result.adequacy
    assert row.job_id == "run-j0"
    assert row.expected_rule_ids == ("40018",)
    assert row.observed_rule_ids == ("40018",)
    assert row.baseline_status == 200
    assert row.response_statuses == (200,)
    assert row.passed_validation is True
    assert row.outcome == "adequate"


def test_replay_stack_trace_is_attached_as_adapter_parsed_evidence():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["JdbcSQLSyntaxErrorException"] * 3,
    )
    config = load_config(
        overrides={"target.base_url": BASE, "zap.rule_map.89": ["40018"]},
        environ={"ZAP_API_KEY": "k"},
    )
    frame = {
        "method": "com.example.OrderService.find",
        "file": "src/OrderService.java",
        "line": 88,
        "project": True,
    }
    coord = Coordinator(
        fake,
        config,
        BASE,
        ContextPath("/VulnerableApp", "config"),
        trace_parser=lambda _: [frame],
    )
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")

    result = coord.run("run", jobs, ROUTES)

    [finding] = [item for item in result.findings if item.cwe == 89]
    assert finding.detail("job_pass") == "directed"
    trace = next(item for item in finding.evidence if item.type == "RESPONSE_TRACE")
    assert trace.detail["frames"] == [frame]


def test_hit_that_does_not_reproduce_is_recorded_as_flaky_runtime_evidence():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["ok", "ok", "ok"],  # oracle never fires on replay
    )
    result = run(fake)
    [finding] = [f for f in result.findings if f.cwe == 89]
    assert finding.detail("oracle_flaky") is True
    assert finding.detail("fired") == 0
    assert finding.detail("job_pass") == "directed"


def test_message_without_the_probe_header_is_dropped_from_attribution():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'", probe="absent")],
        replay_bodies=["JdbcSQLSyntaxErrorException"] * 3,
    )
    result = run(fake)
    assert [f for f in result.findings if f.cwe == 89] == []
    assert result.header_propagation_rate == 0.0


def test_two_changed_params_do_not_attribute():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'&extra=2")],
        replay_bodies=["JdbcSQLSyntaxErrorException"] * 3,
    )
    result = run(fake)
    assert [f for f in result.findings if f.cwe == 89] == []
    assert result.attribution_rate == 0.0  # one considered, none attributed


def test_blocked_baseline_skips_the_scan():
    class Blocked(FakeZap):
        def send_request(self, raw_request, follow_redirects=False):
            if "X-Elenchus" not in raw_request and follow_redirects is False and not self.started_scans:
                return {"responseHeader": "HTTP/1.1 403 Forbidden\r\n", "responseBody": ""}
            return {"responseHeader": "HTTP/1.1 403 Forbidden\r\n", "responseBody": ""}

    fake = Blocked(scan_messages=[scan_message("id=1'")], replay_bodies=[])
    result = run(fake)
    assert result.findings == []
    assert result.jobs[0].outcome == "all_blocked"
    assert fake.started_scans == []
    assert result.adequacy[0].outcome == "blocked_by_validation"
    assert result.adequacy[0].sub_code == "auth"
    assert result.adequacy[0].baseline_status == 403


def test_foreign_host_in_history_is_reported():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["JdbcSQLSyntaxErrorException"] * 3,
        hosts=["127.0.0.1", "evil.example"],
    )
    result = run(fake)
    assert result.foreign_hosts == ["evil.example"]


def test_header_findings_come_from_the_baseline():
    # The fake baseline carries no security headers: one finding per missing
    # protection, deduped per app.
    fake = FakeZap(scan_messages=[scan_message("id=1'")], replay_bodies=["x"] * 3)
    result = run(fake)
    assert sorted(f.cwe for f in result.findings if f.cwe in (693, 1021)) == [693, 1021]


def test_zero_budget_skips_every_job():
    fake = FakeZap(scan_messages=[scan_message("id=1'")], replay_bodies=[])
    config = load_config(
        overrides={"target.base_url": BASE, "probe.stage_budget_seconds.zap_jobs": 0},
        environ={"ZAP_API_KEY": "k"},
    )
    coord = Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")
    result = coord.run("run", jobs, ROUTES)
    assert [f for f in result.findings if f.cwe == 89] == []
    assert len(result.jobs_skipped) == 1
    assert result.jobs[0].outcome == "skipped_budget"
    assert fake.started_scans == []


def test_auth_header_is_carried_on_every_request(monkeypatch):
    monkeypatch.setenv("ELX_TEST_TOKEN", "Bearer t")
    config = load_config(
        overrides={
            "target.base_url": BASE,
            "target.auth.header_name": "Authorization",
            "target.auth.value_env": "ELX_TEST_TOKEN",
        },
        environ={"ZAP_API_KEY": "k"},
    )
    coord = Coordinator(FakeZap([], []), config, BASE, ContextPath("/VulnerableApp", "config"))
    assert coord._auth == ("Authorization", "Bearer t")
    raw = coord._raw(SeedRequest(url=f"{BASE}/x?id=1", method="GET"))
    assert "Authorization: Bearer t" in raw


def test_auth_header_requires_its_env_var():
    config = load_config(
        overrides={
            "target.base_url": BASE,
            "target.auth.header_name": "Authorization",
            "target.auth.value_env": "ELX_MISSING_TOKEN",
        },
        environ={"ZAP_API_KEY": "k"},
    )
    try:
        Coordinator(FakeZap([], []), config, BASE, ContextPath("/VulnerableApp", "config"))
    except ValueError:
        return
    raise AssertionError("expected a ValueError when the auth env var is empty")
