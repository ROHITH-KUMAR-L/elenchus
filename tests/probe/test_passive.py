"""Passive-alert ingestion: advisory only, never changing a verdict."""

from __future__ import annotations

from probe.coordinator import plan_directed_jobs
from probe.passive import ingest
from tests.probe.test_coordinator import ROUTES, FakeZap, coordinator, hypothesis, scan_message

PASSIVE = {"pluginId": "10038", "alert": "CSP header not set", "risk": "Medium",
           "url": "http://127.0.0.1:9090/x", "param": "", "cweid": "693"}
ACTIVE = {"pluginId": "40018", "alert": "SQL Injection", "risk": "High",
          "url": "http://127.0.0.1:9090/y", "param": "id", "cweid": "89"}


def test_ingest_keeps_passive_drops_active_and_deduplicates():
    advisory = ingest([PASSIVE, ACTIVE, dict(PASSIVE)], active_rule_ids={"40018", "40019"})
    assert len(advisory) == 1
    assert advisory[0].plugin_id == "10038"
    assert advisory[0].cwe == 693
    assert advisory[0].to_dict()["advisory"] is True


def test_ingest_drops_alerts_without_a_plugin_id():
    assert ingest([{"alert": "no plugin"}], active_rule_ids=set()) == []


class AlertZap(FakeZap):
    def __init__(self, *args, alerts_list=(), **kwargs):
        super().__init__(*args, **kwargs)
        self._alerts = list(alerts_list)

    def alerts(self, base_url):
        return self._alerts


def run_with(alerts_list):
    fake = AlertZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["JdbcSQLSyntaxErrorException", "JdbcSQLSyntaxErrorException", "ok"],
        alerts_list=alerts_list,
    )
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")
    return coordinator(fake).run("run", jobs, ROUTES)


def test_coordinator_stores_advisory_alerts_without_changing_findings():
    with_alerts = run_with([PASSIVE, ACTIVE])
    without_alerts = run_with([])
    # The passive alert is stored; the active-rule alert is dropped.
    assert [a["plugin_id"] for a in with_alerts.advisory_alerts] == ["10038"]
    assert without_alerts.advisory_alerts == []
    # Verdicts (findings) are identical with and without the advisory alerts.
    assert [f.to_dict() for f in with_alerts.findings] == [
        f.to_dict() for f in without_alerts.findings
    ]


def test_coordinator_without_an_alerts_method_skips_cleanly():
    fake = FakeZap(
        scan_messages=[scan_message("id=1'")],
        replay_bodies=["JdbcSQLSyntaxErrorException", "JdbcSQLSyntaxErrorException", "ok"],
    )
    jobs = plan_directed_jobs([hypothesis()], ROUTES, "run")
    result = coordinator(fake).run("run", jobs, ROUTES)
    assert result.advisory_alerts == []
