"""The with/without harness over real correlation + advisory annotation: the
advisory tasks attach text only, so correct and wrong links never change."""

from __future__ import annotations

from ai.advisor import annotate
from ai.client import AiClient
from ai.harness import with_without
from common.config import load_config
from common.pipeline import hypothesis_id
from common.record import Finding, SinkId
from engine.correlate import correlate

ROUTE = "/orders/{id}"
SINK = {"file": "src/OrderService.java", "enclosing_method": "OrderService.find",
        "start_line": 88, "start_col": 20}
PAIRS = {"pairs": [{"route": ROUTE, "method": "GET", "params": ["id"], "cwe": 89,
                    "file": "src/OrderService.java", "line": 88}]}


def lineage():
    return hypothesis_id("directed", ROUTE, "GET", 89, SinkId.from_value(SINK), ("id",))


def static_finding():
    return Finding.from_dict({
        "run_id": "r", "source": "sast", "provenance": "own", "cwe": 89, "type": "SQL Injection",
        "route": ROUTE, "method": "GET", "file": SINK["file"], "line": 88, "sink_id": SINK,
        "arg_shape": "dynamic", "candidate_params": ["id"], "severity": "high",
        "entry_paths": [{"route": ROUTE, "method": "GET", "hops": 0,
                         "call_chain": [{"method": "OrderService.find", "file": SINK["file"], "line": 88}]}],
        "evidence": [{"type": "PATH", "detail": {"snippet": "q(...)"}}],
    })


def probe_finding():
    return Finding.from_dict({
        "run_id": "r", "source": "dast", "provenance": "zap", "cwe": 89, "type": "SQL Injection",
        "route": ROUTE, "method": "GET", "param": "id", "payload": "1'", "hypothesis_id": lineage(),
        "evidence": [{"type": "ORACLE", "detail": {"oracle": "sql_error",
                     "hypothesis_ids": [lineage()], "fired": 3, "replays": 3}}],
    })


def test_advisory_ai_shows_no_link_regression():
    findings = [static_finding(), probe_finding()]

    def runner(ai_enabled):
        overrides = {"ai.enabled": True, "ai.tasks.fix_text.enabled": True,
                     "ai.tasks.link_explanation.enabled": True} if ai_enabled else {}
        config = load_config(overrides=overrides, environ={})
        issues = correlate(findings, config)
        if not ai_enabled:
            return issues
        client = AiClient(config, environ={"OPENAI_API_KEY": "k"},
                          transport=lambda m, msg: '{"fix": "x"}' if "fix" in msg[1]["content"]
                          else '{"explanation": "y"}')
        return annotate(issues, client)

    result = with_without(runner, PAIRS)
    assert not result.regressed
    assert result.with_ai.correct_links == result.without_ai.correct_links == 1
    assert result.with_ai.wrong_links == 0
