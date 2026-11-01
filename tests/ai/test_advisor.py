"""Advisory AI attaches text only: verdicts, links and confidence never change."""

from __future__ import annotations

from dataclasses import replace

from ai.advisor import annotate, summarise_report
from ai.client import AiClient
from common.config import load_config
from common.record import SinkId
from engine.correlate.models import Issue

SINK = SinkId("A.java", "A.m", 10, 1)


def issue(**overrides) -> Issue:
    base = {
        "issue_key": "k", "label": "Confirmed", "cwe": 89, "type": "SQL Injection",
        "severity": "high", "risk_score": 85.0, "link_status": "unique",
        "link_origin": "directed", "confidence": 0.95, "route": "/a", "method": "GET",
        "param": "id", "sink": SINK, "file": "A.java", "line": 10,
        "link_reason": "Directed hypothesis fired.",
    }
    base.update(overrides)
    return Issue(**base)


def test_annotate_is_a_no_op_when_the_client_is_none():
    issues = [issue()]
    assert annotate(issues, None) == issues


def test_annotate_adds_text_without_changing_the_verdict():
    original = issue()
    client = AiClient(
        load_config(
            overrides={"ai.enabled": True, "ai.tasks.fix_text.enabled": True,
                       "ai.tasks.link_explanation.enabled": True},
            environ={},
        ),
        environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"},
        transport=lambda model, messages: (
            '{"fix": "Use a parameterised query."}'
            if "fix" in messages[1]["content"]
            else '{"explanation": "The probe lineage matched this sink."}'
        ),
    )
    [annotated] = annotate([original], client)
    assert annotated.ai_notes == {
        "fix": "Use a parameterised query.",
        "explanation": "The probe lineage matched this sink.",
    }
    # Everything that decides the verdict is byte-identical.
    assert replace(annotated, ai_notes=None) == original


def test_disabled_tasks_leave_issues_untouched_and_make_no_call():
    calls = []

    def transport(model, messages):
        calls.append(messages)
        return '{"fix": "x"}'

    client = AiClient(load_config(environ={}), environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"}, transport=transport)
    [annotated] = annotate([issue()], client)
    assert annotated.ai_notes is None
    assert calls == []


def test_summarise_report_is_none_without_a_client():
    assert summarise_report([issue()], None) is None


def test_summarise_report_returns_the_ai_text_when_the_task_is_on():
    client = AiClient(
        load_config(overrides={"ai.enabled": True, "ai.tasks.report_summary.enabled": True}, environ={}),
        environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"},
        transport=lambda model, messages: '{"summary": "One Confirmed SQL injection; fix it first."}',
    )
    assert summarise_report([issue()], client) == "One Confirmed SQL injection; fix it first."


def test_summarise_report_is_none_when_the_task_is_off():
    client = AiClient(
        load_config(environ={}),  # ai.enabled defaults off
        environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"},
        transport=lambda model, messages: '{"summary": "should not be produced"}',
    )
    assert summarise_report([issue()], client) is None


def test_link_explanation_is_skipped_for_unlinked_issues():
    client = AiClient(
        load_config(overrides={"ai.enabled": True, "ai.tasks.link_explanation.enabled": True}, environ={}),
        environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"},
        transport=lambda model, messages: '{"explanation": "should not appear"}',
    )
    code_only = issue(label="Code-only", link_status=None, link_origin=None, confidence=None)
    [annotated] = annotate([code_only], client)
    assert annotated.ai_notes is None
