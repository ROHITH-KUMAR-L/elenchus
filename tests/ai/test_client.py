"""The AI client is safe by construction: off, no creds or over budget -> no call."""

from __future__ import annotations

from ai.client import AiClient
from common.config import load_config

SCHEMA = {"type": "object", "required": ["text"], "properties": {"text": {"type": "string"}}}


def enabled_config(max_calls=30):
    return load_config(
        overrides={"ai.enabled": True, "ai.tasks.fix_text.enabled": True, "ai.max_calls": max_calls},
        environ={},
    )


class Counter:
    def __init__(self, reply='{"text": "advice"}'):
        self.reply = reply
        self.calls = 0

    def __call__(self, model, messages):
        self.calls += 1
        return self.reply


def test_groq_variables_configure_the_client():
    client = AiClient(
        enabled_config(),
        environ={
            "GROQ_API_KEY": "gsk_x",
            "GROQ_BASE_URL": "https://api.groq.com/openai/v1",
            "GROQ_MODEL": "llama-3.3-70b-versatile",
        },
    )
    assert client.configured()
    assert client.base_url == "https://api.groq.com/openai/v1"
    assert client.model == "llama-3.3-70b-versatile"


def test_generic_llm_variables_configure_the_client():
    client = AiClient(
        enabled_config(),
        environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"},
    )
    assert client.configured()


def test_openai_variables_take_precedence_over_groq():
    client = AiClient(
        enabled_config(),
        environ={
            "OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "openai-model",
            "GROQ_API_KEY": "gsk_x", "GROQ_BASE_URL": "https://api.groq.com/openai/v1", "GROQ_MODEL": "groq-model",
        },
    )
    assert client.model == "openai-model"


def test_disabled_task_makes_no_call():
    transport = Counter()
    client = AiClient(load_config(environ={}), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "prompt", SCHEMA) is None
    assert transport.calls == 0
    assert client.skips["disabled"] == 1


def test_enabled_without_configuration_makes_no_call():
    # No OPENAI_* in the environment: the client is unconfigured and AI is simply
    # off, even with the task switched on. Nothing is hardcoded as a fallback.
    transport = Counter()
    client = AiClient(enabled_config(), environ={}, transport=transport)
    assert not client.available("fix_text")
    assert not client.configured()
    assert client.complete("fix_text", "prompt", SCHEMA) is None
    assert transport.calls == 0
    assert client.skips["not_configured"] == 1


def test_enabled_call_returns_validated_json():
    transport = Counter()
    client = AiClient(enabled_config(), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "prompt", SCHEMA) == {"text": "advice"}
    assert transport.calls == 1
    assert client.calls == 1


def test_repeated_prompt_is_cached():
    transport = Counter()
    client = AiClient(enabled_config(), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    client.complete("fix_text", "same", SCHEMA)
    client.complete("fix_text", "same", SCHEMA)
    assert transport.calls == 1


def test_budget_caps_the_number_of_calls():
    transport = Counter()
    client = AiClient(enabled_config(max_calls=1), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "one", SCHEMA) == {"text": "advice"}
    assert client.complete("fix_text", "two", SCHEMA) is None
    assert transport.calls == 1
    assert client.skips["budget_exhausted"] == 1


def test_schema_invalid_response_is_dropped():
    transport = Counter(reply='{"wrong": 1}')
    client = AiClient(enabled_config(), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "prompt", SCHEMA) is None
    assert client.skips["schema_invalid"] == 1


def test_non_json_response_is_dropped():
    transport = Counter(reply="not json")
    client = AiClient(enabled_config(), environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "prompt", SCHEMA) is None
    assert client.skips["call_failed"] == 1


def test_judging_profile_keeps_the_client_disabled():
    config = load_config(
        overrides={"judging.profile": True, "ai.enabled": True, "ai.tasks.fix_text.enabled": True},
        environ={},
    )
    transport = Counter()
    client = AiClient(config, environ={"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}, transport=transport)
    assert client.complete("fix_text", "prompt", SCHEMA) is None
    assert transport.calls == 0
