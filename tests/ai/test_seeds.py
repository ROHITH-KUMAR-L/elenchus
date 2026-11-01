"""Advisory DTO seed proposal with repair. Off by default; the oracle still decides."""

from __future__ import annotations

from ai.client import AiClient
from ai.seeds import propose_seed
from common.config import load_config


def seed_client(replies, enabled=True):
    overrides = {"ai.enabled": True, "ai.tasks.dto_seeds.enabled": True} if enabled else {}
    config = load_config(overrides=overrides, environ={})
    queue = list(replies)

    def transport(model, messages):
        return queue.pop(0)

    return AiClient(config, environ={"LLM_API_KEY": "k", "LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_MODEL": "m"}, transport=transport)


def test_disabled_task_returns_none():
    client = seed_client(['{"params": {"name": "a"}}'], enabled=False)
    assert propose_seed(client, "/x", ["name"], lambda p: True) is None


def test_valid_proposal_is_returned():
    client = seed_client(['{"params": {"name": "alice", "age": "1"}}'])
    result = propose_seed(client, "/x", ["name", "age"], lambda p: True)
    assert result == {"name": "alice", "age": "1"}


def test_repair_retries_until_a_proposal_validates():
    client = seed_client(
        ['{"params": {"name": "bad"}}', '{"params": {"name": "good"}}'],
    )
    result = propose_seed(client, "/x", ["name"], lambda p: p["name"] == "good", max_repairs=3)
    assert result == {"name": "good"}
    assert client.calls == 2


def test_gives_up_after_the_repair_budget():
    client = seed_client(['{"params": {"name": "no"}}'] * 3)
    result = propose_seed(client, "/x", ["name"], lambda p: False, max_repairs=3)
    assert result is None
    # The 2nd and 3rd repair prompts are identical, so the 3rd is served from the
    # content-hash cache: three attempts, two network calls.
    assert client.calls == 2


def test_missing_fields_count_as_a_failed_attempt():
    client = seed_client(['{"params": {}}', '{"params": {"name": "ok"}}'])
    result = propose_seed(client, "/x", ["name"], lambda p: True, max_repairs=2)
    assert result == {"name": "ok"}
