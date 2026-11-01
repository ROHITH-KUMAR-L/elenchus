"""Verify the AI side-channel credentials without running a scan.

Reads the base URL, key and model from the environment (or .env via your shell),
reports whether the client is configured and the task is enabled, and — only when
configured — makes one real minimal call to the endpoint and reports success,
latency and any error. No scan, no target, no ZAP.

The provider is Groq (an OpenAI-compatible endpoint). The variables are checked in
order: GROQ_*, then the generic LLM_* (BASE_URL, API_KEY, MODEL):

    GROQ_BASE_URL=https://api.groq.com/openai/v1 GROQ_API_KEY=gsk_... \
        GROQ_MODEL=llama-3.3-70b-versatile \
        uv run --locked python scripts/ai_check.py

Exit code 0 when a live call succeeds (or AI is intentionally off), 1 otherwise.
"""

from __future__ import annotations

import time

from ai.client import AiClient
from common.config import load_config

_TASK = "catalogue_proposer"
_PING_SCHEMA = {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}
_PING_PROMPT = 'Reply only with the JSON object {"ok": true}.'


def main() -> int:
    # Enable AI for the check itself so `available()` reflects credentials, not the
    # default-off switch. A real scan still needs ai.enabled in its own config.
    config = load_config(
        overrides={"ai.enabled": True, f"ai.tasks.{_TASK}.enabled": True}, environ={}
    )
    client = AiClient(config)

    print(f"endpoint : {client.base_url or '(no *_BASE_URL set)'}")
    print(f"model    : {client.model or '(no *_MODEL set)'}")
    print(f"api key  : {'set' if client._api_key else '(no *_API_KEY set)'}")
    print(f"configured: {client.configured()}")

    if not client.configured():
        print(
            "\nAI is not configured. Set the base URL, key and model via GROQ_* "
            "or LLM_* (BASE_URL, API_KEY, MODEL)."
        )
        print("This is a valid state: the AI features are optional and simply stay off.")
        return 0

    print("\nMaking one minimal live call...")
    start = time.monotonic()
    result = client.complete(_TASK, _PING_PROMPT, _PING_SCHEMA)
    elapsed = time.monotonic() - start

    if result is not None and result.get("ok") is True:
        print(f"OK: endpoint reachable and credentials valid ({elapsed:.2f}s).")
        return 0
    reason = next(iter(client.skips), "no_valid_response")
    print(f"FAILED ({elapsed:.2f}s): {reason}.")
    print("Check the key, base URL (must end in /v1 for OpenAI-compatible APIs) and model name.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
