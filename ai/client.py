"""An OpenAI-compatible chat client for the advisory side channel.

The client is safe by construction: when the task is off (`ai.enabled` and the
per-task switch), when credentials are absent, or when the per-run call budget
(`ai.max_calls`) is spent, `complete` returns None and makes no network call.
Every response is parsed as JSON and validated against the task's schema; a
response that fails validation is dropped (returns None). Results are cached by
the content hash of (task, model, prompt), so a repeated prompt costs nothing.

The HTTP transport is injectable so tests never touch the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from ai.schema import valid
from common.config import Config

Transport = Callable[[str, list[dict[str, str]]], str]
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024


class AiClient:
    def __init__(
        self,
        config: Config,
        environ: Mapping[str, str] = os.environ,
        transport: Transport | None = None,
    ) -> None:
        self.config = config
        self.model = environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self._api_key = environ.get("OPENAI_API_KEY", "")
        self._max_calls = int(config["ai.max_calls"])
        self._transport = transport or self._http
        self._cache: dict[str, dict[str, Any] | None] = {}
        self.calls = 0
        self.skips: dict[str, int] = {}

    def available(self, task: str) -> bool:
        """The task is on and the client can make a call. No network here."""
        return bool(self.config.task_enabled(task)) and bool(self._api_key)

    def complete(
        self, task: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not self.config.task_enabled(task):
            return self._skip("disabled")
        if not self._api_key:
            return self._skip("no_credentials")
        cache_key = self._cache_key(task, prompt)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if self.calls >= self._max_calls:
            return self._skip("budget_exhausted")
        self.calls += 1
        result = self._call(task, prompt, schema)
        self._cache[cache_key] = result
        return result

    def _call(self, task: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any] | None:
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ]
        try:
            content = self._transport(self.model, messages)
            payload = json.loads(content)
        except (OSError, ValueError, RuntimeError):
            return self._skip("call_failed")
        if not valid(payload, schema):
            return self._skip("schema_invalid")
        return payload

    def _http(self, model: str, messages: list[dict[str, str]]) -> str:
        body = json.dumps(
            {
                "model": model,
                "messages": messages,
                "temperature": 0,
                "response_format": {"type": "json_object"},
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(_MAX_RESPONSE_BYTES)
        data = json.loads(raw)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("AI response had no choices")
        return choices[0]["message"]["content"]

    def _skip(self, reason: str) -> None:
        self.skips[reason] = self.skips.get(reason, 0) + 1

    def _cache_key(self, task: str, prompt: str) -> str:
        digest = hashlib.sha256(f"{task}\0{self.model}\0{prompt}".encode()).hexdigest()
        return digest[:32]


_SYSTEM = (
    "You are an advisory assistant for a security scanner. Reply only with a JSON "
    "object that matches the requested shape. You never decide whether a finding "
    "is real; your text is advisory and is checked before use."
)
