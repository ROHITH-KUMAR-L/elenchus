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
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from ai.schema import valid
from common.config import Config

Transport = Callable[[str, list[dict[str, str]]], str]
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
_USER_AGENT = "elenchus/0.1 (+https://github.com/ROHITH-KUMAR-L/elenchus)"
_HTTP_ATTEMPTS = 3
_HTTP_BACKOFF_SECONDS = 0.5
_RETRY_STATUS = frozenset({403, 408, 409, 425, 429, 500, 502, 503, 504})
# Groq (an OpenAI-compatible endpoint) is the provider. LLM_* is the
# provider-neutral fallback. Add a prefix here to support another provider's
# native variable names.
_ENV_PREFIXES = ("GROQ", "LLM")


def _env(environ: Mapping[str, str], suffix: str) -> str:
    """The first set value among <PREFIX>_<suffix> for the known providers."""
    for prefix in _ENV_PREFIXES:
        value = environ.get(f"{prefix}_{suffix}")
        if value:
            return value
    return ""


class AiClient:
    def __init__(
        self,
        config: Config,
        environ: Mapping[str, str] = os.environ,
        transport: Transport | None = None,
    ) -> None:
        self.config = config
        # The endpoint, key and model come only from the environment (set via .env
        # or docker run -e). Nothing is hardcoded: when any is missing the client is
        # unavailable and AI is simply off, so the feature is optional. The provider
        # is Groq (an OpenAI-compatible endpoint); GROQ_* names are checked first,
        # then the generic LLM_* fallback.
        self.model = _env(environ, "MODEL")
        self.base_url = _env(environ, "BASE_URL").rstrip("/")
        self._api_key = _env(environ, "API_KEY")
        self._max_calls = int(config["ai.max_calls"])
        self._transport = transport or self._default_transport()
        self._cache: dict[str, dict[str, Any] | None] = {}
        self.calls = 0
        self.skips: dict[str, int] = {}
        self.last_error: str | None = None  # the most recent transport failure, for diagnostics

    def configured(self) -> bool:
        """The endpoint, key and model are all set in the environment."""
        return bool(self._api_key and self.base_url and self.model)

    def available(self, task: str) -> bool:
        """The task is on and the client can make a call. No network here."""
        return bool(self.config.task_enabled(task)) and self.configured()

    def complete(
        self, task: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not self.config.task_enabled(task):
            return self._skip("disabled")
        if not self.configured():
            return self._skip("not_configured")
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
        except (OSError, ValueError, RuntimeError) as error:
            self.last_error = f"{type(error).__name__}: {error}"
            return self._skip("call_failed")
        if not valid(payload, schema):
            return self._skip("schema_invalid")
        return payload

    def _default_transport(self) -> Transport:
        """Prefer the OpenAI SDK transport (httpx, HTTP/2) when installed — it reaches
        providers whose WAF blocks plain urllib — and fall back to urllib otherwise."""
        try:
            import openai  # noqa: F401
        except ImportError:
            return self._http
        return self._sdk

    def _sdk(self, model: str, messages: list[dict[str, str]]) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self._api_key, base_url=self.base_url, max_retries=_HTTP_ATTEMPTS)
        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
        )
        content = completion.choices[0].message.content
        if not content:
            raise RuntimeError("AI response had no content")
        return content

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
                # Some providers front their API with a WAF (Cloudflare) that blocks
                # the default Python-urllib agent (HTTP 403, Cloudflare code 1010).
                # A conventional product agent passes.
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
            },
            method="POST",
        )
        raw = self._send_with_retry(request)
        data = json.loads(raw)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("AI response had no choices")
        return choices[0]["message"]["content"]

    def _send_with_retry(self, request: urllib.request.Request) -> bytes:
        """Send the request, retrying a transient WAF, rate-limit or server error a
        few times with a short backoff. A WAF (Cloudflare 1010) and rate limits are
        intermittent, so one edge rejection should not fail the whole call."""
        last: Exception | None = None
        for attempt in range(_HTTP_ATTEMPTS):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.read(_MAX_RESPONSE_BYTES)
            except urllib.error.HTTPError as error:
                detail = error.read(_MAX_RESPONSE_BYTES).decode("utf-8", "replace").strip()
                last = RuntimeError(f"HTTP {error.code} from {self.base_url}: {detail[:300]}")
                if error.code not in _RETRY_STATUS:
                    raise last from error
            except urllib.error.URLError as error:
                last = RuntimeError(f"network error reaching {self.base_url}: {error.reason}")
            if attempt + 1 < _HTTP_ATTEMPTS:
                time.sleep(_HTTP_BACKOFF_SECONDS * (attempt + 1))
        raise last if last is not None else RuntimeError("AI request failed")

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
