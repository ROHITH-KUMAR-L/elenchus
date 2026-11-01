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
import importlib.util
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ai.schema import valid
from common.config import Config

Transport = Callable[[str, list[dict[str, str]]], str]
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
_USER_AGENT = "elenchus/0.1 (+https://github.com/ROHITH-KUMAR-L/elenchus)"
_HTTP_ATTEMPTS = 3
_HTTP_BACKOFF_SECONDS = 0.5
_RETRY_STATUS = frozenset({403, 408, 409, 425, 429, 500, 502, 503, 504})
_MAX_TOKENS = 2048  # headroom so a longer reply (e.g. the summary) is not truncated to invalid JSON


@dataclass(frozen=True)
class _Provider:
    """One OpenAI-compatible provider. Only the API key must be set; the base URL
    and model have a working free default that <PREFIX>_BASE_URL / <PREFIX>_MODEL
    override. `groq_sdk` picks the Groq SDK transport (httpx, past the WAF)."""

    name: str
    prefix: str
    base_url: str
    model: str
    groq_sdk: bool = False


# Resolution order: the first provider whose <PREFIX>_API_KEY is set wins, so Groq
# is primary and OpenRouter then NVIDIA NIM are fallbacks. LLM_* is a generic
# final fallback for any other OpenAI-compatible endpoint. Models are current
# free-tier choices; override any with <PREFIX>_MODEL.
_PROVIDERS = (
    _Provider("groq", "GROQ", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", groq_sdk=True),
    _Provider(
        "openrouter", "OPENROUTER",
        "https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct:free",
    ),
    _Provider(
        "nvidia", "NVIDIA",
        "https://integrate.api.nvidia.com/v1", "meta/llama-3.3-70b-instruct",
    ),
    _Provider("generic", "LLM", "", ""),
)


def _loads_lenient(content: str) -> Any:
    """Parse JSON, tolerating a model that wrapped it in prose or ```json fences.
    Falls back to the outermost {...} span. Raises ValueError if none parses, which
    _call treats as a failed call."""
    try:
        return json.loads(content)
    except ValueError:
        pass
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :] if "{" in text else text
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        return json.loads(text[start : end + 1])
    raise ValueError("no JSON object in the response")


def _resolve_provider(environ: Mapping[str, str]) -> tuple[_Provider | None, str, str, str]:
    """The first provider in order whose <PREFIX>_API_KEY is set, with its base URL
    and model (env override, else the provider default). Returns (provider, api_key,
    base_url, model); provider is None when no key is set anywhere."""
    for provider in _PROVIDERS:
        key = environ.get(f"{provider.prefix}_API_KEY") or ""
        if not key:
            continue
        base_url = (environ.get(f"{provider.prefix}_BASE_URL") or provider.base_url).rstrip("/")
        model = environ.get(f"{provider.prefix}_MODEL") or provider.model
        return provider, key, base_url, model
    return None, "", "", ""


class AiClient:
    def __init__(
        self,
        config: Config,
        environ: Mapping[str, str] = os.environ,
        transport: Transport | None = None,
    ) -> None:
        self.config = config
        # The provider, key, endpoint and model come only from the environment (set
        # via .env or docker run -e). Nothing is hardcoded as a key: when no provider
        # key is set the client is unavailable and AI is simply off. Groq is primary,
        # then OpenRouter, then NVIDIA NIM; LLM_* is a generic override.
        self._provider, self._api_key, self.base_url, self.model = _resolve_provider(environ)
        self._max_calls = int(config["ai.max_calls"])
        self._transport = transport or self._default_transport()
        self._cache: dict[str, dict[str, Any] | None] = {}
        self.calls = 0
        self.skips: dict[str, int] = {}
        self.last_error: str | None = None  # the most recent transport failure, for diagnostics

    @property
    def provider_name(self) -> str:
        """The resolved provider's name, or 'none' when no key is set."""
        return self._provider.name if self._provider is not None else "none"

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
        result = self._call(prompt, schema)
        self._cache[cache_key] = result
        return result

    def _call(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any] | None:
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ]
        try:
            content = self._transport(self.model, messages)
            payload = _loads_lenient(content)
        except (OSError, ValueError, RuntimeError) as error:
            self.last_error = f"{type(error).__name__}: {error}"
            return self._skip("call_failed")
        if not valid(payload, schema):
            return self._skip("schema_invalid")
        return payload

    def _default_transport(self) -> Transport:
        """Use the Groq SDK (httpx, HTTP/2, past Groq's WAF) only for the Groq
        provider when it is installed. Every other OpenAI-compatible provider
        (OpenRouter, NVIDIA NIM, a generic endpoint) goes through urllib, which
        targets an arbitrary base URL correctly."""
        if self._provider is not None and self._provider.groq_sdk and importlib.util.find_spec("groq"):
            return self._sdk
        return self._http

    def _sdk(self, model: str, messages: list[dict[str, str]]) -> str:
        from groq import Groq

        # The Groq SDK appends /openai/v1 itself and also reads GROQ_BASE_URL from the
        # environment. Pass an explicit base with that suffix stripped, so the URL is
        # not doubled (POST /openai/v1/openai/v1/...).
        base_url = self.base_url.removesuffix("/openai/v1") or "https://api.groq.com"
        client = Groq(api_key=self._api_key, base_url=base_url, max_retries=_HTTP_ATTEMPTS)

        def create(strict_json: bool) -> str:
            params: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": _MAX_TOKENS,
            }
            if strict_json:
                params["response_format"] = {"type": "json_object"}
            completion = client.chat.completions.create(**params)
            content = completion.choices[0].message.content
            if not content:
                raise RuntimeError("AI response had no content")
            return content

        # Any SDK error (auth, 400 strict-JSON validation, rate limit) becomes a
        # RuntimeError so _call handles it gracefully instead of crashing the CLI.
        # Some models fail strict JSON mode; retry once in free mode, then _call
        # parses the JSON leniently out of the text.
        try:
            return create(strict_json=True)
        except Exception as strict_error:  # noqa: BLE001 - normalise every SDK error
            try:
                return create(strict_json=False)
            except Exception as error:
                raise RuntimeError(f"Groq SDK error: {type(error).__name__}: {error}") from error
            finally:
                self.last_error = f"strict JSON mode failed: {strict_error}"

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
