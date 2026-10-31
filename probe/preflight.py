"""Stage 0 preflight: the loopback guard and context-path detection.

The target base URL is the only required input. The servlet context path is
detected, never guessed silently: read from the source config first, then the
base URL's own path, and if neither yields one the caller is told so.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from common.record import LOCALHOST_NAMES

_PROPERTY_FILES = ("application.properties", "application.yml", "application.yaml")
_PROPERTIES_KEY = re.compile(r"^\s*server\.servlet\.context-path\s*[=:]\s*(\S+)\s*$")


class NotLoopbackError(ValueError):
    """The target is not on loopback. Scanning anything else is disqualification."""


@dataclass(frozen=True)
class ContextPath:
    value: str
    source: str  # "config", "base_url" or "none"


def check_loopback(base_url: str) -> None:
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or parts.hostname not in LOCALHOST_NAMES:
        raise NotLoopbackError(f"target must be an http(s) URL on localhost, got {base_url!r}")


def _normalise(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    if value and not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/")


def context_path_from_source(source_path: str | Path) -> str | None:
    """server.servlet.context-path from the first config file that sets it."""
    root = Path(source_path)
    for path in sorted(root.rglob("*")):
        if path.name not in _PROPERTY_FILES or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = _PROPERTIES_KEY.match(line)
            if match:
                return _normalise(match.group(1))
    return None


def detect_context_path(source_path: str | Path, base_url: str) -> ContextPath:
    from_source = context_path_from_source(source_path)
    if from_source is not None:
        return ContextPath(from_source, "config")
    from_url = urlsplit(base_url).path.rstrip("/")
    if from_url:
        return ContextPath(from_url, "base_url")
    return ContextPath("", "none")


# Known framework error-page and server signatures worth recording. Best effort:
# a hit tells a human what stack the target runs; it never feeds scanner logic.
_ERROR_SIGNATURES = (
    "Whitelabel Error Page",
    "Apache Tomcat",
    "HTTP Status 404",
    "There was an unexpected error",
    "nginx",
    "Jetty",
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class _SendsRequests(Protocol):
    def send_request(self, raw_request: str, follow_redirects: bool = ...) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PreflightExtras:
    """Advisory fingerprints gathered before scanning: the Server banner and the
    error-page signature. All fields are optional; nothing here is a verdict."""

    exposed: bool
    server_banner: str | None = None
    error_status: int | None = None
    error_signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "exposed": self.exposed,
            "server_banner": self.server_banner,
            "error_status": self.error_status,
            "error_signature": self.error_signature,
        }


def probe_extras(api: _SendsRequests, base_url: str) -> PreflightExtras:
    """Best-effort preflight probes over the loopback target: the server banner
    and an error-page fingerprint from a random missing path. Skips cleanly when
    the target does not answer, so it never aborts a run."""
    base = _get(api, base_url)
    if base is None:
        return PreflightExtras(exposed=False)
    banner = _header_value(base.get("responseHeader", ""), "Server")
    error_url = f"{base_url.rstrip('/')}/elx-missing-{secrets.token_hex(6)}"
    error = _get(api, error_url)
    if error is None:
        return PreflightExtras(exposed=True, server_banner=banner)
    return PreflightExtras(
        exposed=True,
        server_banner=banner,
        error_status=_status(error.get("responseHeader", "")),
        error_signature=_fingerprint(error.get("responseBody", "")),
    )


def _get(api: _SendsRequests, url: str) -> dict[str, Any] | None:
    host = urlsplit(url).netloc
    raw = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    try:
        message = api.send_request(raw, follow_redirects=False)
    except (RuntimeError, OSError):
        return None
    return message if isinstance(message, dict) else None


def _header_value(response_header: str, name: str) -> str | None:
    for line in response_header.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == name.casefold():
            return value.strip() or None
    return None


def _status(response_header: str) -> int | None:
    match = re.match(r"HTTP/\S+\s+(\d{3})", response_header)
    return int(match.group(1)) if match else None


def _fingerprint(body: str) -> str | None:
    for signature in _ERROR_SIGNATURES:
        if signature.casefold() in body.casefold():
            return signature
    title = _TITLE.search(body)
    if title:
        text = " ".join(title.group(1).split())
        if text:
            return text[:120]
    return None
