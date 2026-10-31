"""Stage 0 preflight: the loopback guard and context-path detection.

The target base URL is the only required input. The servlet context path is
detected, never guessed silently: read from the source config first, then the
base URL's own path, and if neither yields one the caller is told so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
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
