"""Session manager: mint a session token from a login flow and carry it on probes.

When `target.auth.login_url` is set, the coordinator probes that localhost URL once
before scanning and reads a session token out of the response — a `Set-Cookie`, a
JSON field or a response header. The token becomes the `(header_name, value)` pair
the coordinator already carries on every request through the Replacer seam (the
same path the static `target.auth.*` header uses), so auth-gated routes answer 200
instead of 401 and the scan can reach them.

Credentials never sit in config. The login body is read from the environment
variable `target.auth.login_body_env` names. The login URL is localhost-only,
enforced here and in the config loader.
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol
from urllib.parse import urlsplit

from common.config import Config
from common.record import LOCALHOST_NAMES


class _SendsRequests(Protocol):
    def send_request(self, raw_request: str, follow_redirects: bool = ...) -> dict[str, Any]: ...


def login_configured(config: Config) -> bool:
    return bool(config["target.auth.login_url"])


def resolve_session(api: _SendsRequests, config: Config, base_url: str) -> tuple[str, str]:
    """Run the login flow and return the (header_name, value) to carry on probes.

    Raises ValueError if the flow is misconfigured or the token is not found.
    """
    login_url = config["target.auth.login_url"]
    if not login_url:
        raise ValueError("resolve_session called without target.auth.login_url")
    if urlsplit(login_url).hostname not in LOCALHOST_NAMES:
        raise ValueError("target.auth.login_url must be on localhost")

    token_from = config["target.auth.token_from"]
    token_name = config["target.auth.token_name"]
    if token_from in {"json", "header"} and not token_name:
        raise ValueError(f"target.auth.token_from={token_from} needs target.auth.token_name")

    body = ""
    body_env = config["target.auth.login_body_env"]
    if body_env:
        body = os.environ.get(body_env, "")
        if not body:
            raise ValueError(f"target.auth.login_body_env is set but {body_env} is empty")

    message = api.send_request(
        _login_request(
            login_url,
            config["target.auth.login_method"],
            body,
            config["target.auth.login_content_type"],
        ),
        follow_redirects=False,
    )
    response_header = _text(message, "responseHeader")
    response_body = _text(message, "responseBody")

    if token_from == "cookie":
        value = _cookie_value(response_header, token_name)
        if value is None:
            raise ValueError("login response set no usable cookie")
        return (config["target.auth.header_name"] or "Cookie", value)

    if token_from == "header":
        token = _header_value(response_header, token_name)
    else:  # json
        token = _json_field(response_body, token_name)
    if not token:
        header_name = config["target.auth.header_name"]
        if not header_name:
            raise ValueError("target.auth.header_name is required for token or header auth")
        raise ValueError(f"login response had no token at {token_name!r}")
    header_name = config["target.auth.header_name"]
    if not header_name:
        raise ValueError("target.auth.header_name is required for token or header auth")
    return (header_name, config["target.auth.header_template"].format(token=token))


def _login_request(url: str, method: str, body: str, content_type: str) -> str:
    host = urlsplit(url).netloc
    lines = [f"{method.upper()} {url} HTTP/1.1", f"Host: {host}"]
    if body:
        if content_type:
            lines.append(f"Content-Type: {content_type}")
        lines.append(f"Content-Length: {len(body.encode())}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _text(message: dict[str, Any], key: str) -> str:
    value = message.get(key)
    return value if isinstance(value, str) else ""


def _cookie_value(response_header: str, cookie_name: str | None) -> str | None:
    """`name=value` for the named cookie, or every Set-Cookie pair joined when no
    name is given. Cookie attributes (Path, HttpOnly, ...) are dropped."""
    pairs: list[str] = []
    for name, value in _header_values(response_header, "set-cookie"):
        _ = name
        pair = value.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        if cookie_name:
            if pair.split("=", 1)[0] == cookie_name:
                return pair
        else:
            pairs.append(pair)
    return "; ".join(pairs) if pairs else None


def _header_value(response_header: str, name: str) -> str | None:
    for _, value in _header_values(response_header, name):
        return value
    return None


def _header_values(response_header: str, name: str):
    for line in response_header.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == name.casefold():
            yield key.strip(), value.strip()


def _json_field(body: str, dotted: str) -> str | None:
    try:
        node: Any = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return str(node) if isinstance(node, (str, int, float)) else None
