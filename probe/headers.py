"""Own header and cookie checks over one response. Runtime-only, no sink link.

Each check reports a missing protection on a response the target actually
sent. The checks are deterministic and need no correlation.

CWE numbers are [proposed]: 1021 (clickjacking), 693 (protection mechanism
missing), 1004 (cookie without HttpOnly), 1275 (cookie without SameSite).
HSTS and cookie Secure are not checked: the target is plain http on localhost,
where they do not apply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from probe.oracles import Response, header_value

_COOKIE_NAME = re.compile(r"^\s*([^=;\s]+)=")


@dataclass(frozen=True)
class HeaderFinding:
    header_name: str  # the protection that is missing, or the cookie name
    cwe: int
    detail: str


def _set_cookies(headers: str) -> list[str]:
    """Each Set-Cookie line, since a response can set several cookies."""
    values = []
    for line in headers.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == "set-cookie":
            values.append(value.strip())
    return values


def _frame_protected(headers: str) -> bool:
    if header_value(headers, "X-Frame-Options"):
        return True
    csp = header_value(headers, "Content-Security-Policy") or ""
    return "frame-ancestors" in csp.casefold()


def check_response(response: Response) -> list[HeaderFinding]:
    """The protections a response should carry and does not."""
    findings: list[HeaderFinding] = []
    if header_value(response.headers, "X-Content-Type-Options") is None:
        findings.append(HeaderFinding("X-Content-Type-Options", 693, "missing"))
    if not _frame_protected(response.headers):
        findings.append(HeaderFinding("X-Frame-Options", 1021, "no X-Frame-Options or frame-ancestors"))
    for cookie in _set_cookies(response.headers):
        match = _COOKIE_NAME.match(cookie)
        name = match.group(1) if match else cookie
        flags = cookie.casefold()
        if "httponly" not in flags:
            findings.append(HeaderFinding(name, 1004, "cookie without HttpOnly"))
        if "samesite=" not in flags:
            findings.append(HeaderFinding(name, 1275, "cookie without SameSite"))
    return findings
