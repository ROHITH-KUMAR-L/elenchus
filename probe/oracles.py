"""Deterministic, differential oracles. A ZAP alert never decides a verdict.

Each oracle takes the baseline response, the probe response and the attack value
the replayed request carried. ZAP generates its own payloads, so an oracle cannot
rely on a canary we planted: it checks the attack value itself.

ORACLES maps CWE to its oracle. Command injection (78) has none yet: its signal
is timing, and no timing source is verified. Blind and union SQL are also not
built yet.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

# Database error signatures across the engines VulnerableApp and common targets
# use. A signature in the probe response but not the baseline shows the payload
# broke query syntax, which is the error-based SQL injection oracle.
_SQL_ERROR_PATTERNS = (
    r"SQLSyntaxErrorException",
    r"SQLException",
    r"SQLSTATE",
    r"JdbcSQLSyntaxErrorException",
    r"org\.h2\.jdbc",
    r"syntax error at or near",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"you have an error in your SQL syntax",
    r"SQLiteException",
    r"org\.hibernate\.exception",
    r"org\.postgresql\.util\.PSQLException",
    r"ORA-\d{5}",
    r"bad SQL grammar",
)
_SQL_ERROR = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)
_HTML_TYPE = re.compile(r"^content-type:\s*text/html", re.IGNORECASE | re.MULTILINE)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class Response:
    status: int | None
    headers: str
    body: str


Oracle = Callable[[Response, Response, str], bool]


def header_value(headers: str, name: str) -> str | None:
    """The first value of a response header, matched case-insensitively."""
    for line in headers.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == name.casefold():
            return value.strip()
    return None


def sql_error(baseline: Response, probe: Response, payload: str = "") -> bool:
    """A SQL error in the probe response that the baseline did not show."""
    return bool(_SQL_ERROR.search(probe.body)) and not _SQL_ERROR.search(baseline.body)


def xss_reflected(baseline: Response, probe: Response, payload: str) -> bool:
    """The attack value's markup comes back verbatim in an HTML response.

    The check needs `text/html`. VulnerableApp's XSS routes reply `text/plain`,
    so they are not confirmed here. An HTML-escaped reflection does not contain
    the raw markup, so it does not fire.
    """
    if "<" not in payload or ">" not in payload:
        return False
    if not _HTML_TYPE.search(probe.headers):
        return False
    return payload in probe.body and payload not in baseline.body


def open_redirect(baseline: Response, probe: Response, payload: str) -> bool:
    """A redirect whose Location host is the attack's external host."""
    if probe.status is None or not 300 <= probe.status < 400:
        return False
    location = header_value(probe.headers, "Location")
    if not location:
        return False
    host = (urlsplit(location).hostname or "").casefold()
    if not host or host in _LOCAL_HOSTS or host not in payload.casefold():
        return False
    baseline_location = header_value(baseline.headers, "Location") or ""
    return urlsplit(baseline_location).hostname != host


ORACLES: dict[int, Oracle] = {
    79: xss_reflected,
    89: sql_error,
    601: open_redirect,
}


def oracle_for(cwe: int) -> Oracle | None:
    return ORACLES.get(cwe)
