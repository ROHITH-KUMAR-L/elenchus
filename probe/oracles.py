"""Deterministic, differential oracles. A ZAP alert never decides a verdict.

Each oracle takes the baseline response, the probe response and the attack value
the replayed request carried. ZAP generates its own payloads, so an oracle cannot
rely on a canary we planted: it checks the attack value itself.

ORACLES maps CWE to its oracle. Command injection (78) is confirmed by command
output reflected in the response (differential, offline-testable). Its timing
variant (`timing_slower`) is built but not registered: it needs a verified timing
source (`probe.timing_repeats`), measured live. Blind and union SQL are also not
built yet; boolean SQL (`sql_boolean`) is a three-response oracle, so it is not in
ORACLES either.
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

# Output signatures of the commands an OS-command-injection scanner runs (id,
# cat /etc/passwd, ipconfig). A signature in the probe response but not the
# baseline shows the injected command ran. ZAP owns the payload, so there is no
# planted canary; these are the command's own output, not ours.
_COMMAND_OUTPUT_PATTERNS = (
    r"uid=\d+\([^)]+\)\s+gid=\d+\(",
    r"\bgroups=\d+\(",
    r"^root:.*:0:0:",
    r"Windows IP Configuration",
)
_COMMAND_OUTPUT = re.compile("|".join(_COMMAND_OUTPUT_PATTERNS), re.IGNORECASE | re.MULTILINE)


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


def command_output(baseline: Response, probe: Response, payload: str = "") -> bool:
    """OS command injection: output of an injected command appears in the probe
    response and not in the baseline."""
    return bool(_COMMAND_OUTPUT.search(probe.body)) and not _COMMAND_OUTPUT.search(baseline.body)


# A traversal sequence in the attack, and the content of a well-known sensitive
# file in the probe response but not the baseline.
_TRAVERSAL_PAYLOAD = re.compile(r"\.\.[\\/]|%2e%2e|\.\.%2f|%252e", re.IGNORECASE)
_TRAVERSAL_EVIDENCE = re.compile(
    r"root:[^:\n]*:0:0:|\[boot loader\]|\[fonts\]|; for 16-bit app support",
    re.IGNORECASE,
)


def path_traversal(baseline: Response, probe: Response, payload: str) -> bool:
    """Path traversal: the attack carried a traversal sequence and a sensitive
    file's content came back in the probe response and not the baseline."""
    if not _TRAVERSAL_PAYLOAD.search(payload):
        return False
    return bool(_TRAVERSAL_EVIDENCE.search(probe.body)) and not _TRAVERSAL_EVIDENCE.search(baseline.body)


ORACLES: dict[int, Oracle] = {
    22: path_traversal,
    78: command_output,
    79: xss_reflected,
    89: sql_error,
    601: open_redirect,
}


def oracle_for(cwe: int) -> Oracle | None:
    return ORACLES.get(cwe)


def sql_boolean(baseline: Response, true_probe: Response, false_probe: Response) -> bool:
    """Boolean-based SQL injection: the true-condition payload answers like the
    baseline, and the false-condition payload answers differently.

    It needs three responses, so it is not in ORACLES. Wiring it into the
    coordinator means sending a true and a false replay pair per candidate.
    """
    if baseline.status != 200 or true_probe.status != 200 or false_probe.status != 200:
        return False
    if not baseline.body:
        return False
    return true_probe.body == baseline.body and false_probe.body != baseline.body


def timing_slower(baseline_seconds: float, probe_seconds: float, threshold_seconds: float) -> bool:
    """Time-based blind injection: the probe response is slower than the baseline
    by at least threshold_seconds.

    It compares elapsed times, not responses, so it is not an Oracle and is not in
    ORACLES. Wiring it needs a verified timing source: `probe.timing_repeats`
    requests with the median taken, measured live before it is trusted.
    """
    return (probe_seconds - baseline_seconds) >= threshold_seconds
