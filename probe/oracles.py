"""Deterministic, differential oracles. A ZAP alert never decides a verdict.

Each oracle compares a probe response with the route's baseline, so a signature
already present without an attack does not count. BS4 ships the error-based SQL
oracle only; the other classes arrive in BS6. ORACLES maps CWE to its oracle.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

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


@dataclass(frozen=True)
class Response:
    status: int | None
    headers: str
    body: str


Oracle = Callable[[Response, Response], bool]


def sql_error(baseline: Response, probe: Response) -> bool:
    """A SQL error in the probe response that the baseline did not show."""
    return bool(_SQL_ERROR.search(probe.body)) and not _SQL_ERROR.search(baseline.body)


ORACLES: dict[int, Oracle] = {
    89: sql_error,
}


def oracle_for(cwe: int) -> Oracle | None:
    return ORACLES.get(cwe)
