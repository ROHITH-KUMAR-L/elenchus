"""PostgreSQL persistence for raw findings and merged issue history."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from engine.correlate.models import Finding, Issue

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed')),
    finding_count INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('sast', 'dast')),
    fingerprint TEXT NOT NULL,
    record JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS findings_run_source_idx ON findings (run_id, source);
CREATE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings (fingerprint);

CREATE TABLE IF NOT EXISTS issues (
    issue_key TEXT PRIMARY KEY,
    record JSONB NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS issue_keys (
    alias_key TEXT PRIMARY KEY,
    issue_key TEXT NOT NULL REFERENCES issues(issue_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS issue_runs (
    issue_key TEXT NOT NULL REFERENCES issues(issue_key) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    record JSONB NOT NULL,
    PRIMARY KEY (issue_key, run_id)
);

CREATE INDEX IF NOT EXISTS issue_runs_run_idx ON issue_runs (run_id);
"""


class PostgresStore:
    def __init__(self, conninfo: str | None = None) -> None:
        self._conninfo = conninfo

    def save_run(
        self,
        run_id: str,
        findings: Sequence[Finding],
        issues: Sequence[Issue],
    ) -> None:
        try:
            import psycopg
            from psycopg.types.json import Jsonb
        except ImportError as error:
            raise RuntimeError(
                "PostgreSQL support requires the project dependencies; install with `pip install .`"
            ) from error

        try:
            self._save_run_transaction(run_id, findings, issues, psycopg, Jsonb)
        except psycopg.Error as error:
            raise RuntimeError(f"PostgreSQL persistence failed: {error}") from error

    def _save_run_transaction(
        self,
        run_id: str,
        findings: Sequence[Finding],
        issues: Sequence[Issue],
        psycopg: Any,
        jsonb: Any,
    ) -> None:
        connection = (
            psycopg.connect(self._conninfo)
            if self._conninfo
            else psycopg.connect()
        )
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(_SCHEMA)
                cursor.execute(
                    "INSERT INTO scan_runs (run_id, status) VALUES (%s, 'running')",
                    (run_id,),
                )
                for finding in findings:
                    record = finding.to_dict()
                    cursor.execute(
                        """
                        INSERT INTO findings (run_id, source, fingerprint, record)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            run_id,
                            finding.source,
                            _finding_fingerprint(finding),
                            jsonb(record),
                        ),
                    )
                for issue in issues:
                    _save_issue(cursor, run_id, issue, jsonb)
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET status = 'completed', completed_at = now(),
                        finding_count = %s, issue_count = %s
                    WHERE run_id = %s
                    """,
                    (len(findings), len(issues), run_id),
                )


def _finding_identity(finding: Finding) -> tuple[object, ...]:
    header_name = finding.evidence.get("header_name")
    if isinstance(header_name, str) and header_name:
        return "header", finding.cwe, header_name.casefold()
    if finding.file is not None and finding.line is not None:
        return "code", finding.cwe, _normalize_file(finding.file), finding.line
    return "route", finding.cwe, finding.route, finding.method, finding.param


def _finding_fingerprint(finding: Finding) -> str:
    import hashlib
    import json

    encoded = json.dumps(_finding_identity(finding), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _issue_aliases(issue: Issue) -> set[str]:
    if issue.sast_findings and issue.dast_findings:
        return {
            *(_alias_for_finding(finding) for finding in issue.sast_findings),
            *(_route_alias(finding) for finding in issue.dast_findings),
        }
    if issue.sast_findings:
        return {_alias_for_finding(finding) for finding in issue.sast_findings}
    return {_route_alias(finding) for finding in issue.dast_findings}


def _alias_for_finding(finding: Finding) -> str:
    import hashlib
    import json

    if isinstance(finding.evidence.get("header_name"), str):
        identity = _finding_identity(finding)
    elif finding.file is not None and finding.line is not None:
        identity = _finding_identity(finding)
    else:
        identity = _route_identity(finding)
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _code_alias(finding: Finding) -> str:
    import hashlib
    import json

    identity = ("code", finding.cwe, _normalize_file(finding.file), finding.line)
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _route_alias(finding: Finding) -> str:
    import hashlib
    import json

    identity = _route_identity(finding)
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _route_identity(finding: Finding) -> tuple[object, ...]:
    header_name = finding.evidence.get("header_name")
    if isinstance(header_name, str) and header_name:
        return "header", finding.cwe, header_name.casefold()
    return "route", finding.cwe, finding.route, finding.method, finding.param


def _normalize_file(file: str) -> str:
    normalized = file.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _save_issue(cursor: Any, run_id: str, issue: Issue, jsonb: Any) -> None:
    aliases = _issue_aliases(issue)
    existing_keys: dict[str, str] = {}
    existing_issue_ids: set[str] = set()
    expanded_aliases = set(aliases)
    while True:
        cursor.execute(
            "SELECT alias_key, issue_key FROM issue_keys WHERE alias_key = ANY(%s)",
            (list(expanded_aliases),),
        )
        current = dict(cursor.fetchall())
        new_issue_ids = set(current.values()) - existing_issue_ids
        existing_keys.update(current)
        if not new_issue_ids:
            break
        existing_issue_ids.update(new_issue_ids)
        cursor.execute(
            "SELECT alias_key FROM issue_keys WHERE issue_key = ANY(%s)",
            (list(new_issue_ids),),
        )
        new_aliases = {row[0] for row in cursor.fetchall()} - expanded_aliases
        if not new_aliases:
            break
        expanded_aliases.update(new_aliases)

    code_aliases = {
        _alias_for_finding(finding)
        for finding in issue.sast_findings
        if finding.file is not None and finding.line is not None
    }
    matching_code_ids = [
        existing_keys[alias]
        for alias in sorted(code_aliases)
        if alias in existing_keys
    ]
    if matching_code_ids:
        canonical_key = matching_code_ids[0]
    elif code_aliases or not existing_issue_ids:
        canonical_key = issue.issue_key
    else:
        canonical_key = sorted(existing_issue_ids)[0]
    merged_aliases = expanded_aliases
    record = issue.to_dict()
    record["issue_key"] = canonical_key

    if canonical_key not in existing_issue_ids:
        cursor.execute(
            "INSERT INTO issues (issue_key, record) VALUES (%s, %s)",
            (canonical_key, jsonb(record)),
        )
    else:
        cursor.execute(
            """
            UPDATE issues SET record = %s, last_seen = now()
            WHERE issue_key = %s
            """,
            (jsonb(record), canonical_key),
        )

    old_issue_ids = existing_issue_ids - {canonical_key}
    for old_key in old_issue_ids:
        cursor.execute(
            """
            INSERT INTO issue_runs (issue_key, run_id, record)
            SELECT %s, run_id, record FROM issue_runs WHERE issue_key = %s
            ON CONFLICT (issue_key, run_id) DO NOTHING
            """,
            (canonical_key, old_key),
        )
        cursor.execute("DELETE FROM issues WHERE issue_key = %s", (old_key,))

    for alias in merged_aliases:
        cursor.execute(
            """
            INSERT INTO issue_keys (alias_key, issue_key) VALUES (%s, %s)
            ON CONFLICT (alias_key) DO UPDATE SET issue_key = EXCLUDED.issue_key
            """,
            (alias, canonical_key),
        )
    cursor.execute(
        """
        INSERT INTO issue_runs (issue_key, run_id, record)
        VALUES (%s, %s, %s)
        ON CONFLICT (issue_key, run_id) DO UPDATE SET record = EXCLUDED.record
        """,
        (canonical_key, run_id, jsonb(record)),
    )
