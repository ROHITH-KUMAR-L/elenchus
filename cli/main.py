"""Command-line entry point for the consumer pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Sequence

from common.record import ScanTarget
from engine.correlate import Finding, Issue, correlate
from engine.report import format_text, to_sarif


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.run_id is not None and not args.run_id.strip():
            raise ValueError("--run-id must not be empty")
        run_id = args.run_id or uuid.uuid4().hex
        if args.command == "scan":
            findings = _run_producers(args, run_id)
        else:
            records = _load_inputs(args.sast, args.dast)
            findings = [record.with_run_id(run_id) for record in records]
        issues = correlate(findings)
        if not args.no_store:
            from engine.store import PostgresStore

            PostgresStore(args.database_url).save_run(run_id, findings, issues)
        if args.sarif_output == "-":
            print(json.dumps(to_sarif(issues), indent=2, sort_keys=True))
        else:
            _write_report(issues, args.output_format)
        if args.sarif_output and args.sarif_output != "-":
            _write_json(Path(args.sarif_output), to_sarif(issues))
        if args.ci and any(
            issue.label == "Confirmed"
            and issue.severity.casefold() in {"critical", "high"}
            for issue in issues
        ):
            return 1
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(f"elenchus: {error}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elenchus",
        description="Correlate SAST and DAST finding records.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    correlate_parser = commands.add_parser(
        "correlate",
        help="correlate JSON finding records produced by scanners",
    )
    correlate_parser.add_argument("--run-id", help="run identifier (default: generated UUID)")
    correlate_parser.add_argument(
        "--sast",
        action="append",
        default=[],
        metavar="FILE",
        help="SAST JSON array or object containing a findings array; repeatable",
    )
    correlate_parser.add_argument(
        "--dast",
        action="append",
        default=[],
        metavar="FILE",
        help="DAST JSON array or object containing a findings array; repeatable",
    )
    _add_output_arguments(correlate_parser)

    scan_parser = commands.add_parser(
        "scan",
        help="run the route map, Semgrep, and localhost ZAP scans",
    )
    scan_parser.add_argument("--source-path", required=True, help="target source directory")
    scan_parser.add_argument(
        "--base-url",
        required=True,
        help="target base URL; must resolve to localhost, 127.0.0.1, or ::1",
    )
    scan_parser.add_argument(
        "--framework",
        choices=("spring-mvc",),
        default="spring-mvc",
        help="target framework adapter (default: spring-mvc)",
    )
    scan_parser.add_argument("--run-id", help="run identifier (default: generated UUID)")
    _add_output_arguments(scan_parser)
    return parser


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL connection string (or DATABASE_URL environment variable)",
    )
    parser.add_argument(
        "--no-store",
        action="store_true",
        help="skip persistence for local previews and tests",
    )
    parser.add_argument(
        "--output-format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--sarif-output",
        metavar="FILE",
        help="write the correlated issues as SARIF 2.1.0",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="return exit status 1 for Confirmed high or critical issues",
    )


def _run_producers(args: argparse.Namespace, run_id: str) -> list[Finding]:
    target = ScanTarget(args.source_path, args.base_url, run_id, args.framework)
    from producers.dast.zap_runner import run_dast
    from producers.sast.semgrep_runner import run_sast
    from producers.sast.spring_routes import route_map

    routes = route_map(target)
    return run_sast(target, routes) + run_dast(target, routes)


def _load_inputs(sast_paths: Sequence[str], dast_paths: Sequence[str]) -> list[Finding]:
    if not sast_paths and not dast_paths:
        raise ValueError("provide at least one --sast or --dast file")

    findings: list[Finding] = []
    for source, paths in (("sast", sast_paths), ("dast", dast_paths)):
        for path in paths:
            for raw in _read_records(Path(path)):
                finding = Finding.from_dict(raw)
                if finding.source != source:
                    raise ValueError(
                        f"{path} was supplied as {source} input but contains a {finding.source} finding"
                    )
                findings.append(finding)
    return findings


def _read_records(path: Path) -> list[dict[str, Any]]:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: invalid JSON at line {error.lineno}, column {error.colno}") from error
    if isinstance(content, dict):
        content = content.get("findings")
    if not isinstance(content, list):
        raise ValueError(f"{path}: expected a JSON array or an object with a findings array")
    if not all(isinstance(item, dict) for item in content):
        raise ValueError(f"{path}: each finding must be a JSON object")
    return content


def _write_report(issues: list[Issue], output_format: str) -> None:
    if output_format == "json":
        output = json.dumps(
            {"issues": [issue.to_dict() for issue in issues]},
            indent=2,
            sort_keys=True,
        )
    else:
        output = format_text(issues)
    print(output)


def _write_json(path: Path, content: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
