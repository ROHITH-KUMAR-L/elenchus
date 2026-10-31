"""Command-line entry point for the consumer pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from common.config import load_config
from common.record import EvidenceEntry, Finding, ScanTarget
from engine.correlate import Issue, correlate
from engine.report import build_coverage_report, format_text, to_sarif


@dataclass(frozen=True)
class _PipelineOutput:
    findings: list[Finding]
    attribution_rate: float | None = None
    header_propagation_rate: float | None = None
    skipped_by_type: tuple[tuple[str, str, str], ...] = ()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.run_id is not None and not args.run_id.strip():
            raise ValueError("--run-id must not be empty")
        run_id = args.run_id or uuid.uuid4().hex
        if args.command == "scan":
            if not args.base_url:
                raise ValueError("a target base URL is required: pass --base-url or set ELENCHUS_BASE_URL")
            config = load_config(
                overrides={"target.base_url": args.base_url, "judging.profile": args.judging}
            )
            pipeline_output = _run_pipeline(args, run_id, config)
            findings = pipeline_output.findings
        else:
            config = load_config()
            records = _load_inputs(args.sast, args.dast)
            findings = [record.with_run_id(run_id) for record in records]
            pipeline_output = _PipelineOutput(findings)
        issues = correlate(findings, config)
        findings = _apply_conflict_resolution(findings, issues)
        expected_pairs = _load_expected_pairs(args.expected_pairs)
        coverage = build_coverage_report(
            findings,
            issues=issues,
            expected_pairs=expected_pairs,
            supported_cwes=config.rule_map(),
            skipped_by_type=pipeline_output.skipped_by_type,
            attribution_rate=pipeline_output.attribution_rate,
            header_propagation_rate=pipeline_output.header_propagation_rate,
        )
        output_dir = _run_output_directory(run_id)
        suppressed = [issue for issue in issues if issue.suppressed]
        primary_issues = [issue for issue in issues if not issue.suppressed]
        _write_json(output_dir / "suppressed.json", {"issues": [i.to_dict() for i in suppressed]})
        _write_json(output_dir / "coverage.json", coverage)
        print(
            f"suppressed_file={output_dir / 'suppressed.json'} "
            f"coverage_file={output_dir / 'coverage.json'}",
            file=sys.stderr,
        )
        if not args.no_store:
            from engine.store import PostgresStore

            PostgresStore(args.database_url).save_run(run_id, findings, issues)
        if args.sarif_output == "-":
            sarif_issues = issues if config["export.include_suppressed"] else primary_issues
            print(json.dumps(to_sarif(sarif_issues), indent=2, sort_keys=True))
        else:
            _write_report(primary_issues, args.output_format)
        if args.sarif_output and args.sarif_output != "-":
            sarif_issues = issues if config["export.include_suppressed"] else primary_issues
            _write_json(Path(args.sarif_output), to_sarif(sarif_issues))
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
        help="run the staged pipeline against source and a localhost target",
    )
    scan_parser.add_argument("--source-path", required=True, help="target source directory")
    scan_parser.add_argument(
        "--base-url",
        default=os.environ.get("ELENCHUS_BASE_URL"),
        help="target base URL (or ELENCHUS_BASE_URL); must resolve to localhost, 127.0.0.1, or ::1",
    )
    scan_parser.add_argument(
        "--framework",
        choices=("spring-mvc",),
        default="spring-mvc",
        help="target framework adapter (default: spring-mvc)",
    )
    scan_parser.add_argument(
        "--judging",
        action="store_true",
        help="judging profile: ZAP on, AI and Semgrep off, no target restarts",
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
    parser.add_argument(
        "--expected-pairs",
        metavar="FILE",
        help="optional YAML ground truth used only for the coverage report",
    )


def _run_pipeline(args: argparse.Namespace, run_id: str, config: Any) -> _PipelineOutput:
    """Stages 0 to 4: index, static, hypotheses, preflight, ZAP probe.

    Static findings carry their own status (untested, no_http_path, ...); probe
    findings carry ORACLE evidence and lineage. Correlation links the two.
    """
    from probe.coordinator import Coordinator, plan_directed_jobs, plan_sweep_jobs
    from probe.oracles import ORACLES
    from probe.preflight import check_loopback, detect_context_path
    from producers.dast.zap_runner import ZapApi
    from producers.hypotheses.builder import build_directed, build_sweep, skipped_by_type
    from producers.sast.code_index import build_code_index
    from producers.sast.response_trace import parse_java_response_trace
    from producers.sast.static_stage import run_static

    check_loopback(args.base_url)
    target = ScanTarget(args.source_path, args.base_url, run_id, args.framework)
    index = build_code_index(args.source_path)
    static_findings = run_static(target, index)
    directed = build_directed(static_findings, index)
    # Sweep the classes that have both a ZAP rule and a runtime oracle, for bugs
    # the static stage missed. The two-pass scheduler runs these after directed.
    sweep_cwes = sorted(set(ORACLES) & set(config.rule_map()))
    sweep = build_sweep(index, sweep_cwes)
    skipped = tuple(skipped_by_type(index))
    jobs = plan_directed_jobs(directed, index.routes, run_id) + plan_sweep_jobs(
        sweep, index.routes, run_id
    )
    context = detect_context_path(args.source_path, args.base_url)
    coordinator = Coordinator(
        ZapApi.from_environment(),
        config,
        args.base_url,
        context,
        enum_types=index.enum_types,
        trace_parser=lambda body: parse_java_response_trace(body, args.source_path),
    )
    result = coordinator.run(run_id, jobs, index.routes)
    _report_probe_telemetry(result)
    return _PipelineOutput(
        _apply_adequacy(
            static_findings + result.findings,
            result.adequacy,
            {
                (route.route, route.method): tuple(param.name for param in route.params)
                for route in index.routes
            },
        ),
        attribution_rate=result.attribution_rate,
        header_propagation_rate=result.header_propagation_rate,
        skipped_by_type=skipped,
    )


def _apply_adequacy(
    findings: list[Finding],
    probe_rows: Sequence[Any],
    route_params: Mapping[tuple[str, str], tuple[str, ...]],
) -> list[Finding]:
    """Attach probe outcomes and advance only static findings with complete evidence."""
    rows = [item.to_dict() for item in probe_rows]
    output = []
    for finding in findings:
        if finding.source != "sast" or not finding.entry_paths:
            output.append(finding)
            continue
        route_keys = {
            (path.route, path.method)
            for path in finding.entry_paths
        }
        attached = [
            row
            for row in rows
            if row["cwe"] == finding.cwe
            and (row["route"], row["method"]) in route_keys
            and row["param"] in route_params.get((row["route"], row["method"]), ())
        ]
        if not attached:
            output.append(finding)
            continue

        evidence = finding.evidence + tuple(
            EvidenceEntry("ADEQUACY", row) for row in attached
        )
        status = finding.status
        unlinked_reason = finding.unlinked_reason
        has_oracle_hit = any(
            probe.source == "dast"
            and probe.cwe == finding.cwe
            and any(
                path.route == probe.route
                and path.method == probe.method
                and probe.param in route_params.get((path.route, path.method), ())
                for path in finding.entry_paths
            )
            and any(entry.type == "ORACLE" for entry in probe.evidence)
            for probe in findings
        )
        if status == "untested" and not has_oracle_hit:
            blocked = None
            for row in attached:
                route_key = (row["route"], row["method"])
                param_rows = [
                    item
                    for item in attached
                    if (item["route"], item["method"], item["param"])
                    == (route_key[0], route_key[1], row["param"])
                ]
                if (
                    row["outcome"] == "blocked_by_validation"
                    and not any(
                        item["outcome"] in {"adequate", "type_rejected"}
                        for item in param_rows
                    )
                ):
                    blocked = row
                    break
            if blocked is not None:
                status = "blocked"
                unlinked_reason = blocked["sub_code"] or "validation"
            else:
                complete = bool(route_keys)
                for route_key in route_keys:
                    params = route_params.get(route_key, ())
                    if not params:
                        complete = False
                        break
                    for param in params:
                        param_rows = [
                            row
                            for row in attached
                            if (row["route"], row["method"], row["param"])
                            == (route_key[0], route_key[1], param)
                        ]
                        if not any(
                            row["params_status"] == "complete"
                            and row["job_outcome"] == "finished"
                            and not row["after_drift"]
                            and row["outcome"] in {"adequate", "type_rejected"}
                            for row in param_rows
                        ):
                            complete = False
                            break
                    if not complete:
                        break
                if complete:
                    status = "tested_negative"
                    unlinked_reason = None
        output.append(
            replace(
                finding,
                evidence=evidence,
                status=status,
                unlinked_reason=unlinked_reason,
            )
        )
    return output


def _apply_conflict_resolution(
    findings: list[Finding], issues: Sequence[Issue]
) -> list[Finding]:
    """Persist conflict-cleared static records alongside their correlated issue."""
    cleared = {
        (finding.sink_id, finding.cwe): finding
        for issue in issues
        if issue.conflict and issue.link_status == "ambiguous" and issue.link_origin == "sweep"
        for finding in issue.sast_findings
        if finding.source == "sast" and finding.conflict and finding.status is None
    }
    return [
        cleared.get((finding.sink_id, finding.cwe), finding)
        for finding in findings
    ]


def _load_expected_pairs(path: str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    import yaml

    try:
        value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"{path}: invalid expected-pairs YAML: {error}") from error
    if not isinstance(value, dict) or not isinstance(value.get("pairs"), list):
        raise ValueError(f"{path}: expected a YAML object with a pairs list")
    return value


def _run_output_directory(run_id: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", run_id).strip(".")[:48] or "run"
    suffix = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:10]
    return Path("out") / f"{slug}-{suffix}"


def _report_probe_telemetry(result: Any) -> None:
    """Probe-stage telemetry to stderr: wall time, outcomes, skips. The exit test
    and judging-mode runs read these; they do not belong in the findings output."""
    from collections import Counter

    outcomes = Counter(job.outcome for job in result.jobs)
    print(
        f"probe: stage_seconds={result.stage_seconds} jobs_run={len(result.jobs)} "
        f"jobs_skipped={len(result.jobs_skipped)} drift_detected={result.drift_detected} "
        f"outcomes={dict(outcomes)} "
        f"attribution_rate={result.attribution_rate:.3f} "
        f"header_propagation_rate={result.header_propagation_rate:.3f} "
        f"foreign_hosts={result.foreign_hosts}",
        file=sys.stderr,
    )


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
