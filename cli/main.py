"""Command-line entry point for the consumer pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from common.config import load_config
from common.record import EvidenceEntry, Finding, ScanTarget
from engine.correlate import Issue, correlate
from engine.report import build_coverage_report, format_comparison, format_text, to_sarif


@dataclass(frozen=True)
class _PipelineOutput:
    findings: list[Finding]
    attribution_rate: float | None = None
    header_propagation_rate: float | None = None
    skipped_by_type: tuple[tuple[str, str, str], ...] = ()
    index: Any = None
    advisory_alerts: tuple[dict[str, Any], ...] = ()
    preflight_extras: dict[str, Any] | None = None


def _create_progress(no_progress: bool) -> Progress:
    console = Console(stderr=True, no_color="NO_COLOR" in os.environ)
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
        disable=no_progress or not console.is_terminal,
    )


def _progress_step(progress: Progress, description: str, operation: Callable[[], Any]) -> Any:
    task_id = progress.add_task(description, total=None)
    result = operation()
    progress.update(task_id, description=f"✓ {description}", total=1, completed=1)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            return _run_compare(args)
        if args.run_id is not None and not args.run_id.strip():
            raise ValueError("--run-id must not be empty")
        run_id = args.run_id or uuid.uuid4().hex
        if args.command == "scan":
            if not args.base_url:
                raise ValueError("a target base URL is required: pass --base-url or set ELENCHUS_BASE_URL")
            args.source_path = _resolve_source(args)
            config = load_config(
                path=Path(args.config) if args.config else None,
                overrides={"target.base_url": args.base_url, "judging.profile": args.judging},
            )
            pipeline_output = _run_pipeline(args, run_id, config)
            findings = pipeline_output.findings
        else:
            config = load_config(path=Path(args.config) if args.config else None)
            records = _load_inputs(args.sast, args.dast)
            findings = [record.with_run_id(run_id) for record in records]
            pipeline_output = _PipelineOutput(findings)
        issues = correlate(findings, config)
        if config["backguided.enabled"] and pipeline_output.index is not None:
            from engine.correlate.back_guided import apply_back_guided
            from producers.sast.sink_finder import load_catalogue

            issues = apply_back_guided(issues, pipeline_output.index, load_catalogue(), config)
        issues = _apply_ai_advice(issues, config)
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
        # Passive ZAP alerts are advisory context, not verdicts; they are written
        # to their own file and never enter correlation.
        _write_json(
            output_dir / "advisory.json",
            {
                "advisory_alerts": list(pipeline_output.advisory_alerts),
                "preflight_extras": pipeline_output.preflight_extras,
            },
        )
        print(
            f"suppressed_file={output_dir / 'suppressed.json'} "
            f"coverage_file={output_dir / 'coverage.json'} "
            f"advisory_file={output_dir / 'advisory.json'} "
            f"advisory_alerts={len(pipeline_output.advisory_alerts)}",
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

    compare_parser = commands.add_parser(
        "compare",
        help="compare two stored scan runs: new, fixed and still-open issues (B-5)",
    )
    compare_parser.add_argument("--base", required=True, metavar="RUN_ID", help="the earlier run")
    compare_parser.add_argument(
        "--current", required=True, metavar="RUN_ID", help="the later run"
    )
    compare_parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL connection string (or DATABASE_URL environment variable)",
    )
    compare_parser.add_argument(
        "--output-format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )

    scan_parser = commands.add_parser(
        "scan",
        help="run the staged pipeline against source and a localhost target",
    )
    scan_parser.add_argument(
        "--source-path",
        help="target source directory on the local filesystem",
    )
    scan_parser.add_argument(
        "--source-image",
        metavar="IMAGE_OR_CONTAINER",
        help="docker image or container holding the target source; copied out and scanned. "
        "Use with --source-image-path",
    )
    scan_parser.add_argument(
        "--source-image-path",
        metavar="PATH",
        help="absolute path of the source inside --source-image",
    )
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
    scan_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="disable terminal progress feedback",
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
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="optional TOML config file (keys from the Config reference in docs/architecture.md)",
    )


def _resolve_source(args: argparse.Namespace) -> str:
    """The local source directory to scan: either --source-path, or the source
    copied out of a docker image or container named by --source-image."""
    if args.source_image:
        if not args.source_image_path:
            raise ValueError("--source-image needs --source-image-path (the source path inside it)")
        return _source_from_image(args.source_image, args.source_image_path)
    if not args.source_path:
        raise ValueError("provide --source-path, or --source-image with --source-image-path")
    return args.source_path


def _source_from_image(ref: str, path_in_image: str) -> str:
    """Copy `path_in_image` out of a docker image or container into a temp dir.

    Works for an image (a throwaway container is created and removed) or a
    running/stopped container. The copied tree is untrusted data: it is only
    parsed, never executed."""
    import shutil
    import subprocess
    import tempfile

    if shutil.which("docker") is None:
        raise RuntimeError("--source-image needs docker on PATH")
    workdir = Path(tempfile.mkdtemp(prefix="elenchus-src-"))
    destination = workdir / "source"
    created = subprocess.run(
        ["docker", "create", ref], capture_output=True, text=True, check=False
    )
    container, remove = (created.stdout.strip(), True) if created.returncode == 0 else (ref, False)
    try:
        copy = subprocess.run(
            ["docker", "cp", f"{container}:{path_in_image}", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        if copy.returncode != 0:
            raise RuntimeError(f"could not copy source from {ref!r}: {copy.stderr.strip()}")
    finally:
        if remove:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True, check=False)
    print(f"elenchus: copied source from {ref}:{path_in_image} to {destination}", file=sys.stderr)
    return str(destination)


def _run_pipeline(args: argparse.Namespace, run_id: str, config: Any) -> _PipelineOutput:
    """Stages 0 to 4: index, static, hypotheses, preflight, ZAP probe.

    Static findings carry their own status (untested, no_http_path, ...); probe
    findings carry ORACLE evidence and lineage. Correlation links the two.
    """
    from cli.zap_setup import ensure_zap_api_available, load_or_create_zap_api_key
    from probe.coordinator import Coordinator, plan_directed_jobs, plan_sweep_jobs
    from probe.oracles import ORACLES
    from probe.preflight import check_loopback, detect_context_path, probe_extras
    from producers.dast.zap_runner import ZapApi
    from producers.hypotheses.builder import build_directed, build_sweep, skipped_by_type
    from producers.sast.code_index import build_code_index
    from producers.sast.response_trace import parse_java_response_trace
    from producers.sast.static_stage import run_static

    progress = _create_progress(getattr(args, "no_progress", False))
    with progress:
        _progress_step(progress, "Preflight checks", lambda: check_loopback(args.base_url))
        target = ScanTarget(args.source_path, args.base_url, run_id, args.framework)
        index = _progress_step(
            progress, "Building route table", lambda: build_code_index(args.source_path)
        )
        static_findings = _progress_step(
            progress, "Running static analysis", lambda: run_static(target, index)
        )

        def collect_hypotheses() -> tuple[list[Any], tuple[tuple[str, str, str], ...]]:
            directed = build_directed(static_findings, index, narrow=config["flow.enabled"])
            # Sweep classes with both a ZAP rule and runtime oracle for bugs the
            # static stage missed. The scheduler runs these after directed jobs.
            sweep_cwes = sorted(set(ORACLES) & set(config.rule_map()))
            sweep = build_sweep(index, sweep_cwes)
            skipped = tuple(skipped_by_type(index))
            jobs = plan_directed_jobs(directed, index.routes, run_id) + plan_sweep_jobs(
                sweep, index.routes, run_id
            )
            return jobs, skipped

        jobs, skipped = _progress_step(progress, "Collecting hypotheses", collect_hypotheses)
        context = _progress_step(
            progress,
            "Detecting application context",
            lambda: detect_context_path(args.source_path, args.base_url),
        )

        def start_zap() -> ZapApi:
            api_url = os.environ.get("ZAP_API_URL", config["zap.api_url"])
            if not isinstance(api_url, str):
                raise ValueError("zap.api_url must be a string")
            api_key = load_or_create_zap_api_key(config["zap.api_key"])
            api = ZapApi(api_url, api_key)
            ensure_zap_api_available(api, api_url, api_key)
            return api

        api = _progress_step(progress, "Starting local ZAP API", start_zap)
        preflight_extras = _progress_step(
            progress, "Checking target baseline", lambda: probe_extras(api, args.base_url).to_dict()
        )
        coordinator = Coordinator(
            api,
            config,
            args.base_url,
            context,
            enum_types=index.enum_types,
            trace_parser=lambda body: parse_java_response_trace(body, args.source_path),
        )
        probe_task = progress.add_task("Probing with ZAP", total=None)
        result = coordinator.run(run_id, jobs, index.routes)
        progress.update(
            probe_task,
            total=1,
            completed=1,
            description="ZAP probe stage complete",
        )
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
        index=index,
        advisory_alerts=tuple(result.advisory_alerts),
        preflight_extras=preflight_extras,
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


def _apply_ai_advice(issues: list[Issue], config: Any) -> list[Issue]:
    """Attach advisory fix text and link explanations when an AI task is on.

    Advisory only: it never changes a verdict, label, link or confidence. Off by
    default and in judging mode, so this is a no-op on a normal run.
    """
    if not any(config.task_enabled(task) for task in ("fix_text", "link_explanation")):
        return issues
    from ai.advisor import annotate
    from ai.client import AiClient

    return annotate(issues, AiClient(config))


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


def _run_compare(args: argparse.Namespace) -> int:
    """Read two stored runs and classify their issues (B-5)."""
    from engine.compare import compare_runs
    from engine.store import PostgresStore

    store = PostgresStore(args.database_url)
    base = store.read_run_issues(args.base)
    current = store.read_run_issues(args.current)
    comparison = compare_runs(
        base, current, base_run_id=args.base, current_run_id=args.current
    )
    if args.output_format == "json":
        print(json.dumps(comparison.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_comparison(comparison))
    return 0


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
