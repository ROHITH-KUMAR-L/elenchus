"""Score static and runtime findings against explicit ground-truth snapshots.

The JSON snapshots are measurement inputs only. They are never imported by the
scanner pipeline, probe planner, or correlation engine.

    uv run python -m producers.benchmark sast <source-root> --expected <snapshot>
    uv run python -m producers.benchmark dast <scan-issues.json> --expected <snapshot>
    uv run python -m producers.benchmark snapshot --source-root <root> --base-url <loopback-url> ...
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

from common.config import load_config
from common.record import ScanTarget, normalize_file
from common.vocabulary import grader_cwe, to_grader_sast
from producers.sast.code_index import build_code_index
from producers.sast.static_stage import run_static

_ENUM_ROW = re.compile(
    r"^\s*([A-Z][A-Z0-9_]*)\((null|\d+),\s*(null|\d+)\)[,;]?\s*(?://.*)?$"
)


class ExpectedIssue(TypedDict):
    cwe: str
    type: str
    file: str
    line: int


class SastScore(TypedDict):
    matched: set[int]
    unmatched: list[dict[str, Any]]


def load_expected(root: Path, ground_truth_csv: Path) -> list[ExpectedIssue]:
    csv_path = _source_path(root, ground_truth_csv)
    with csv_path.open(newline="", encoding="utf-8") as handle:
        expected = []
        for row in csv.DictReader(handle):
            file = normalize_file(row["File"].strip())
            if file is None:
                raise ValueError("ground-truth file path must not be empty")
            expected.append(
                ExpectedIssue(
                    cwe=row["CWE"].strip().upper(),
                    type=row["Vulnerability Type"].strip().lower(),
                    file=file,
                    line=int(row["Line"]),
                )
            )
        return expected


def score_sast(
    expected: list[ExpectedIssue], reported: list[dict[str, Any]]
) -> SastScore:
    """Apply the target grader's exact file/line plus CWE-or-type matching rule."""
    matched: set[int] = set()
    unmatched = []
    for item in reported:
        file, line = normalize_file(item["filePath"]), item["line"]
        cwe, kind = item["cwe"].strip().upper(), item["type"].strip().lower()
        hits = [
            i
            for i, ground_truth in enumerate(expected)
            if ground_truth["file"] == file
            and ground_truth["line"] == line
            and (ground_truth["cwe"] == cwe or ground_truth["type"] == kind)
        ]
        matched.update(hits)
        if not hits:
            unmatched.append(item)
    return {"matched": matched, "unmatched": unmatched}


def score_dast(
    expected: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    supported_cwes: set[str],
) -> dict[str, Any]:
    """Score only issues with runtime evidence using route, method and CWE/type.

    One observed CWE can match multiple target vulnerability types on the same
    route, consistent with the target comparator's URL+method+CWE semantics.
    """
    runtime = [issue for issue in issues if issue.get("dast_findings")]
    normalized_issues = [
        {
            "issue": issue,
            "route": _normalize_route(issue.get("route")),
            "method": _normalize_method(issue.get("method")),
            "cwe": grader_cwe(int(issue["cwe"])) if issue.get("cwe") is not None else None,
            "type": _normalize_type(issue.get("type")),
        }
        for issue in runtime
    ]

    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    misses = []
    matched_indexes: set[int] = set()
    for index, row in enumerate(expected):
        route = _normalize_route(row.get("route"))
        method = _normalize_method(row.get("method"))
        cwe = _normalize_cwe(row.get("cwe"))
        kind = _normalize_type(row.get("type"))
        found = any(
            item["route"] == route
            and item["method"] == method
            and (
                (cwe is not None and item["cwe"] == cwe)
                or (kind and item["type"] == kind)
            )
            for item in normalized_issues
        )
        if found:
            matched_indexes.add(index)
        else:
            misses.append(
                {
                    "route": row.get("route"),
                    "method": row.get("method"),
                    "type": row.get("type"),
                    "cwe": row.get("cwe"),
                }
            )
        by_type[str(row.get("type"))].append({"found": found, "cwe": cwe})

    supported_indices = {
        index
        for index, row in enumerate(expected)
        if _normalize_cwe(row.get("cwe")) in supported_cwes
    }
    per_type = {
        kind: {
            "found": sum(item["found"] for item in rows),
            "expected": len(rows),
            "recall": (
                sum(item["found"] for item in rows) / len(rows) if rows else None
            ),
        }
        for kind, rows in sorted(by_type.items())
    }
    matched_supported = len(matched_indexes & supported_indices)
    return {
        "expected_count": len(expected),
        "runtime_issue_count": len(runtime),
        "matched_count": len(matched_indexes),
        "raw_score": _score(len(matched_indexes), len(expected)),
        "supported_score": _score(matched_supported, len(supported_indices)),
        "supported_cwes": sorted(supported_cwes, key=lambda value: int(value[4:])),
        "recall_by_type": per_type,
        "misses": misses,
        "runtime_issues_without_expected_match": [
            issue.get("issue_key")
            for item in normalized_issues
            if not any(
                _normalize_route(row.get("route")) == item["route"]
                and _normalize_method(row.get("method")) == item["method"]
                and (
                    (
                        _normalize_cwe(row.get("cwe")) is not None
                        and _normalize_cwe(row.get("cwe")) == item["cwe"]
                    )
                    or (
                        _normalize_type(row.get("type"))
                        and _normalize_type(row.get("type")) == item["type"]
                    )
                )
                for row in expected
            )
            for issue in [item["issue"]]
        ],
    }


def snapshot_ground_truth(
    source_root: Path,
    base_url: str,
    sast_ground_truth: Path,
    type_metadata_path: Path,
    dast_endpoint: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture local target ground truth without adding runtime parameters."""
    parsed_base = urlsplit(base_url)
    if not _is_loopback_http(parsed_base):
        raise ValueError("benchmark base URL must be an http URL on loopback")
    parsed_endpoint = urlsplit(dast_endpoint)
    if not _is_loopback_http(parsed_endpoint):
        raise ValueError("DAST ground-truth endpoint must be an http URL on loopback")

    commit = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    source_path = _source_path(source_root, type_metadata_path)
    type_metadata = _load_type_metadata(source_path)
    captured_at = datetime.now(UTC).isoformat()
    source = {
        "source_commit": commit,
        "captured_at": captured_at,
        "sast_source": str(sast_ground_truth),
        "dast_endpoint": dast_endpoint,
    }

    sast_csv = _source_path(source_root, sast_ground_truth)
    sast_expected = load_expected(source_root, sast_ground_truth)
    sast = {
        "schema_version": 1,
        "benchmark": "SAST",
        "source": source,
        "expected": [
            {
                **row,
                "number_of_sources": _number_of_sources(sast_csv, row),
            }
            for row in sast_expected
        ],
    }

    dast_rows = _fetch_json(dast_endpoint)
    if not isinstance(dast_rows, list):
        raise ValueError("the DAST ground-truth endpoint must return a JSON array")
    context_path = parsed_base.path.rstrip("/")
    dast_expected = []
    seen: set[tuple[str, str, str]] = set()
    for route_record in dast_rows:
        if not isinstance(route_record, dict):
            raise ValueError("each DAST ground-truth row must be an object")
        if str(route_record.get("variant", "")).casefold() != "unsecure":
            continue
        route = _normalize_target_url(route_record.get("url"), context_path)
        method = _normalize_method(route_record.get("method"))
        types = route_record.get("vulnerabilityTypes")
        if not isinstance(types, list):
            raise ValueError("DAST ground-truth vulnerabilityTypes must be an array")
        for vulnerability_type in types:
            if not isinstance(vulnerability_type, str) or vulnerability_type not in type_metadata:
                raise ValueError(f"unknown DAST vulnerability type: {vulnerability_type!r}")
            key = (route, method, vulnerability_type)
            if key in seen:
                continue
            seen.add(key)
            metadata = type_metadata[vulnerability_type]
            dast_expected.append(
                {
                    "route": route,
                    "method": method,
                    "type": vulnerability_type,
                    "cwe": f"CWE-{metadata['cwe']}" if metadata["cwe"] is not None else None,
                    "wasc_id": metadata["wasc_id"],
                }
            )
    dast = {
        "schema_version": 1,
        "benchmark": "DAST",
        "source": source,
        "expected": dast_expected,
    }
    return sast, dast


def _number_of_sources(csv_path: Path, expected: ExpectedIssue) -> int:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if (
                normalize_file(row["File"].strip()) == expected["file"]
                and int(row["Line"]) == expected["line"]
                and row["CWE"].strip().upper() == expected["cwe"]
            ):
                return int(row["Number of Sources"])
    raise ValueError(f"could not find source count for {expected['file']}:{expected['line']}")


def _source_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _is_loopback_http(parsed_url: Any) -> bool:
    return parsed_url.scheme == "http" and parsed_url.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
    }


def _load_type_metadata(path: Path) -> dict[str, dict[str, int | None]]:
    metadata = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ENUM_ROW.match(line)
        if not match:
            continue
        name, cwe, wasc_id = match.groups()
        metadata[name] = {
            "cwe": int(cwe) if cwe != "null" else None,
            "wasc_id": int(wasc_id) if wasc_id != "null" else None,
        }
    if not metadata:
        raise ValueError(f"no vulnerability type metadata found in {path}")
    return metadata


def _fetch_json(url: str) -> Any:
    class RejectRedirects(HTTPRedirectHandler):
        def redirect_request(self, request, file, code, message, headers, new_url):
            return None

    opener = build_opener(RejectRedirects())
    with opener.open(url, timeout=15) as response:
        if not _is_loopback_http(urlsplit(response.geturl())):
            raise ValueError("DAST ground-truth response resolved to a non-loopback URL")
        return json.load(response)


def _normalize_target_url(value: Any, context_path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("DAST ground-truth URL must be a non-empty string")
    parsed = urlsplit(value)
    if parsed.scheme and parsed.hostname not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
        raise ValueError("DAST ground-truth endpoint returned a non-loopback URL")
    route = parsed.path or "/"
    if context_path and (route == context_path or route.startswith(context_path + "/")):
        route = route[len(context_path) :] or "/"
    return _normalize_route(route)


def _normalize_route(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    route = urlsplit(value).path or "/"
    if len(route) > 1:
        route = route.rstrip("/")
    return route if route.startswith("/") else f"/{route}"


def _normalize_method(value: Any) -> str:
    return str(value or "ANY").strip().upper()


def _normalize_type(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return re.sub(r"[^A-Z0-9]+", "_", value.strip().upper()).strip("_")


def _normalize_cwe(value: Any) -> str | None:
    if value is None:
        return None
    digits = re.sub(r"\D", "", str(value))
    return f"CWE-{int(digits)}" if digits else None


def _score(found: int, expected: int) -> dict[str, Any]:
    return {
        "found": found,
        "expected": expected,
        "recall": found / expected if expected else None,
    }


def _write_snapshot(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_snapshot(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"{path}: unsupported benchmark snapshot schema")
    expected = value.get("expected")
    if not isinstance(expected, list) or not all(isinstance(row, dict) for row in expected):
        raise ValueError(f"{path}: expected an expected array of objects")
    return expected


def _load_issue_records(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    records = value.get("issues") if isinstance(value, dict) else value
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise ValueError(f"{path}: expected an issue array or object with an issues array")
    return records


def _run_sast(source_root: Path, snapshot: Path) -> dict[str, Any]:
    target = ScanTarget(
        str(source_root),
        "http://localhost/",
        "benchmark",
        "spring-mvc",
    )
    reported = to_grader_sast(run_static(target, build_code_index(source_root)))
    expected = _load_snapshot(snapshot)
    result = score_sast(expected, reported)
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for index, row in enumerate(expected):
        cwe = _normalize_cwe(row["cwe"])
        if cwe is not None:
            counts[cwe][1] += 1
            counts[cwe][0] += index in result["matched"]
    supported = {
        grader_cwe(cwe)
        for cwe in load_config().rule_map()
    }
    supported_rows = {
        index
        for index, row in enumerate(expected)
        if _normalize_cwe(row["cwe"]) in supported
    }
    matched_supported = len(result["matched"] & supported_rows)
    return {
        "reported_count": len(reported),
        "expected_count": len(expected),
        "matched_count": len(result["matched"]),
        "raw_score": _score(len(result["matched"]), len(expected)),
        "supported_score": _score(matched_supported, len(supported_rows)),
        "supported_cwes": sorted(supported, key=lambda value: int(value[4:])),
        "recall_by_cwe": {
            cwe: _score(values[0], values[1])
            for cwe, values in sorted(counts.items(), key=lambda item: int(item[0][4:]))
        },
        "misses": [
            row for index, row in enumerate(expected) if index not in result["matched"]
        ],
        "reported_without_expected_match": result["unmatched"],
    }


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Measure findings against target ground truth.")
    commands = parser.add_subparsers(dest="command", required=True)
    sast_parser = commands.add_parser("sast", help="score source findings against SAST ground truth")
    sast_parser.add_argument("source_root", type=Path)
    sast_parser.add_argument(
        "--expected",
        required=True,
        type=Path,
        help="SAST ground-truth JSON snapshot",
    )
    dast_parser = commands.add_parser("dast", help="score runtime findings against DAST ground truth")
    dast_parser.add_argument("issues", type=Path, help="JSON output from elenchus scan --output-format json")
    dast_parser.add_argument(
        "--expected",
        type=Path,
        required=True,
        help="DAST ground-truth JSON snapshot",
    )
    dast_parser.add_argument(
        "--config",
        type=Path,
        help="optional TOML config for supported CWE scope",
    )
    snapshot_parser = commands.add_parser(
        "snapshot",
        help="refresh full measurement-only snapshots from a local target",
    )
    snapshot_parser.add_argument("--source-root", required=True, type=Path)
    snapshot_parser.add_argument("--base-url", required=True)
    snapshot_parser.add_argument("--sast-ground-truth", required=True, type=Path)
    snapshot_parser.add_argument("--type-metadata", required=True, type=Path)
    snapshot_parser.add_argument("--dast-endpoint", required=True)
    snapshot_parser.add_argument("--sast-output", required=True, type=Path)
    snapshot_parser.add_argument("--dast-output", required=True, type=Path)
    args = parser.parse_args(argv[1:])

    if args.command == "snapshot":
        sast, dast = snapshot_ground_truth(
            args.source_root,
            args.base_url,
            args.sast_ground_truth,
            args.type_metadata,
            args.dast_endpoint,
        )
        _write_snapshot(args.sast_output, sast)
        _write_snapshot(args.dast_output, dast)
        print(
            f"SAST snapshot: {len(sast['expected'])} expected rows\n"
            f"DAST snapshot: {len(dast['expected'])} expected route/method/type rows\n"
            f"SAST output: {args.sast_output}\n"
            f"DAST output: {args.dast_output}"
        )
        return 0

    if args.command == "sast":
        report = _run_sast(args.source_root, args.expected)
    else:
        expected = _load_snapshot(args.expected)
        issues = _load_issue_records(args.issues)
        config = load_config(path=args.config)
        supported = {grader_cwe(cwe) for cwe in config.rule_map()}
        report = score_dast(expected, issues, supported)

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
