"""Optional Semgrep adapter: findings joined to the route map.

Off by default. No pipeline stage may require it, so it is installed with
`uv sync --extra semgrep`. run_sast(target, route_map) runs our Semgrep rules,
ingests the SARIF output, and returns canonical Finding records:

- entry_paths lists every route whose handler contains the sink or calls the
  method that does. route and method are set only when exactly one path exists.
- It never claims a param. candidate_params lists the params of those routes.
- Taint findings that no route reaches are dropped: no URL can trigger them.
  Pattern findings (rules/java-pattern.yaml, e.g. hard-coded secrets) are kept
  without a route; they are Code-only by nature.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from common.record import CallEdge, Finding, RouteEntry, RouteMap, ScanTarget
from common.vocabulary import type_name

RULES_DIR = Path(__file__).parent / "rules"
TAINT_RULES = RULES_DIR / "java-injection.yaml"
PATTERN_RULES = RULES_DIR / "java-pattern.yaml"

SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def run_sast(target: ScanTarget, route_map: RouteMap) -> list[Finding]:
    """Producer entry (D-16)."""
    findings = []
    for rules, needs_route in ((TAINT_RULES, True), (PATTERN_RULES, False)):
        if not rules.exists():
            continue
        for result, rule in _sarif_results(_run_semgrep(target.source_path, rules)):
            finding = _to_finding(target, route_map, result, rule, needs_route)
            if finding is not None:
                findings.append(finding)
    return findings


def _run_semgrep(source_path: str, rules: Path) -> dict[str, Any]:
    semgrep = shutil.which("semgrep")
    if semgrep is None:
        raise RuntimeError("semgrep not found; install the optional adapter with `uv sync --extra semgrep`")
    completed = subprocess.run(
        [
            semgrep, "scan",
            "--config", str(rules),
            "--sarif",
            "--metrics=off",
            "--disable-version-check",
            "--exclude", "src/test",
            ".",
        ],
        cwd=source_path,
        capture_output=True,
        text=True,
        check=False,
    )
    # Semgrep exits 0 with or without findings; anything else is a real failure.
    if completed.returncode != 0:
        raise RuntimeError(f"semgrep failed ({completed.returncode}): {completed.stderr.strip()[-500:]}")
    return json.loads(completed.stdout)


def _sarif_results(sarif: dict[str, Any]):
    for run in sarif.get("runs", []):
        rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}
        for result in run.get("results", []):
            yield result, rules.get(result["ruleId"], {})


def _rule_cwe(rule: dict[str, Any]) -> int:
    """CWE from the rule's `metadata.cwe`, which Semgrep emits as a numeric tag."""
    for tag in rule.get("properties", {}).get("tags", []):
        if str(tag).isdigit():
            return int(tag)
    raise ValueError(f"rule {rule.get('id')} has no numeric cwe metadata")


def _to_finding(
    target: ScanTarget,
    route_map: RouteMap,
    result: dict[str, Any],
    rule: dict[str, Any],
    needs_route: bool,
) -> Finding | None:
    location = result["locations"][0]["physicalLocation"]
    file = location["artifactLocation"]["uri"].removeprefix("./")
    line = location["region"]["startLine"]
    snippet = location["region"].get("snippet", {}).get("text", "").strip()

    paths: dict[tuple[str, str], dict[str, Any]] = {}
    params: set[str] = set()
    for entry in sorted(route_map, key=lambda e: (e.route, e.method)):
        if entry.file == file and entry.line_start <= line <= entry.line_end:
            paths[(entry.route, entry.method)] = _entry_path(entry, None)
        else:
            call = next(
                (c for c in entry.calls if c.file == file and c.line_start <= line <= c.line_end),
                None,
            )
            if call is None:
                continue
            paths.setdefault((entry.route, entry.method), _entry_path(entry, call))
        params.update(p.name for p in entry.params)
    if needs_route and not paths:
        return None

    single_route = next(iter(paths)) if len(paths) == 1 else None
    rule_id = result["ruleId"].rsplit(".", 1)[-1]
    cwe = _rule_cwe(rule)
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")

    return Finding.from_dict({
        "run_id": target.run_id,
        "source": "sast",
        "provenance": "semgrep",
        "cwe": cwe,
        "type": type_name(cwe),
        "route": single_route[0] if single_route else None,
        "method": single_route[1] if single_route else None,
        "file": file,
        "line": line,
        "entry_paths": list(paths.values()) or None,
        "candidate_params": sorted(params) if paths else None,
        "evidence": [
            {
                "type": "PATH",
                "detail": {
                    "scanner": "semgrep",
                    "rule_id": rule_id,
                    "scanner_severity": level,
                    "snippet": snippet,
                },
            }
        ],
        # Semgrep OSS emits no dataflow trace in SARIF or JSON for these rules.
        "taint_trace": None,
        "severity": SEVERITY.get(level, "medium"),
    })


def _entry_path(entry: RouteEntry, call: CallEdge | None) -> dict[str, Any]:
    chain = [{"method": entry.func, "file": entry.file, "line": entry.line_start}]
    if call is not None:
        chain.append(
            {"method": f"{call.type_name}.{call.method}", "file": call.file, "line": call.line_start}
        )
    return {"route": entry.route, "method": entry.method, "hops": len(chain) - 1, "call_chain": chain}
