"""SAST producer: Semgrep findings joined to the route map.

run_sast(target, route_map) runs our Semgrep rules, ingests the SARIF output,
and returns canonical Finding records. Each finding is joined to the route map:

- The sink sits inside a handler: handler_* fields are set (Tier A input), and
  route/method too when that handler serves exactly one route.
- reached_via lists every route whose handler contains the sink or calls the
  method that does (Tier B input, D-07).
- Taint findings that no route reaches are dropped: no URL can trigger them.
  Pattern findings (rules/java-pattern.yaml, e.g. hard-coded secrets) are kept
  without a route; they are Code-only by nature.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from common.record import Finding, RouteEntry, RouteMap, ScanTarget
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
        raise RuntimeError("semgrep not found; run inside the project environment (uv run)")
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

    handlers = [e for e in route_map if e.file == file and e.line_start <= line <= e.line_end]
    callers = [
        e for e in route_map
        if any(c.file == file and c.line_start <= line <= c.line_end for c in e.calls)
    ]
    reaching = list({(e.route, e.method, e.file, e.line_start): e for e in handlers + callers}.values())
    if needs_route and not reaching:
        return None

    spans = {(e.file, e.line_start, e.line_end) for e in handlers}
    handler = next(iter(spans)) if len(spans) == 1 else None
    single_route = handlers[0] if len(handlers) == 1 else None
    rule_id = result["ruleId"].rsplit(".", 1)[-1]
    cwe = _rule_cwe(rule)
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")

    return Finding.from_dict({
        "run_id": target.run_id,
        "source": "sast",
        "cwe": cwe,
        "type": type_name(cwe),
        "route": single_route.route if single_route else None,
        "method": single_route.method if single_route else None,
        "file": file,
        "line": line,
        "param": _infer_param(reaching, snippet),
        "payload": None,
        "handler_file": handler[0] if handler else None,
        "handler_line_start": handler[1] if handler else None,
        "handler_line_end": handler[2] if handler else None,
        "reached_via": [
            {
                "route": e.route,
                "method": e.method,
                "handler_file": e.file,
                "handler_line_start": e.line_start,
                "handler_line_end": e.line_end,
            }
            for e in sorted(reaching, key=lambda e: (e.route, e.method))
        ] or None,
        "evidence": {
            "scanner": "semgrep",
            "rule_id": rule_id,
            "scanner_severity": level,
            "snippet": snippet,
        },
        # Semgrep OSS emits no dataflow trace in SARIF or JSON for these rules.
        "taint_trace": None,
        "label": None,
        "confidence": None,
        "risk_score": None,
        "severity": SEVERITY.get(level, "medium"),
        "wasc_id": None,
    })


def _infer_param(reaching: list[RouteEntry], snippet: str) -> str | None:
    """Request param that most likely reaches the sink, or None if unsure.

    The param guard in correlation needs this to match the DAST param. Use the
    reaching routes' only param, else the one param named in the sink line.
    """
    names = sorted({p.name for e in reaching for p in e.params})
    if len(names) == 1:
        return names[0]
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", snippet))
    named = [n for n in names if n in words]
    return named[0] if len(named) == 1 else None
