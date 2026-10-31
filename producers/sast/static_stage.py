"""Stage 2: static findings. Walks the call graph backward from each sink to the
routes that reach it. The result gives route and call path, never the param.

    uv run python -m producers.sast.static_stage <target-source-root>
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from common.pipeline import CallGraphEdge, CodeIndex, SinkSite
from common.record import Finding, RouteEntry, ScanTarget
from producers.sast.code_index import build_code_index


def _callers(index: CodeIndex) -> dict[str, list[CallGraphEdge]]:
    callers: dict[str, list[CallGraphEdge]] = defaultdict(list)
    for edge in index.call_graph:
        if edge.resolved and edge.callee_file is not None:
            callers[edge.callee].append(edge)
    return callers


def _walk_to_handlers(
    method: str, callers: dict[str, list[CallGraphEdge]], handlers: set[str]
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    """Shortest call chain from each reachable handler to method, and every
    method the walk visited."""
    chains: dict[str, list[dict[str, Any]]] = {}
    seen = {method}
    queue: deque[tuple[str, list[dict[str, Any]]]] = deque([(method, [])])
    while queue:
        current, tail = queue.popleft()
        if current in handlers and current not in chains:
            chains[current] = tail
        for edge in callers.get(current, ()):
            if edge.caller not in seen:
                seen.add(edge.caller)
                queue.append((edge.caller, [{"caller": edge.caller, "callee": current, "edge": edge}, *tail]))
    return chains, seen


def _chain_hops(handler: RouteEntry, tail: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain = [{"method": handler.func, "file": handler.file, "line": handler.line_start}]
    for step in tail:
        edge = step["edge"]
        chain.append({"method": step["callee"], "file": edge.callee_file, "line": edge.line})
    return chain


def _unresolved_call_could_reach(index: CodeIndex, visited: set[str]) -> bool:
    names = {method.rsplit(".", 1)[-1] for method in visited}
    return any(
        not edge.resolved and edge.callee.rsplit(".", 1)[-1] in names for edge in index.call_graph
    )


def _finding(target: ScanTarget, index: CodeIndex, site: SinkSite, callers, routes_by_func) -> Finding:
    chains, visited = _walk_to_handlers(site.sink_id.enclosing_method, callers, set(routes_by_func))
    entry_paths = []
    params: set[str] = set()
    for func, tail in sorted(chains.items()):
        for entry in sorted(routes_by_func[func], key=lambda r: (r.route, r.method)):
            entry_paths.append(
                {
                    "route": entry.route,
                    "method": entry.method,
                    "hops": len(tail),
                    "call_chain": _chain_hops(entry, tail),
                }
            )
            params.update(p.name for p in entry.params)
    only = entry_paths[0] if len(entry_paths) == 1 else None
    unlinked_reason = None
    if site.arg_shape in {"constant", "sanitised"}:
        status = "safe_pattern"
    elif not entry_paths:
        status = "no_http_path"
        unlinked_reason = (
            "walk_unresolved" if _unresolved_call_could_reach(index, visited) else "no_callers"
        )
    else:
        status = "untested"
    return Finding.from_dict(
        {
            "run_id": target.run_id,
            "source": "sast",
            "provenance": "own",
            "cwe": site.cwe,
            "type": site.type_name,
            "route": only["route"] if only else None,
            "method": only["method"] if only else None,
            "file": site.sink_id.file,
            "line": site.line,
            "sink_id": site.sink_id.to_dict(),
            "arg_shape": site.arg_shape,
            "entry_paths": entry_paths or None,
            "candidate_params": sorted(params) if entry_paths else None,
            "match_mode": site.match_mode,
            "evidence": [
                {
                    "type": "PATH",
                    "detail": {"snippet": site.snippet, "catalogue_entry": site.catalogue_entry},
                }
            ],
            "status": status,
            "unlinked_reason": unlinked_reason,
            "severity": site.severity,
        }
    )


def run_static(target: ScanTarget, index: CodeIndex) -> list[Finding]:
    callers = _callers(index)
    routes_by_func: dict[str, list[RouteEntry]] = defaultdict(list)
    for entry in index.routes:
        routes_by_func[entry.func].append(entry)
    return [_finding(target, index, site, callers, routes_by_func) for site in index.sinks]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m producers.sast.static_stage <target-source-root>")
    scan = ScanTarget(sys.argv[1], "http://localhost/", "static", "spring-mvc")
    code_index = build_code_index(Path(sys.argv[1]))
    findings = run_static(scan, code_index)
    print(
        json.dumps(
            {
                "sinks": len(findings),
                "by_shape": dict(Counter(f.arg_shape for f in findings)),
                "by_status": dict(Counter(f"{f.status}:{f.unlinked_reason}" for f in findings)),
                "by_entry": dict(Counter(f.detail("catalogue_entry") for f in findings)),
            },
            indent=2,
        )
    )
