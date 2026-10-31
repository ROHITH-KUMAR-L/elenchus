"""Stage 1: the code index. Route table, param bindings and call graph.

    uv run python -m producers.sast.code_index <target-source-root>

prints the counts the BS2 exit test records.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from common.pipeline import CodeIndex, SecretSite
from common.record import RouteEntry
from producers.sast.call_graph import build_call_graph
from producers.sast.secrets import find_secrets
from producers.sast.sink_finder import find_sinks, load_catalogue
from producers.sast.spring_routes import _build_entries, _parse_files, build_index


def build_code_index(source_root: str | Path) -> CodeIndex:
    files = _parse_files(Path(source_root))
    index = build_index(files)
    return CodeIndex(
        routes=tuple(RouteEntry.from_dict(entry) for entry in _build_entries(index)),
        call_graph=build_call_graph(index),
        sinks=tuple(find_sinks(index, load_catalogue())),
        enum_types=frozenset(
            name
            for name, infos in index.types.items()
            if any(info["kind"] == "enum_declaration" for info in infos)
        ),
        secrets=tuple(
            SecretSite(f.cwe, f.type_name, f.severity, f.file, f.line, f.rule, f.snippet)
            for f in find_secrets(files)
        ),
    )


def summary(index: CodeIndex) -> dict[str, Any]:
    routes = index.routes
    edges = index.call_graph
    resolved = [edge for edge in edges if edge.resolved]
    return {
        "routes": len(routes),
        "routes_by_method": dict(sorted(Counter(r.method for r in routes).items())),
        "params": sum(len(r.params) for r in routes),
        "params_by_location": dict(sorted(Counter(p.source for r in routes for p in r.params).items())),
        "params_status": dict(sorted(Counter(r.params_status for r in routes).items())),
        "call_sites": len({(e.file, e.line, e.col) for e in edges}),
        "edges": len(edges),
        "edges_into_source": sum(1 for e in resolved if e.callee_file is not None),
        "edges_unresolved": len(edges) - len(resolved),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m producers.sast.code_index <target-source-root>")
    print(json.dumps(summary(build_code_index(sys.argv[1])), indent=2))
