"""BS4 live check: run the directed SQL probe spine against local VulnerableApp.

Not pipeline code; the CLI wiring is BS5. It builds the index, the SQL directed
hypotheses and the probe jobs, runs the coordinator against the running target,
and prints the metrics the BS4 exit test records.

    export ZAP_API_KEY=<key ZAP was started with>
    uv run python scripts/bs4_live_check.py --source .targets/VulnerableApp \
        --base-url http://127.0.0.1:9090/VulnerableApp
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from common.config import load_config
from common.record import ScanTarget
from probe.coordinator import Coordinator, plan_directed_jobs
from probe.preflight import check_loopback, detect_context_path
from producers.dast.zap_runner import ZapApi
from producers.hypotheses.builder import build_directed
from producers.sast.code_index import build_code_index
from producers.sast.static_stage import run_static


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=".targets/VulnerableApp")
    parser.add_argument("--base-url", default="http://127.0.0.1:9090/VulnerableApp")
    parser.add_argument("--run-id", default="bs4")
    args = parser.parse_args()

    check_loopback(args.base_url)
    config = load_config(overrides={"target.base_url": args.base_url})
    target = ScanTarget(args.source, args.base_url, args.run_id, "spring-mvc")

    index = build_code_index(Path(args.source))
    static_findings = run_static(target, index)
    directed = [h for h in build_directed(static_findings, index) if h.cwe == 89]
    jobs = plan_directed_jobs(directed, index.routes, args.run_id)
    print(f"directed SQL hypotheses: {len(directed)}; jobs: {len(jobs)}", file=sys.stderr)

    context = detect_context_path(args.source, args.base_url)
    coordinator = Coordinator(ZapApi.from_environment(), config, args.base_url, context)
    result = coordinator.run(args.run_id, jobs, index.routes)

    print(
        json.dumps(
            {
                "context_path": [context.value, context.source],
                "jobs_run": len(result.jobs),
                "job_outcomes": sorted({job.outcome for job in result.jobs}),
                "confirmed_findings": len(result.findings),
                "attribution_rate": round(result.attribution_rate, 3),
                "header_propagation_rate": round(result.header_propagation_rate, 3),
                "foreign_hosts": result.foreign_hosts,
                "findings": [
                    {
                        "route": f.route,
                        "param": f.param,
                        "cwe": f.cwe,
                        "payload": f.payload,
                        "hypothesis_id": f.hypothesis_id,
                        "fired": f.detail("fired"),
                    }
                    for f in result.findings
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
