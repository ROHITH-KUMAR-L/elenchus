"""Throwaway live check: confirm command injection, XSS and open redirect against
a running VulnerableApp, using the coordinator's project-controlled confirmation
passes through ZAP. Not pipeline code; it may name the practice app, like the
bs0/bs4 checks. Run with ZAP on loopback and ELENCHUS_BASE_URL set.

    ZAP_API_KEY=... ELENCHUS_BASE_URL=http://127.0.0.1:9090/VulnerableApp \
        uv run --locked python scripts/bs10_live_check.py
"""

from __future__ import annotations

import os
import sys

from common.config import load_config
from common.pipeline import ProbeJob, SeedRequest
from probe.coordinator import (
    Coordinator,
    _command_payloads,
    _redirect_payloads,
    _response,
    _xss_payloads,
)
from probe.oracles import command_output, open_redirect, xss_reflected
from probe.preflight import ContextPath
from producers.dast.zap_runner import ZapApi

# (route, cwe, param, oracle, payload-maker). Param values are read from the
# handlers in VulnerableApp source at the pinned commit.
CASES = [
    ("/CommandInjection/LEVEL_1", 78, "ipaddress", command_output, _command_payloads),
    ("/XSSWithHtmlTagInjection/LEVEL_1", 79, "input", xss_reflected, _xss_payloads),
    ("/Http3xxStatusCodeBasedInjection/LEVEL_1", 601, "returnTo", open_redirect, _redirect_payloads),
]


def main() -> int:
    base = os.environ.get("ELENCHUS_BASE_URL")
    if not base:
        print("set ELENCHUS_BASE_URL", file=sys.stderr)
        return 2
    config = load_config(overrides={"target.base_url": base})
    coordinator = Coordinator(ZapApi.from_environment(), config, base, ContextPath("", "none"))

    ok = True
    for route, cwe, param, oracle, payloads in CASES:
        seed = SeedRequest(url=f"{base.rstrip('/')}{route}?{param}=1", method="GET")
        job = ProbeJob(
            job_id="check", route=route, method="GET", job_pass="directed",
            hypothesis_ids=("h-check",), cwes=(cwe,), seed_request=seed, canary="elx-check",
        )
        baseline = _response(coordinator.api.send_request(coordinator._raw(seed)))
        findings = coordinator._confirm_injection(
            "check", job, seed, baseline, cwe, oracle, payloads, set()
        )
        status = "PASS" if findings else "FAIL"
        ok = ok and bool(findings)
        payload = findings[0].payload if findings else "-"
        print(f"CWE-{cwe:<3} {route:<40} {status}  payload={payload}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
