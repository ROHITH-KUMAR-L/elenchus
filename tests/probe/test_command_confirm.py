"""Project-controlled command-injection confirmation pass."""

from __future__ import annotations

from common.config import load_config
from common.pipeline import ProbeJob, SeedRequest
from probe.coordinator import Coordinator
from probe.oracles import Response
from probe.preflight import ContextPath

BASE = "http://127.0.0.1:9090/VulnerableApp"
ROUTE = "/CommandInjection/LEVEL_1"
# The replay URL-encodes the shell separators the pass appends.
_SEPARATOR_ENCODINGS = ("%3B", "%26", "%7C", "%60", "%24")
BASELINE = Response(status=200, headers="HTTP/1.1 200 OK\r\n", body="PING 1 (1): 2 packets transmitted")


class CommandZap:
    """Returns `id` output when a request carries an injected shell separator;
    plain ping output otherwise. base_url kept for the coordinator's host check."""

    base_url = "http://127.0.0.1:8090"

    def __init__(self, *, vulnerable=True):
        self._vulnerable = vulnerable

    def send_request(self, raw_request, follow_redirects=False):
        injected = any(code in raw_request for code in _SEPARATOR_ENCODINGS)
        if injected and self._vulnerable:
            body = "PING 1 ...\nuid=0(root) gid=0(root) groups=0(root)\n"
        else:
            body = "PING 1 (1): 2 packets transmitted"
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": body}


def job():
    return ProbeJob(
        job_id="run-j0", route=ROUTE, method="GET", job_pass="directed",
        hypothesis_ids=("h-1",), cwes=(78,),
        seed_request=SeedRequest(url=f"{BASE}{ROUTE}?ipaddress=1", method="GET"), canary="elx-run-j0",
    )


def coordinator(fake):
    config = load_config(overrides={"target.base_url": BASE}, environ={"ZAP_API_KEY": "k"})
    return Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))


def seed():
    return SeedRequest(url=f"{BASE}{ROUTE}?ipaddress=1", method="GET")


def test_command_injection_is_confirmed_by_id_output():
    findings = coordinator(CommandZap())._confirm_command("run", job(), seed(), BASELINE, set())
    assert len(findings) == 1
    assert findings[0].cwe == 78
    assert findings[0].param == "ipaddress"
    assert findings[0].detail("oracle") == "command_output"
    assert findings[0].detail("fired") >= 2


def test_no_command_output_makes_no_finding():
    findings = coordinator(CommandZap(vulnerable=False))._confirm_command(
        "run", job(), seed(), BASELINE, set()
    )
    assert findings == []


def test_already_confirmed_param_is_skipped():
    findings = coordinator(CommandZap())._confirm_command("run", job(), seed(), BASELINE, {"ipaddress"})
    assert findings == []
