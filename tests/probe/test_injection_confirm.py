"""Project-controlled confirmation of command injection, XSS and open redirect.

Each fake ZAP reflects the injected payload the way the matching VulnerableApp
route does (command output, verbatim markup, a redirect Location), so the class
oracle fires on the coordinator's own replay.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlsplit

from common.config import load_config
from common.pipeline import ProbeJob, SeedRequest
from probe.coordinator import (
    Coordinator,
    _command_payloads,
    _redirect_payloads,
    _xss_payloads,
)
from probe.oracles import Response, command_output, open_redirect, xss_reflected
from probe.preflight import ContextPath

BASE = "http://127.0.0.1:9090/VulnerableApp"


def _injected_value(raw_request: str) -> str:
    target = raw_request.splitlines()[0].split(" ")[1]
    pairs = parse_qsl(urlsplit(unquote(target)).query, keep_blank_values=True)
    return pairs[-1][1] if pairs else ""


def coordinator(fake):
    config = load_config(overrides={"target.base_url": BASE}, environ={"ZAP_API_KEY": "k"})
    return Coordinator(fake, config, BASE, ContextPath("/VulnerableApp", "config"))


def job(route, cwe, param, value="1"):
    return ProbeJob(
        job_id="run-j0", route=route, method="GET", job_pass="sweep",
        hypothesis_ids=("h-1",), cwes=(cwe,),
        seed_request=SeedRequest(url=f"{BASE}{route}?{param}={value}", method="GET"),
        canary="elx-run-j0",
    )


def seed(route, param, value="1"):
    return SeedRequest(url=f"{BASE}{route}?{param}={value}", method="GET")


class CommandZap:
    base_url = "http://127.0.0.1:8090"

    def send_request(self, raw, follow_redirects=False):
        value = _injected_value(raw)
        body = "uid=0(root) gid=0(root) groups=0(root)" if any(
            s in value for s in (";id", "&&id", "|id", "`id`", "$(id)", "& id", "&id")
        ) else "ping output"
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": body}


class XssZap:
    base_url = "http://127.0.0.1:8090"

    def send_request(self, raw, follow_redirects=False):
        value = _injected_value(raw)  # the route reflects the value verbatim into HTML
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": f"<div>{value}<div>"}


class RedirectZap:
    base_url = "http://127.0.0.1:8090"

    def send_request(self, raw, follow_redirects=False):
        value = _injected_value(raw)
        if value.startswith("http"):  # the route copies returnTo into Location
            return {"responseHeader": f"HTTP/1.1 302 Found\r\nLocation: {value}\r\n", "responseBody": ""}
        return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "home"}


BASE_200 = Response(status=200, headers="HTTP/1.1 200 OK\r\n", body="home")


def test_command_injection_confirmed():
    j = job("/CommandInjection/LEVEL_1", 78, "ipaddress")
    findings = coordinator(CommandZap())._confirm_injection(
        "run", j, seed("/CommandInjection/LEVEL_1", "ipaddress"), BASE_200, 78,
        command_output, _command_payloads, set(),
    )
    assert len(findings) == 1 and findings[0].cwe == 78
    assert findings[0].detail("oracle") == "command_output"


def test_reflected_xss_confirmed():
    j = job("/XSSWithHtmlTagInjection/LEVEL_1", 79, "x")
    findings = coordinator(XssZap())._confirm_injection(
        "run", j, seed("/XSSWithHtmlTagInjection/LEVEL_1", "x"), BASE_200, 79,
        xss_reflected, _xss_payloads, set(),
    )
    assert len(findings) == 1 and findings[0].cwe == 79
    assert findings[0].detail("oracle") == "xss_reflected"


def test_open_redirect_confirmed():
    j = job("/Http3xxStatusCodeBasedInjection/LEVEL_1", 601, "returnTo")
    findings = coordinator(RedirectZap())._confirm_injection(
        "run", j, seed("/Http3xxStatusCodeBasedInjection/LEVEL_1", "returnTo"), BASE_200, 601,
        open_redirect, _redirect_payloads, set(),
    )
    assert len(findings) == 1 and findings[0].cwe == 601
    assert findings[0].detail("oracle") == "open_redirect"


def test_safe_route_is_not_confirmed_and_costs_one_request_per_param():
    class SafeZap:
        base_url = "http://127.0.0.1:8090"
        def __init__(self): self.calls = 0
        def send_request(self, raw, follow_redirects=False):
            self.calls += 1
            return {"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "home"}

    fake = SafeZap()
    j = job("/Safe", 79, "q")
    findings = coordinator(fake)._confirm_injection(
        "run", j, seed("/Safe", "q"), BASE_200, 79, xss_reflected, _xss_payloads, set(),
    )
    assert findings == []
    assert fake.calls == 1  # one probe, no confirming replays on a safe route


def test_generic_param_seeds_a_map_handler_with_no_declared_param():
    # A @RequestParam Map<String,String> handler leaves no param in the seed URL;
    # the generic-name probe still reaches the reflection and confirms it.
    j = ProbeJob(
        job_id="run-j0", route="/PersistentXSS/LEVEL_1", method="GET", job_pass="directed",
        hypothesis_ids=("h-1",), cwes=(79,),
        seed_request=SeedRequest(url=f"{BASE}/PersistentXSS/LEVEL_1", method="GET"),
        canary="elx-run-j0",
    )
    findings = coordinator(XssZap())._confirm_injection(
        "run", j, SeedRequest(url=f"{BASE}/PersistentXSS/LEVEL_1", method="GET"),
        BASE_200, 79, xss_reflected, _xss_payloads, set(),
    )
    assert len(findings) == 1 and findings[0].cwe == 79
    assert findings[0].param == "q"


def test_no_generic_param_for_non_reflection_classes():
    # Command injection does not get a generic param: a no-param seed yields nothing.
    j = ProbeJob(
        job_id="run-j0", route="/Cmd/LEVEL_1", method="GET", job_pass="directed",
        hypothesis_ids=("h-1",), cwes=(78,),
        seed_request=SeedRequest(url=f"{BASE}/Cmd/LEVEL_1", method="GET"),
        canary="elx-run-j0",
    )
    findings = coordinator(CommandZap())._confirm_injection(
        "run", j, SeedRequest(url=f"{BASE}/Cmd/LEVEL_1", method="GET"),
        BASE_200, 78, command_output, _command_payloads, set(),
    )
    assert findings == []
