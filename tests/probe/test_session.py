"""Session manager: mint a token from a login flow and reach an auth-gated route."""

from __future__ import annotations

import pytest

from common.config import load_config
from common.pipeline import Hypothesis
from common.record import CallHop, RouteEntry, RouteParam, SinkId
from probe.coordinator import Coordinator, plan_directed_jobs
from probe.preflight import ContextPath
from probe.session import resolve_session

BASE = "http://127.0.0.1:9090/VulnerableApp"
LOGIN = f"{BASE}/login"
ROUTE = "/Protected/LEVEL_1"
SINK = SinkId("Svc.java", "Svc.find", 83, 20)
ROUTES = (
    RouteEntry(ROUTE, "GET", "C.java", "C.get", 70, 90, (RouteParam("id", "query", "String"),), ()),
)


class LoginStub:
    """A send_request stub: the login URL returns the scripted login message; any
    other request is the baseline, gated on the Cookie header when `gated`."""

    def __init__(self, login_message, *, gated=False, cookie="JSESSIONID=sess"):
        self._login_message = login_message
        self._gated = gated
        self._cookie = cookie
        self.requests: list[str] = []

    def send_request(self, raw_request, follow_redirects=False):
        self.requests.append(raw_request)
        if "/login " in raw_request:
            return self._login_message
        authorised = (not self._gated) or (f"Cookie: {self._cookie}" in raw_request)
        status = "200 OK" if authorised else "401 Unauthorized"
        body = '{"ok": true}' if authorised else "login required"
        return {"responseHeader": f"HTTP/1.1 {status}\r\n", "responseBody": body}


def login_config(**overrides):
    base = {
        "target.base_url": BASE,
        "target.auth.login_url": LOGIN,
        "target.auth.token_from": "cookie",
        "target.auth.token_name": "JSESSIONID",
    }
    base.update(overrides)
    return load_config(overrides=base, environ={"ZAP_API_KEY": "k"})


def cookie_message(cookie="JSESSIONID=sess; Path=/; HttpOnly"):
    return {"responseHeader": f"HTTP/1.1 200 OK\r\nSet-Cookie: {cookie}\r\n", "responseBody": ""}


def test_cookie_login_extracts_the_named_cookie():
    api = LoginStub(cookie_message())
    assert resolve_session(api, login_config(), BASE) == ("Cookie", "JSESSIONID=sess")


def test_json_token_login_builds_a_bearer_header():
    api = LoginStub({"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": '{"data": {"jwt": "xyz"}}'})
    config = login_config(
        **{
            "target.auth.token_from": "json",
            "target.auth.token_name": "data.jwt",
            "target.auth.header_name": "Authorization",
            "target.auth.header_template": "Bearer {token}",
        }
    )
    assert resolve_session(api, config, BASE) == ("Authorization", "Bearer xyz")


def test_header_token_login_reads_a_response_header():
    api = LoginStub({"responseHeader": "HTTP/1.1 200 OK\r\nX-Auth-Token: abc\r\n", "responseBody": ""})
    config = login_config(
        **{
            "target.auth.token_from": "header",
            "target.auth.token_name": "X-Auth-Token",
            "target.auth.header_name": "X-Auth-Token",
        }
    )
    assert resolve_session(api, config, BASE) == ("X-Auth-Token", "abc")


def test_login_body_comes_from_the_environment_not_config(monkeypatch):
    monkeypatch.setenv("LOGIN_BODY", "username=admin&password=admin")
    api = LoginStub(cookie_message())
    config = load_config(
        overrides={
            "target.base_url": BASE,
            "target.auth.login_url": LOGIN,
            "target.auth.token_name": "JSESSIONID",
            "target.auth.login_body_env": "LOGIN_BODY",
        },
        environ={"ZAP_API_KEY": "k"},
    )
    resolve_session(api, config, BASE)
    login_raw = next(r for r in api.requests if "/login " in r)
    assert "username=admin&password=admin" in login_raw


def test_missing_cookie_is_an_error():
    api = LoginStub({"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": ""})
    with pytest.raises(ValueError, match="no usable cookie"):
        resolve_session(api, login_config(), BASE)


def test_non_loopback_login_url_is_rejected_by_config():
    with pytest.raises(ValueError, match="login_url must be on localhost"):
        login_config(**{"target.auth.login_url": "http://example.com/login"})


class GatedZap(LoginStub):
    """A scripted ZAP that gates every route on the session cookie, so a job only
    gets past the baseline when the session manager carried the cookie."""

    base_url = "http://127.0.0.1:8090"

    def __init__(self, **kwargs):
        super().__init__(cookie_message(), **kwargs)
        self.replacer: dict[str, str] = {}

    def set_option(self, *a): pass
    def ensure_scan_policy(self, *a): pass
    def create_context(self, name, regex): return "7"
    def remove_context(self, name): pass
    def replacer_rules(self): return [{"description": d} for d in self.replacer]
    def add_replacer_request_header(self, description, header, value): self.replacer[description] = value
    def remove_replacer_rule(self, description): self.replacer.pop(description, None)
    def prime_site_tree(self, *a): pass
    def start_scan(self, *a): return "11"
    def stop_scan(self, scan_id): pass
    def active_scan_status(self, scan_id): return 100
    def scan_message_ids(self, scan_id): return []
    def message(self, message_id): return {}
    def hosts(self): return ["127.0.0.1"]


def run_job(api, config):
    jobs = plan_directed_jobs(
        [Hypothesis("directed", ROUTE, "GET", 89, ("id",), SINK, (CallHop("C.get", "C.java", 70),))],
        ROUTES,
        "run",
    )
    coordinator = Coordinator(api, config, BASE, ContextPath("/VulnerableApp", "config"))
    return coordinator.run("run", jobs, ROUTES)


def test_auth_gated_route_is_reached_only_with_the_session_cookie():
    gated = run_job(GatedZap(gated=True), login_config())
    assert gated.jobs[0].outcome == "finished"  # baseline 200, scan ran
    # Without the login flow, the same gated route stays blocked at the baseline.
    no_login = run_job(GatedZap(gated=True), load_config(overrides={"target.base_url": BASE}, environ={"ZAP_API_KEY": "k"}))
    assert no_login.jobs[0].outcome == "all_blocked"
