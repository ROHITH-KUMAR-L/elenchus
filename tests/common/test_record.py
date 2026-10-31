"""Contract-logic tests for common/record.py."""

import pytest

from common.record import (
    CallEdge,
    Finding,
    RouteEntry,
    ScanTarget,
    dedupe_key,
    normalise_route,
    route_key,
)


def entry(route, method="GET"):
    return RouteEntry(route, method, "C.java", "C.f", 1, 2, (), ())


ROUTES = (
    entry("/orders/{id}"),
    entry("/orders/latest"),
    entry("/items/{id}/parts/{part}"),
    entry("/BlindSQLInjectionVulnerability/LEVEL_1"),
)


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://localhost:9090/orders/5", "/orders/{id}"),
        ("/orders/5?x=1#frag", "/orders/{id}"),
        ("/orders/latest", "/orders/latest"),  # literal beats template
        ("/orders/5/", "/orders/{id}"),
        ("/items/a%20b/parts/7", "/items/{id}/parts/{part}"),
        ("/unknown", None),
        ("/orders", None),
    ],
)
def test_normalise_route(url, expected):
    assert normalise_route(url, ROUTES) == expected


def test_normalise_route_strips_context_path():
    url = "http://localhost:9090/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?id=1"
    assert normalise_route(url, ROUTES, base_path="/VulnerableApp") == (
        "/BlindSQLInjectionVulnerability/LEVEL_1"
    )


@pytest.mark.parametrize("url", ["http://localhost:9090/App", "http://127.0.0.1", "https://[::1]:8443"])
def test_scan_target_accepts_localhost(url):
    ScanTarget("src", url, "run-1", "spring-mvc")


@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:9090", "ftp://localhost", "localhost:9090"])
def test_scan_target_rejects_non_localhost(url):
    with pytest.raises(ValueError):
        ScanTarget("src", url, "run-1", "spring-mvc")


def test_scan_target_base_path():
    assert ScanTarget("src", "http://localhost:9090/VulnerableApp/", "r", "spring-mvc").base_path == "/VulnerableApp"


def finding(**overrides):
    record = {
        "run_id": "r", "source": "dast", "cwe": 89, "type": "SQL Injection",
        "route": "/orders/{id}", "method": "GET", "file": None, "line": None,
        "param": "id", "payload": "1'", "handler_file": None,
        "handler_line_start": None, "handler_line_end": None, "reached_via": None,
        "evidence": {}, "taint_trace": None, "label": None, "confidence": None,
        "risk_score": None, "severity": None, "wasc_id": None,
    }
    record.update(overrides)
    return Finding.from_dict(record)


def test_dedupe_key_prefers_code_location():
    f = finding(source="sast", file="./src/A.java", line=88)
    assert dedupe_key(f) == ("code", 89, "src/A.java", 88)
    assert route_key(f) == ("route", 89, "/orders/{id}", "GET", "id")


def test_dedupe_key_falls_back_to_route():
    assert dedupe_key(finding()) == ("route", 89, "/orders/{id}", "GET", "id")


def test_header_findings_collapse_app_wide():
    a = finding(cwe=693, route="/a", param=None, evidence={"header_name": "X-Frame-Options"})
    b = finding(cwe=693, route="/b", param=None, evidence={"header_name": "x-frame-options"})
    assert dedupe_key(a) == dedupe_key(b) == route_key(a) == ("header", 693, "x-frame-options")


def test_route_entry_from_parser_dict():
    parsed = {
        "route": "/c", "method": "GET", "file": "C.java", "func": "C.c",
        "line_start": 3, "line_end": 9,
        "params": [{"name": "x", "source": "query"}],
        "calls": [{"class": "Svc", "method": "run", "file": "Svc.java", "line_start": 3, "line_end": 5}],
    }
    route = RouteEntry.from_dict(parsed)
    assert route.params[0].name == "x"
    assert route.calls == (CallEdge("Svc", "run", "Svc.java", 3, 5),)
