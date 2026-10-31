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
        "run_id": "r", "source": "dast", "provenance": "zap", "cwe": 89,
        "type": "SQL Injection", "route": "/orders/{id}", "method": "GET",
        "param": "id", "payload": "1'", "evidence": [],
    }
    record.update(overrides)
    return Finding.from_dict(record)


SINK = {"file": "./src/A.java", "enclosing_method": "A.find", "start_line": 88, "start_col": 4}


def header_evidence(name):
    return [{"type": "ORACLE", "detail": {"header_name": name}}]


def test_dedupe_key_prefers_sink_id():
    f = finding(source="sast", param=None, file="src/A.java", line=88, sink_id=SINK)
    assert dedupe_key(f) == ("sink", 89, "src/A.java", "A.find", 88, 4)


def test_probe_record_shares_the_key_of_its_sink():
    static = finding(source="sast", param=None, sink_id=SINK)
    probe = finding(sink_id=SINK, param="other")
    assert dedupe_key(static) == dedupe_key(probe)


def test_dedupe_key_falls_back_to_code_location():
    f = finding(source="sast", param=None, cwe=798, file="./src/A.java", line=88)
    assert dedupe_key(f) == ("code", 798, "src/A.java", 88)
    assert route_key(f) == ("route", 798, "/orders/{id}", "GET", None)


def test_dedupe_key_falls_back_to_route():
    assert dedupe_key(finding()) == ("route", 89, "/orders/{id}", "GET", "id")


def test_header_findings_collapse_app_wide():
    a = finding(cwe=693, route="/a", param=None, evidence=header_evidence("X-Frame-Options"))
    b = finding(cwe=693, route="/b", param=None, evidence=header_evidence("x-frame-options"))
    assert dedupe_key(a) == dedupe_key(b) == route_key(a) == ("header", 693, "x-frame-options")


def test_header_findings_split_per_url_when_configured():
    a = finding(cwe=693, route="/a", param=None, evidence=header_evidence("X-Frame-Options"))
    b = finding(cwe=693, route="/b", param=None, evidence=header_evidence("X-Frame-Options"))
    assert dedupe_key(a, "per_url") != dedupe_key(b, "per_url")
    with pytest.raises(ValueError, match="header_count_mode"):
        dedupe_key(a, "bogus")


def test_round_trip_keeps_every_field():
    original = finding(
        sink_id=SINK,
        arg_shape="dynamic",
        entry_paths=[{
            "route": "/orders/{id}", "method": "get", "hops": 1,
            "call_chain": [
                {"method": "C.get", "file": "C.java", "line": 3},
                {"method": "engine.run", "file": None, "line": 9},
            ],
        }],
        candidate_params=["id", "sort"],
        hypothesis_id="h-1",
        link_status="ambiguous",
        link_origin="directed",
        alternatives=[SINK],
        candidate_sinks=[SINK],
        match_mode="relaxed",
        unresolved_hops=1,
        conflict=True,
        status="untested",
        evidence=[{"type": "RESPONSE_TRACE", "detail": {"frames": []}}],
        confidence=0.45,
        confidence_reasons=[{"factor": "oracle_fired", "delta": 0.5}],
        risk_score=70,
        label="Confirmed",
    )
    assert Finding.from_dict(original.to_dict()) == original
    assert original.entry_paths[0].method == "GET"
    assert original.sink_id.file == "src/A.java"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"source": "sast"}, "must not set param"),
        ({"link_status": "unique"}, "both be set"),
        ({"link_origin": "sweep"}, "both be set"),
        ({"status": "bogus"}, "status"),
        ({"suppressed": True, "status": "blocked"}, "suppressed requires"),
        ({"suppressed": True}, "suppressed requires"),
        ({"confidence": 1.5}, "between 0 and 1"),
        ({"confidence": "A"}, "confidence"),
        ({"arg_shape": "maybe"}, "arg_shape"),
        ({"evidence": {"oracle": "x"}}, "evidence must be an array"),
        ({"evidence": [{"type": "GUESS", "detail": {}}]}, "evidence\\[0\\].type"),
        ({"sink_id": {"file": "A.java"}}, "sink_id"),
        ({"handler_file": "A.java"}, "unsupported"),
        ({"reached_via": []}, "unsupported"),
        ({"provenance": "other"}, "provenance"),
        ({"provenance": None}, "provenance"),
    ],
)
def test_contract_rejects(overrides, message):
    with pytest.raises(ValueError, match=message):
        finding(**overrides)


def test_provenance_is_required():
    record = finding().to_dict()
    del record["provenance"]
    with pytest.raises(ValueError, match="provenance"):
        Finding.from_dict(record)


@pytest.mark.parametrize("status", ["safe_pattern", "tested_negative", "no_http_path"])
def test_suppression_allowed_only_for_suppressible_statuses(status):
    assert finding(status=status, suppressed=True).suppressed


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
