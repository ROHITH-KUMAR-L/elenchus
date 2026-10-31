"""Typed seed requests from route entries."""

import json

from common.record import RouteEntry, RouteParam
from probe.seeds import build_seed

BASE = "http://localhost:9090/VulnerableApp"


def entry(route, method="GET", params=()):
    return RouteEntry(route, method, "C.java", "C.f", 1, 2, tuple(params), ())


def test_query_and_path_params_get_benign_values():
    seed = build_seed(
        entry("/orders/{id}", params=[RouteParam("id", "path", "Long"), RouteParam("sort", "query", "String")]),
        BASE,
    )
    assert seed.method == "GET"
    assert seed.url == f"{BASE}/orders/1?sort=1"
    assert seed.body == ""


def test_any_method_seeds_as_get():
    assert build_seed(entry("/x", method="ANY"), BASE).method == "GET"


def test_json_body_builds_nested_object():
    seed = build_seed(
        entry(
            "/reset",
            method="POST",
            params=[
                RouteParam("email", "body", "String", "json"),
                RouteParam("address.city", "body", "String", "json"),
            ],
        ),
        BASE,
    )
    assert seed.content_type == "application/json"
    assert json.loads(seed.body) == {"email": "1", "address": {"city": "1"}}


def test_form_body_is_urlencoded():
    seed = build_seed(
        entry("/login", method="POST", params=[RouteParam("user", "body", "String", "form")]),
        BASE,
    )
    assert seed.content_type == "application/x-www-form-urlencoded"
    assert seed.body == "user=1"


def test_body_params_on_a_get_route_do_not_make_a_body():
    seed = build_seed(
        entry("/search", method="GET", params=[RouteParam("q", "body", "String", "form")]),
        BASE,
    )
    assert seed.body == "" and seed.content_type == ""
