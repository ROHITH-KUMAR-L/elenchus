"""The attack value is the decoded value of the candidate param.

Regression: it used to return the whole query string, so a replay sent
`id=id%3D1%2527` instead of `id=1'`.
"""

from probe.coordinator import _attack_value


def request(target: str) -> str:
    return f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n\r\n"


def test_returns_the_decoded_value_of_the_named_query_param():
    header = request("http://127.0.0.1:9090/app/route?id=1%27")
    assert _attack_value(header, {}, "id") == "1'"


def test_picks_the_named_param_among_several():
    header = request("http://h/route?sort=asc&id=%3Cb%3E")
    assert _attack_value(header, {}, "id") == "<b>"


def test_reads_the_body_when_there_is_no_query():
    message = {"requestBody": "name=%3Cscript%3E&other=1"}
    assert _attack_value(request("http://h/route"), message, "name") == "<script>"


def test_returns_empty_when_the_param_is_absent():
    assert _attack_value(request("http://h/route?id=1"), {}, "sort") == ""
