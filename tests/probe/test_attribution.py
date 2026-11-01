"""Attribution on recorded-style ZAP messages. No live ZAP."""

import pytest

from probe.attribution import (
    Attribution,
    attribute,
    changed_keys,
    header_value,
    request_path,
    request_values,
)

RULE_CWES = {"40018": 89, "40012": 79}
BASE = "http://localhost:9090/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1"
SEED_PATH = "/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1"


def message(target, *, probe="elx-job1", rule="40018", host="Host: localhost:9090"):
    lines = [f"GET {target} HTTP/1.1", host]
    if probe is not None:
        lines.append(f"X-Elenchus-Probe: {probe}")
    if rule is not None:
        lines.append(f"X-ZAP-Scan-ID: {rule}")
    return "\r\n".join(lines) + "\r\n\r\n"


SEED = request_values(message(f"{BASE}?id=1"), "")


def attribute_get(target, **kw):
    header = message(target, **kw)
    return attribute(
        header, "", seed_path=SEED_PATH, seed_values=SEED, canary="elx-job1", rule_cwes=RULE_CWES
    )


def test_one_changed_query_param_attributes_to_param_and_cwe():
    assert attribute_get(f"{BASE}?id=1'") == Attribution(
        param="id", cwe=89, rule_id="40018", param_location="query"
    )


def test_missing_probe_header_is_dropped():
    assert attribute_get(f"{BASE}?id=1'", probe=None) is None


def test_wrong_canary_is_dropped():
    assert attribute_get(f"{BASE}?id=1'", probe="elx-other") is None


def test_missing_or_unknown_rule_header_is_dropped():
    assert attribute_get(f"{BASE}?id=1'", rule=None) is None
    assert attribute_get(f"{BASE}?id=1'", rule="99999") is None


def test_path_off_route_is_dropped():
    # ZAP's 404-analysis request mutates the path; it must not attribute.
    assert attribute_get(f"http://localhost:9090/VulnerableApp/{'x' * 6}/LEVEL_1?id=1") is None


def test_zero_changed_params_is_unlinked():
    assert attribute_get(f"{BASE}?id=1") is None


def test_two_changed_params_is_unlinked():
    seed = request_values(message(f"{BASE}?id=1&sort=asc"), "")
    header = message(f"{BASE}?id=1'&sort=desc")
    assert (
        attribute(header, "", seed_path=SEED_PATH, seed_values=seed, canary="elx-job1", rule_cwes=RULE_CWES)
        is None
    )


def test_json_body_field_attributes_by_name():
    target = "http://localhost:9090/VulnerableApp/PasswordResetVulnerability/LEVEL_1"
    path = "/VulnerableApp/PasswordResetVulnerability/LEVEL_1"
    post = "POST " + target + " HTTP/1.1\r\nHost: localhost:9090\r\nX-Elenchus-Probe: elx-job1\r\nX-ZAP-Scan-ID: 40018\r\n\r\n"
    seed = request_values(post, '{"email": "a@b.test", "action": "request"}')
    probe = request_values(post, '{"email": "a@b.test\' or 1=1", "action": "request"}')
    # request_values gives us the raw dicts; attribute() recomputes from the message.
    assert changed_keys(seed, probe) == ["json.email"]
    attribution = attribute(
        post, '{"email": "a@b.test\' or 1=1", "action": "request"}',
        seed_path=path, seed_values=seed, canary="elx-job1", rule_cwes=RULE_CWES,
    )
    assert attribution == Attribution(
        param="email", cwe=89, rule_id="40018", param_location="body"
    )


def test_form_body_param_is_reported_as_body_location():
    post = (
        "POST /search HTTP/1.1\r\nHost: localhost\r\n"
        "X-Elenchus-Probe: elx-job1\r\nX-ZAP-Scan-ID: 40018\r\n\r\n"
    )
    seed = request_values(post, "query=one")

    attribution = attribute(
        post,
        "query=one%27",
        seed_path="/search",
        seed_values=seed,
        canary="elx-job1",
        rule_cwes=RULE_CWES,
    )

    assert attribution == Attribution(
        param="query", cwe=89, rule_id="40018", param_location="body"
    )


def test_header_value_and_request_path_helpers():
    header = message(f"{BASE}?id=1")
    assert header_value(header, "x-zap-scan-id") == "40018"
    assert header_value(header, "absent") is None
    assert request_path(header) == SEED_PATH


@pytest.mark.parametrize(
    "body, key",
    [("a=1&b=2", "form.a"), ('{"a": 1}', "json.a"), ("not a form or json", "body")],
)
def test_request_values_reads_each_body_shape(body, key):
    values = request_values("POST /x HTTP/1.1\r\nHost: h\r\n\r\n", body)
    assert key in values
