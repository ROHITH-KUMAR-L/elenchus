"""Loopback guard and context-path detection."""

import pytest

from probe.preflight import NotLoopbackError, check_loopback, detect_context_path


@pytest.mark.parametrize("url", ["http://localhost:9090/VulnerableApp", "http://127.0.0.1:8080", "https://[::1]/x"])
def test_loopback_targets_pass(url):
    check_loopback(url)


@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:9090/x", "ftp://localhost"])
def test_non_loopback_targets_are_refused(url):
    with pytest.raises(NotLoopbackError):
        check_loopback(url)


def test_context_path_from_properties_wins(tmp_path):
    (tmp_path / "application.properties").write_text(
        "server.port=9090\nserver.servlet.context-path=/VulnerableApp\n"
    )
    detected = detect_context_path(tmp_path, "http://localhost:9090/")
    assert (detected.value, detected.source) == ("/VulnerableApp", "config")


def test_context_path_from_yaml(tmp_path):
    (tmp_path / "application.yml").write_text(
        "server:\n  servlet:\n    context-path: /App\n"
    )
    # The flat-key reader does not parse nested YAML, so this falls back to the URL.
    detected = detect_context_path(tmp_path, "http://localhost:9090/App")
    assert detected.value == "/App"


def test_falls_back_to_the_base_url_path(tmp_path):
    detected = detect_context_path(tmp_path, "http://localhost:9090/Shop/")
    assert (detected.value, detected.source) == ("/Shop", "base_url")


def test_root_context_is_reported_as_none(tmp_path):
    detected = detect_context_path(tmp_path, "http://localhost:9090/")
    assert (detected.value, detected.source) == ("", "none")


class FingerprintApi:
    """A send_request stub keyed by whether the URL is the base or a missing path."""

    def __init__(self, base=None, error=None, fail_base=False, fail_error=False):
        self._base = base
        self._error = error
        self._fail_base = fail_base
        self._fail_error = fail_error

    def send_request(self, raw_request, follow_redirects=False):
        is_error = "/elx-missing-" in raw_request
        if is_error:
            if self._fail_error:
                raise RuntimeError("no response")
            return self._error
        if self._fail_base:
            raise RuntimeError("target down")
        return self._base


BASE = "http://127.0.0.1:9090/VulnerableApp"


def test_probe_extras_reads_banner_and_error_fingerprint():
    from probe.preflight import probe_extras

    api = FingerprintApi(
        base={"responseHeader": "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n", "responseBody": "<html/>"},
        error={"responseHeader": "HTTP/1.1 404 Not Found\r\n", "responseBody": "<h1>Whitelabel Error Page</h1>"},
    )
    extras = probe_extras(api, BASE)
    assert extras.exposed is True
    assert extras.server_banner == "Apache-Coyote/1.1"
    assert extras.error_status == 404
    assert extras.error_signature == "Whitelabel Error Page"


def test_probe_extras_falls_back_to_the_page_title():
    from probe.preflight import probe_extras

    api = FingerprintApi(
        base={"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": ""},
        error={"responseHeader": "HTTP/1.1 500 Server Error\r\n",
               "responseBody": "<html><title> Oops something broke </title></html>"},
    )
    extras = probe_extras(api, BASE)
    assert extras.server_banner is None
    assert extras.error_status == 500
    assert extras.error_signature == "Oops something broke"


def test_probe_extras_skips_cleanly_when_the_target_is_down():
    from probe.preflight import probe_extras

    extras = probe_extras(FingerprintApi(fail_base=True), BASE)
    assert extras.exposed is False
    assert extras.to_dict() == {
        "exposed": False, "server_banner": None, "error_status": None, "error_signature": None
    }


def test_probe_extras_keeps_the_banner_when_the_error_probe_fails():
    from probe.preflight import probe_extras

    api = FingerprintApi(
        base={"responseHeader": "HTTP/1.1 200 OK\r\nServer: nginx\r\n", "responseBody": ""},
        fail_error=True,
    )
    extras = probe_extras(api, BASE)
    assert extras.exposed is True
    assert extras.server_banner == "nginx"
    assert extras.error_status is None
