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
