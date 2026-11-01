from __future__ import annotations

import os
from http.client import RemoteDisconnected
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cli.zap_setup import ensure_zap_api_available, load_or_create_zap_api_key


def test_key_is_created_with_restricted_permissions_and_reused(tmp_path: Path) -> None:
    key_path = tmp_path / ".elenchus" / "zap.key"

    key = load_or_create_zap_api_key(key_path=key_path, environ={})

    assert len(key) >= 40
    assert key_path.read_text(encoding="utf-8") == key
    assert load_or_create_zap_api_key(key_path=key_path, environ={}) == key
    if os.name == "posix":
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert key_path.parent.stat().st_mode & 0o777 == 0o700


def test_explicit_and_environment_keys_do_not_create_a_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "key" / "zap.key"

    assert (
        load_or_create_zap_api_key("configured", key_path=key_path, environ={})
        == "configured"
    )
    assert (
        load_or_create_zap_api_key(key_path=key_path, environ={"ZAP_API_KEY": "from-env"})
        == "from-env"
    )
    assert not key_path.parent.exists()


def test_existing_key_permissions_are_restricted(tmp_path: Path) -> None:
    key_path = tmp_path / "zap.key"
    key_path.write_text("existing-key", encoding="utf-8")
    key_path.chmod(0o644)

    assert load_or_create_zap_api_key(key_path=key_path, environ={}) == "existing-key"
    if os.name == "posix":
        assert key_path.stat().st_mode & 0o777 == 0o600


def test_running_zap_with_a_different_key_is_not_restarted(tmp_path: Path) -> None:
    api = Mock()
    api.call.side_effect = RuntimeError("ZAP API core/version returned HTTP 403")
    compose = tmp_path / "zap.compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    run = Mock()

    with pytest.raises(RuntimeError, match="rejected its key"):
        ensure_zap_api_available(
            api,
            "http://127.0.0.1:8090",
            "secret",
            compose_file=compose,
            run=run,
        )

    run.assert_not_called()


def test_listening_but_unresponsive_zap_is_not_restarted(tmp_path: Path) -> None:
    api = Mock()
    api.call.side_effect = RuntimeError("cannot reach the local ZAP API: connection closed")
    compose = tmp_path / "zap.compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    run = Mock()

    with pytest.raises(RuntimeError, match="left unchanged"):
        ensure_zap_api_available(
            api,
            "http://127.0.0.1:8090",
            "secret",
            compose_file=compose,
            api_port_accepting=Mock(return_value=True),
            run=run,
        )

    run.assert_not_called()


def test_remote_disconnect_from_listening_zap_is_not_restarted(tmp_path: Path) -> None:
    api = Mock()
    api.call.side_effect = RemoteDisconnected("remote end closed connection")
    compose = tmp_path / "zap.compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    run = Mock()

    with pytest.raises(RuntimeError, match="left unchanged"):
        ensure_zap_api_available(
            api,
            "http://127.0.0.1:8090",
            "secret",
            compose_file=compose,
            api_port_accepting=Mock(return_value=True),
            run=run,
        )

    run.assert_not_called()


def test_unavailable_zap_starts_compose_with_key_in_environment(tmp_path: Path) -> None:
    api = Mock()
    api.call.side_effect = [
        RuntimeError("cannot reach the local ZAP API: connection refused"),
        {"version": "2.17.0"},
    ]
    compose = tmp_path / "infra" / "zap.compose.yaml"
    compose.parent.mkdir()
    compose.write_text("services: {}", encoding="utf-8")
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))

    ensure_zap_api_available(
        api,
        "http://127.0.0.1:9191",
        "secret",
        compose_file=compose,
        environ={"PATH": "/bin"},
        api_port_accepting=Mock(return_value=False),
        run=run,
    )

    command = run.call_args.args[0]
    options = run.call_args.kwargs
    assert command == ["docker", "compose", "-f", str(compose), "up", "-d"]
    assert "secret" not in command
    assert options["env"]["ZAP_API_KEY"] == "secret"
    assert options["env"]["ZAP_PORT"] == "9191"


def test_compose_error_redacts_the_api_key(tmp_path: Path) -> None:
    compose = tmp_path / "zap.compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    run = Mock(
        return_value=SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="failed with key secret-value",
        )
    )
    api = Mock()
    api.call.side_effect = RuntimeError("cannot reach the local ZAP API: refused")

    with pytest.raises(RuntimeError, match=r"\[redacted\]") as error:
        ensure_zap_api_available(
            api,
            "http://127.0.0.1:8090",
            "secret-value",
            compose_file=compose,
            api_port_accepting=Mock(return_value=False),
            run=run,
        )

    assert "secret-value" not in str(error.value)
