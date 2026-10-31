from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from common.record import RouteEntry, RouteMap, RouteParam, ScanTarget
from producers.dast import zap_runner


def target() -> ScanTarget:
    return ScanTarget(
        "src",
        "http://localhost:9090/VulnerableApp",
        "dast-test",
        "spring-mvc",
    )


def routes() -> RouteMap:
    return (
        RouteEntry(
            route="/orders/{id}",
            method="GET",
            file="src/Orders.java",
            func="Orders.get",
            line_start=1,
            line_end=10,
            params=(
                RouteParam("id", "path"),
                RouteParam("sort", "query"),
            ),
            calls=(),
        ),
    )


def alert(cwe: int, **overrides: Any) -> dict[str, Any]:
    return {
        "cweid": str(cwe),
        "url": "http://localhost:9090/VulnerableApp/orders/1?sort=elenchus",
        "method": "GET",
        "param": "sort",
        "attack": "",
        "evidence": "",
        "messageId": "7",
        "alert": "test alert",
        "pluginId": "10001",
        "risk": "High",
        "wascid": "19",
        **overrides,
    }


def test_seed_requests_encode_path_and_query_parameters() -> None:
    [request] = zap_runner._seed_requests(target(), routes())

    assert request.url == (
        "http://localhost:9090/VulnerableApp/orders/1?sort=elenchus"
    )
    assert request.method == "GET"
    assert request.post_data == ""


def test_seed_requests_put_post_parameters_in_body() -> None:
    post_route = (
        RouteEntry(
            route="/orders",
            method="POST",
            file="src/Orders.java",
            func="Orders.create",
            line_start=1,
            line_end=10,
            params=(RouteParam("name", "query"),),
            calls=(),
        ),
    )

    [request] = zap_runner._seed_requests(target(), post_route)

    assert request.url == "http://localhost:9090/VulnerableApp/orders"
    assert request.method == "POST"
    assert request.post_data == "name=elenchus"


def test_zap_api_rejects_non_local_api_urls() -> None:
    with pytest.raises(ValueError, match="localhost"):
        zap_runner.ZapApi("http://zap.example.com:8090", "test-key")


@contextmanager
def local_zap_api():
    seen: list[tuple[str, dict[str, list[str]]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            seen.append((parts.path, parse_qs(parts.query)))
            if parts.path.endswith("/redirect/"):
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/")
                self.end_headers()
                return
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_zap_api_encodes_local_calls_and_blocks_external_redirects() -> None:
    with local_zap_api() as (base_url, seen):
        api = zap_runner.ZapApi(base_url, "test-key")

        assert api.call(
            "core", "view", "version", {"target": "http://localhost/a b"}
        ) == {"status": "ok"}
        assert seen[0][0] == "/JSON/core/view/version/"
        assert seen[0][1]["apikey"] == ["test-key"]
        assert seen[0][1]["target"] == ["http://localhost/a b"]
        with pytest.raises(RuntimeError, match="HTTP 302"):
            api.call("core", "view", "redirect")
        assert len(seen) == 2


def test_scope_regex_limits_scanning_to_target_context_path() -> None:
    expression = zap_runner._scope_regex(target())

    assert expression.startswith("^http://localhost:9090/VulnerableApp")
    assert expression.endswith(r"(?:/[^?#]*)?(?:\?[^#]*)?$")
    assert "example.com" not in expression


def test_sql_error_oracle_requires_database_error_response() -> None:
    assert zap_runner._verify_alert(
        89,
        alert(89),
        {"responseBody": "java.sql.SQLException: syntax error near id"},
    ).confirmed
    assert not zap_runner._verify_alert(
        89, alert(89), {"responseBody": "The request was accepted."}
    ).confirmed


def test_xss_oracle_requires_raw_unescaped_reflection() -> None:
    reflected = zap_runner._verify_alert(
        79,
        alert(79, attack="<ELENCHUS>"),
        {"responseBody": "<html><ELENCHUS></html>"},
    )
    escaped = zap_runner._verify_alert(
        79,
        alert(79, attack="<ELENCHUS>"),
        {"responseBody": "<html>&lt;ELENCHUS&gt;</html>"},
    )

    assert reflected.confirmed
    assert not escaped.confirmed


def test_command_oracle_requires_command_output_marker() -> None:
    assert zap_runner._verify_alert(
        78,
        alert(78, attack="; echo ELENCHUS_CMD_123"),
        {"responseBody": "ELENCHUS_CMD_123"},
    ).confirmed
    assert not zap_runner._verify_alert(
        78,
        alert(78, attack="; sleep 2"),
        {"responseBody": "request completed"},
    ).confirmed


def test_redirect_oracle_requires_external_location_and_redirect_status() -> None:
    confirmed = zap_runner._verify_alert(
        601,
        alert(601),
        {
            "responseHeader": (
                "HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/\r\n"
            )
        },
    )
    local = zap_runner._verify_alert(
        601,
        alert(601),
        {
            "responseHeader": (
                "HTTP/1.1 302 Found\r\nLocation: http://localhost/login\r\n"
            )
        },
    )

    assert confirmed.confirmed
    assert not local.confirmed


def test_header_oracle_checks_the_actual_response_header() -> None:
    missing = zap_runner._verify_alert(
        693,
        alert(693, alert="X-Frame-Options Header Not Set"),
        {"responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"},
    )
    present = zap_runner._verify_alert(
        693,
        alert(693, alert="X-Frame-Options Header Not Set"),
        {
            "responseHeader": (
                "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n"
            )
        },
    )

    assert missing.confirmed
    assert missing.header_name == "x-frame-options"
    assert not present.confirmed


class FakeZapApi:
    def __init__(self) -> None:
        self.scope_regex: str | None = None
        self.accessed: list[str] = []
        self.scans: list[tuple[str, str, str, str]] = []
        self.removed_context: str | None = None

    def create_context(self, name: str, scope_regex: str) -> str:
        assert name.startswith("elenchus-")
        self.scope_regex = scope_regex
        return "1"

    def remove_context(self, name: str) -> None:
        self.removed_context = name

    def access_url(self, url: str) -> None:
        self.accessed.append(url)

    def start_active_scan(
        self, url: str, method: str, post_data: str, context_id: str
    ) -> str:
        self.scans.append((url, method, post_data, context_id))
        return str(len(self.scans))

    def active_scan_status(self, scan_id: str) -> int:
        assert scan_id.isdigit()
        return 100

    def passive_records_to_scan(self) -> int:
        return 0

    def alerts(self, base_url: str) -> list[dict[str, Any]]:
        assert base_url.startswith("http://localhost:")
        return [
            alert(89),
            alert(
                89,
                url="http://example.com/orders/1?sort=elenchus",
            ),
        ]

    def message(self, message_id: str) -> dict[str, Any]:
        assert message_id == "7"
        return {
            "requestHeader": (
                "GET /VulnerableApp/orders/1?sort=elenchus HTTP/1.1"
            ),
            "requestBody": "",
            "responseHeader": "HTTP/1.1 500 Internal Server Error\r\n",
            "responseBody": "java.sql.SQLException: syntax error near id",
        }


def test_run_dast_scans_and_reports_only_verified_in_scope_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_api = FakeZapApi()
    monkeypatch.setattr(
        zap_runner.ZapApi,
        "from_environment",
        staticmethod(lambda: fake_api),
    )

    [finding] = zap_runner.run_dast(target(), routes())

    assert finding.cwe == 89
    assert finding.type == "SQL Injection"
    assert finding.route == "/orders/{id}"
    assert finding.method == "GET"
    assert finding.param == "sort"
    assert finding.detail("oracle") == "database_error"
    assert fake_api.scope_regex is not None
    assert len(fake_api.accessed) == 1
    assert fake_api.scans == [
        (
            "http://localhost:9090/VulnerableApp/orders/1?sort=elenchus",
            "GET",
            "",
            "1",
        )
    ]
    assert fake_api.removed_context == "elenchus-dast-test"
