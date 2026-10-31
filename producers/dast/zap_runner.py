"""Run a localhost-scoped OWASP ZAP active scan and verify its alerts."""

from __future__ import annotations

import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from common.record import (
    LOCALHOST_NAMES,
)

DEFAULT_ZAP_API_URL = "http://127.0.0.1:8090"
DEFAULT_SCAN_TIMEOUT_SECONDS = 300
POLL_INTERVAL_SECONDS = 1
MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024
SUPPORTED_CWES = {78, 79, 89, 601, 693}

_SQL_ERROR_PATTERNS = (
    r"SQLSyntaxErrorException",
    r"SQLException",
    r"SQLSTATE",
    r"syntax error at or near",
    r"unclosed quotation mark",
    r"you have an error in your SQL syntax",
    r"SQLiteException",
    r"org\.hibernate\.exception",
)
_COMMAND_OUTPUT_PATTERNS = (
    r"\buid=\d+",
    r"\bgid=\d+",
    r"ELENCHUS_CMD_[A-Za-z0-9_-]+",
)
_HEADER_NAME_PATTERN = re.compile(
    r"\b(?:Strict-Transport-Security|Content-Security-Policy|"
    r"X-[A-Za-z0-9-]+|Referrer-Policy|Permissions-Policy)\b",
    re.IGNORECASE,
)
_TEMPLATE_PARAM_PATTERN = re.compile(r"\{([^{}]+)\}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req, fp, code, msg, headers, newurl
    ):  # type: ignore[no-untyped-def]
        if urllib.parse.urlsplit(newurl).hostname not in LOCALHOST_NAMES:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ZapApi:
    """Small API client that accepts only a loopback ZAP endpoint."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 30) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if (
            parts.scheme != "http"
            or parts.hostname not in LOCALHOST_NAMES
            or parts.username is not None
            or parts.password is not None
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            raise ValueError("ZAP_API_URL must be an http URL on localhost")
        if not api_key:
            raise ValueError("ZAP_API_KEY must not be empty")
        if timeout <= 0:
            raise ValueError("ZAP API timeout must be positive")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    @classmethod
    def from_environment(cls) -> ZapApi:
        return cls(
            os.environ.get("ZAP_API_URL", DEFAULT_ZAP_API_URL),
            os.environ.get("ZAP_API_KEY", ""),
        )

    def call(
        self,
        component: str,
        operation_type: str,
        operation: str,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        query = {"apikey": self.api_key, **(params or {})}
        endpoint = (
            f"{self.base_url}/JSON/{component}/{operation_type}/{operation}/"
        )
        url = f"{endpoint}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(MAX_API_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"ZAP API {component}/{operation} returned HTTP {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"cannot reach the local ZAP API: {error.reason}") from error
        except TimeoutError as error:
            # A read timeout while ZAP is busy scanning raises TimeoutError, not
            # URLError. Wrap it so callers see one error type for a stalled call.
            raise RuntimeError(f"ZAP API {component}/{operation} timed out") from error
        if len(body) > MAX_API_RESPONSE_BYTES:
            raise RuntimeError(f"ZAP API {component}/{operation} response is too large")
        try:
            result = json.loads(body)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"ZAP API {component}/{operation} returned invalid JSON"
            ) from error
        if not isinstance(result, dict):
            raise RuntimeError(f"ZAP API {component}/{operation} returned a non-object")
        return result

    def create_context(self, name: str, scope_regex: str) -> str:
        result = self.call("context", "action", "newContext", {"contextName": name})
        context_id = result.get("contextId")
        if not isinstance(context_id, str) or not context_id:
            raise RuntimeError("ZAP did not return a context ID")
        self.call(
            "context",
            "action",
            "includeInContext",
            {"contextName": name, "regex": scope_regex},
        )
        self.call(
            "context",
            "action",
            "setContextInScope",
            {"contextName": name, "booleanInScope": "true"},
        )
        return context_id

    def remove_context(self, name: str) -> None:
        self.call("context", "action", "removeContext", {"contextName": name})

    def access_url(self, url: str) -> None:
        self.call(
            "core",
            "action",
            "accessUrl",
            {"url": url, "followRedirects": "false"},
        )

    def start_active_scan(
        self, url: str, method: str, post_data: str, context_id: str
    ) -> str:
        result = self.call(
            "ascan",
            "action",
            "scan",
            {
                "url": url,
                "recurse": "false",
                "inScopeOnly": "true",
                "method": method,
                "postData": post_data,
                "contextId": context_id,
            },
        )
        scan_id = result.get("scan") or result.get("scanId")
        if not isinstance(scan_id, str) or not scan_id:
            raise RuntimeError("ZAP did not return an active scan ID")
        return scan_id

    def active_scan_status(self, scan_id: str) -> int:
        result = self.call("ascan", "view", "status", {"scanId": scan_id})
        return _parse_progress(result.get("status"), "active scan")

    def passive_records_to_scan(self) -> int:
        result = self.call("pscan", "view", "recordsToScan")
        return _parse_progress(result.get("recordsToScan"), "passive scan queue")

    def alerts(self, base_url: str) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        start = 0
        page_size = 100
        while True:
            result = self.call(
                "core",
                "view",
                "alerts",
                {"baseurl": base_url, "start": str(start), "count": str(page_size)},
            )
            page = result.get("alerts")
            if not isinstance(page, list) or not all(
                isinstance(alert, dict) for alert in page
            ):
                raise RuntimeError("ZAP returned an invalid alerts list")
            alerts.extend(page)
            if len(page) < page_size:
                return alerts
            start += page_size

    def message(self, message_id: str) -> dict[str, Any]:
        result = self.call("core", "view", "message", {"id": message_id})
        message = result.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("ZAP returned an invalid message")
        return message

    # --- Methods the BS4 coordinator uses. BS0 verified each against ZAP 2.17.0.

    def set_option(self, component: str, option: str, type_name: str, value: str) -> None:
        self.call(component, "action", f"setOption{option}", {type_name: value})

    def scanners(self, policy: str | None = None) -> list[dict[str, Any]]:
        params = {"scanPolicyName": policy} if policy else None
        result = self.call("ascan", "view", "scanners", params)
        scanners = result.get("scanners")
        if not isinstance(scanners, list):
            raise RuntimeError("ZAP returned an invalid scanners list")
        return scanners

    def scan_policy_names(self) -> list[str]:
        result = self.call("ascan", "view", "scanPolicyNames")
        return [name for name in result.get("scanPolicyNames", []) if isinstance(name, str)]

    def ensure_scan_policy(self, name: str, rule_ids: list[str], strength: str) -> None:
        """A fresh allow-list policy: only rule_ids on, all at one strength."""
        if name in self.scan_policy_names():
            self.call("ascan", "action", "removeScanPolicy", {"scanPolicyName": name})
        self.call(
            "ascan",
            "action",
            "addScanPolicy",
            {"scanPolicyName": name, "attackStrength": strength, "alertThreshold": "MEDIUM"},
        )
        self.call("ascan", "action", "disableAllScanners", {"scanPolicyName": name})
        self.call(
            "ascan",
            "action",
            "enableScanners",
            {"ids": ",".join(rule_ids), "scanPolicyName": name},
        )
        for rule_id in rule_ids:
            self.call(
                "ascan",
                "action",
                "setScannerAttackStrength",
                {"id": rule_id, "attackStrength": strength, "scanPolicyName": name},
            )

    def start_scan(
        self, url: str, method: str, post_data: str, context_id: str, policy: str
    ) -> str:
        result = self.call(
            "ascan",
            "action",
            "scan",
            {
                "url": url,
                "recurse": "false",
                "method": method,
                "postData": post_data,
                "contextId": context_id,
                "scanPolicyName": policy,
            },
        )
        scan_id = result.get("scan")
        if not isinstance(scan_id, str) or not scan_id:
            raise RuntimeError("ZAP did not return an active scan ID")
        return scan_id

    def stop_scan(self, scan_id: str) -> None:
        self.call("ascan", "action", "stop", {"scanId": scan_id})

    def scan_message_ids(self, scan_id: str) -> list[str]:
        result = self.call("ascan", "view", "messagesIds", {"scanId": scan_id})
        return [str(message_id) for message_id in result.get("messagesIds", [])]

    def excluded_params(self) -> list[dict[str, Any]]:
        result = self.call("ascan", "view", "excludedParams")
        return result.get("excludedParams", [])

    def add_excluded_param(self, name: str, type_id: str) -> None:
        self.call(
            "ascan", "action", "addExcludedParam", {"name": name, "type": type_id, "url": "*"}
        )

    def remove_excluded_param(self, index: str) -> None:
        self.call("ascan", "action", "removeExcludedParam", {"idx": index})

    def replacer_rules(self) -> list[dict[str, Any]]:
        return self.call("replacer", "view", "rules").get("rules", [])

    def add_replacer_request_header(self, description: str, header: str, value: str) -> None:
        """A Replacer rule that sets a request header on all traffic, scanner included."""
        self.call(
            "replacer",
            "action",
            "addRule",
            {
                "description": description,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": header,
                "replacement": value,
                "initiators": "",
            },
        )

    def remove_replacer_rule(self, description: str) -> None:
        self.call("replacer", "action", "removeRule", {"description": description})

    def send_request(self, raw_request: str, follow_redirects: bool = False) -> dict[str, Any]:
        result = self.call(
            "core",
            "action",
            "sendRequest",
            {"request": raw_request, "followRedirects": str(follow_redirects).lower()},
        )
        messages = result.get("sendRequest")
        if not isinstance(messages, list) or not messages:
            raise RuntimeError("ZAP returned no response for a sent request")
        return messages[0]

    def hosts(self) -> list[str]:
        return [host for host in self.call("core", "view", "hosts").get("hosts", [])]

    def prime_site_tree(self, url: str, method: str, body: str, content_type: str) -> None:
        """Send one request through ZAP's proxy so the node enters the site tree.

        An active scan can only start from a node ZAP has seen, and core/sendRequest
        does not add a POST to the tree (BS0). Best effort: a target hiccup here
        must not abort the run, since the scan's own baseline gate catches it."""
        proxy = urllib.request.ProxyHandler({"http": self.base_url, "https": self.base_url})
        opener = urllib.request.build_opener(proxy, _NoRedirect())
        headers = {"Content-Type": content_type} if content_type else {}
        request = urllib.request.Request(
            url, data=body.encode() if body else None, headers=headers, method=method
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                response.read(MAX_API_RESPONSE_BYTES)
        except urllib.error.HTTPError as error:
            error.read()
        except urllib.error.URLError:
            pass


@dataclass(frozen=True)
class OracleResult:
    name: str
    confirmed: bool
    header_name: str | None = None


@dataclass(frozen=True)
class SeedRequest:
    url: str
    method: str
    post_data: str


def _parse_progress(value: Any, description: str) -> int:
    try:
        progress = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"ZAP returned invalid {description} progress") from error
    if progress < 0:
        raise RuntimeError(f"ZAP returned invalid {description} progress")
    return progress


def _verify_alert(
    cwe: int, alert: dict[str, Any], message: dict[str, Any]
) -> OracleResult:
    response_body = _message_text(message, "responseBody")
    response_header = _message_text(message, "responseHeader")
    if cwe == 89:
        confirmed = any(
            re.search(pattern, response_body, re.IGNORECASE)
            for pattern in _SQL_ERROR_PATTERNS
        )
        return OracleResult("database_error", confirmed)
    if cwe == 79:
        attack = alert.get("attack")
        confirmed = (
            isinstance(attack, str)
            and bool(attack)
            and attack in response_body
            and html.escape(attack, quote=True) != attack
        )
        return OracleResult("unescaped_reflection", confirmed)
    if cwe == 78:
        attack = alert.get("attack")
        if not isinstance(attack, str) or not attack:
            return OracleResult("command_output", False)
        marker_present = any(
            re.search(pattern, response_body, re.IGNORECASE)
            for pattern in _COMMAND_OUTPUT_PATTERNS
        )
        command_present = any(
            command in attack.casefold() for command in ("echo", "printf", "whoami", " id")
        )
        return OracleResult("command_output", marker_present and command_present)
    if cwe == 601:
        status = _response_status(response_header)
        location = _header_value(response_header, "location")
        if location is None or status is None or not 300 <= status < 400:
            return OracleResult("external_redirect", False)
        destination = urllib.parse.urlsplit(
            urllib.parse.urljoin(str(alert.get("url", "")), location)
        )
        confirmed = (
            destination.scheme in {"http", "https"}
            and destination.hostname is not None
            and destination.hostname.casefold() not in LOCALHOST_NAMES
        )
        return OracleResult("external_redirect", confirmed)
    if cwe == 693:
        header_name = _header_name(alert)
        if header_name is None:
            return OracleResult("missing_response_header", False)
        present = _header_value(response_header, header_name) is not None
        return OracleResult(
            "missing_response_header", not present, header_name.casefold()
        )
    return OracleResult("unsupported", False)


def _message_text(message: dict[str, Any], key: str) -> str:
    value = message.get(key)
    return value if isinstance(value, str) else ""


def _response_status(response_header: str) -> int | None:
    first_line = response_header.splitlines()[0] if response_header else ""
    match = re.match(r"HTTP/\S+\s+(\d{3})\b", first_line)
    return int(match.group(1)) if match else None


def _header_value(response_header: str, header_name: str) -> str | None:
    for line in response_header.splitlines()[1:]:
        name, separator, value = line.partition(":")
        if separator and name.casefold() == header_name.casefold():
            return value.strip()
    return None


def _header_name(alert: dict[str, Any]) -> str | None:
    for key in ("param", "alert", "name", "evidence"):
        value = alert.get(key)
        if not isinstance(value, str):
            continue
        match = _HEADER_NAME_PATTERN.search(value)
        if match:
            return match.group(0)
    return None


