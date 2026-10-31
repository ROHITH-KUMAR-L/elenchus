"""Run a localhost-scoped OWASP ZAP active scan and verify its alerts."""

from __future__ import annotations

import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from common.record import (
    LOCALHOST_NAMES,
    Finding,
    RouteMap,
    ScanTarget,
    normalise_route,
)
from common.vocabulary import type_name

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

    def __init__(self, base_url: str, api_key: str, timeout: float = 10) -> None:
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


def run_dast(target: ScanTarget, route_map: RouteMap) -> list[Finding]:
    """Scan only routes from the supplied map, inside an exact localhost scope."""
    if not route_map:
        raise ValueError("DAST requires a non-empty route map")
    target_parts = urllib.parse.urlsplit(target.base_url)
    if (
        target_parts.hostname not in LOCALHOST_NAMES
        or target_parts.query
        or target_parts.fragment
        or target_parts.username is not None
        or target_parts.password is not None
    ):
        raise ValueError("DAST target must be a localhost URL without credentials or query")
    timeout = _scan_timeout()
    deadline = time.monotonic() + timeout
    api = ZapApi.from_environment()
    context_name = f"elenchus-{target.run_id}"
    context_created = False

    try:
        context_id = api.create_context(context_name, _scope_regex(target))
        context_created = True
        requests = _seed_requests(target, route_map)
        for request in requests:
            _check_deadline(deadline)
            api.access_url(request.url)
            scan_id = api.start_active_scan(
                request.url, request.method, request.post_data, context_id
            )
            _wait_for_active_scan(api, scan_id, deadline)
        _wait_for_passive_scan(api, deadline)
        findings = []
        for alert in api.alerts(target.base_url):
            finding = _alert_to_finding(target, route_map, alert, api)
            if finding is not None:
                findings.append(finding)
        return findings
    finally:
        if context_created:
            api.remove_context(context_name)


@dataclass(frozen=True)
class SeedRequest:
    url: str
    method: str
    post_data: str


def _seed_requests(target: ScanTarget, route_map: RouteMap) -> tuple[SeedRequest, ...]:
    requests: dict[tuple[str, str, str], SeedRequest] = {}
    base_url = target.base_url.rstrip("/")
    for entry in route_map:
        path_values = {
            param.name: "1" for param in entry.params if param.source == "path"
        }
        path = _TEMPLATE_PARAM_PATTERN.sub(
            lambda match: path_values.get(match.group(1), "1"),  # noqa: B023
            entry.route,
        )
        url = f"{base_url}/{path.lstrip('/')}"
        query_params = [
            (param.name, "elenchus")
            for param in entry.params
            if param.source == "query"
        ]
        method = entry.method.upper()
        if method == "ANY":
            method = "GET"
        if method in {"POST", "PUT", "PATCH"}:
            post_data = urllib.parse.urlencode(query_params)
        else:
            post_data = ""
            if query_params:
                query = urllib.parse.urlencode(query_params)
                url = f"{url}?{query}"
        requests[(url, method, post_data)] = SeedRequest(url, method, post_data)
    return tuple(requests[key] for key in sorted(requests))


def _scope_regex(target: ScanTarget) -> str:
    parts = urllib.parse.urlsplit(target.base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    prefix = f"{origin}{parts.path.rstrip('/')}"
    return rf"^{re.escape(prefix)}(?:/[^?#]*)?(?:\?[^#]*)?$"


def _scan_timeout() -> int:
    raw_timeout = os.environ.get(
        "ZAP_SCAN_TIMEOUT_SECONDS", str(DEFAULT_SCAN_TIMEOUT_SECONDS)
    )
    try:
        timeout = int(raw_timeout)
    except ValueError as error:
        raise ValueError("ZAP_SCAN_TIMEOUT_SECONDS must be a positive integer") from error
    if timeout < 1:
        raise ValueError("ZAP_SCAN_TIMEOUT_SECONDS must be a positive integer")
    return timeout


def _parse_progress(value: Any, description: str) -> int:
    try:
        progress = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"ZAP returned invalid {description} progress") from error
    if progress < 0:
        raise RuntimeError(f"ZAP returned invalid {description} progress")
    return progress


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("ZAP scan exceeded ZAP_SCAN_TIMEOUT_SECONDS")


def _wait_for_active_scan(api: ZapApi, scan_id: str, deadline: float) -> None:
    while True:
        _check_deadline(deadline)
        if api.active_scan_status(scan_id) >= 100:
            return
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0, deadline - time.monotonic())))


def _wait_for_passive_scan(api: ZapApi, deadline: float) -> None:
    while True:
        _check_deadline(deadline)
        if api.passive_records_to_scan() == 0:
            return
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0, deadline - time.monotonic())))


def _alert_to_finding(
    target: ScanTarget,
    route_map: RouteMap,
    alert: dict[str, Any],
    api: ZapApi,
) -> Finding | None:
    try:
        cwe = int(alert.get("cweid", ""))
    except (TypeError, ValueError):
        return None
    if cwe not in SUPPORTED_CWES:
        return None
    url = alert.get("url")
    if not isinstance(url, str) or not _url_is_in_target_scope(url, target):
        return None
    route = normalise_route(url, route_map, target.base_path)
    if route is None:
        return None
    method = alert.get("method")
    if not isinstance(method, str) or not method:
        method = "GET"
    method = method.upper()
    if not any(
        entry.route == route and entry.method in {method, "ANY"}
        for entry in route_map
    ):
        return None
    message_id = alert.get("messageId")
    if message_id is None:
        return None
    message = api.message(str(message_id))
    oracle = _verify_alert(cwe, alert, message)
    if not oracle.confirmed:
        return None

    param = alert.get("param")
    if not isinstance(param, str) or not param.strip():
        param = None
    attack = alert.get("attack")
    payload = attack if isinstance(attack, str) and attack else None
    request_header = _message_text(message, "requestHeader")
    request_body = _message_text(message, "requestBody")
    response_body = _message_text(message, "responseBody")
    evidence: dict[str, Any] = {
        "scanner": "owasp-zap",
        "oracle": oracle.name,
        "alert": str(alert.get("alert", "")),
        "plugin_id": str(alert.get("pluginId", "")),
        "scanner_severity": alert.get("risk"),
        "request": request_header.splitlines()[0] if request_header else "",
        "request_body": request_body[:500],
        "response_excerpt": response_body[:500],
    }
    if oracle.header_name is not None:
        evidence["header_name"] = oracle.header_name
    wasc_id = _optional_nonnegative_int(alert.get("wascid"))
    severity = _zap_severity(alert.get("risk"))
    return Finding.from_dict(
        {
            "run_id": target.run_id,
            "source": "dast",
            "provenance": "zap",
            "cwe": cwe,
            "type": type_name(cwe),
            "route": route,
            "method": method,
            "param": param,
            "payload": payload,
            "evidence": [{"type": "ORACLE", "detail": evidence}],
            "severity": severity,
            "wasc_id": wasc_id,
        }
    )


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


def _url_is_in_target_scope(url: str, target: ScanTarget) -> bool:
    candidate = urllib.parse.urlsplit(url)
    expected = urllib.parse.urlsplit(target.base_url)
    if (
        candidate.scheme != expected.scheme
        or candidate.hostname != expected.hostname
        or candidate.port != expected.port
    ):
        return False
    base_path = expected.path.rstrip("/")
    return not base_path or candidate.path == base_path or candidate.path.startswith(
        base_path + "/"
    )


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


def _optional_nonnegative_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _zap_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }.get(value.casefold())
