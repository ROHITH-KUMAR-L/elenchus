"""Typed seed requests from the code index.

A seed is a valid, benign request for a route: path variables filled, query and
body params given harmless values from their declared types. ZAP mutates the
seed; attribution diffs each message against it. The coordinator sends the seed
first so the baseline reflects a well-formed request.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote, urlencode

from common.pipeline import SeedRequest
from common.record import RouteEntry

_TEMPLATE_PARAM = re.compile(r"\{([^{}]+)\}")
# Types that must stay numeric, or Spring rejects the request before our code runs.
_NUMERIC_TYPES = {
    "int", "Integer", "long", "Long", "short", "Short", "byte", "Byte",
    "double", "Double", "float", "Float", "BigDecimal", "BigInteger",
}
_BENIGN_TEXT = "1"
_BENIGN_NUMBER = "1"
_BENIGN_BOOL = "true"


def _benign(java_type: str | None) -> str:
    if java_type in _NUMERIC_TYPES:
        return _BENIGN_NUMBER
    if java_type in {"boolean", "Boolean"}:
        return _BENIGN_BOOL
    return _BENIGN_TEXT


def _nest(flat: dict[str, str]) -> dict:
    """{'a.b': '1'} -> {'a': {'b': '1'}}, for JSON bodies with nested DTO fields."""
    root: dict = {}
    for dotted, value in flat.items():
        node = root
        parts = dotted.split(".")
        for key in parts[:-1]:
            node = node.setdefault(key, {})
        node[parts[-1]] = value
    return root


def build_seed(entry: RouteEntry, base_url: str) -> SeedRequest:
    path_values = {p.name: _benign(p.java_type) for p in entry.params if p.source == "path"}
    path = _TEMPLATE_PARAM.sub(lambda m: quote(path_values.get(m.group(1), _BENIGN_TEXT)), entry.route)
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    query = [(p.name, _benign(p.java_type)) for p in entry.params if p.source == "query"]
    body_params = [p for p in entry.params if p.source == "body"]
    method = entry.method.upper()
    if method == "ANY":
        method = "GET"

    if query:
        url = f"{url}?{urlencode(query)}"

    if not body_params or method in {"GET", "DELETE", "HEAD"}:
        return SeedRequest(url=url, method=method, body="", content_type="")

    flat = {p.name: _benign(p.java_type) for p in body_params}
    if any(p.body_format == "json" for p in body_params):
        return SeedRequest(
            url=url, method=method, body=json.dumps(_nest(flat)), content_type="application/json"
        )
    return SeedRequest(
        url=url, method=method, body=urlencode(flat), content_type="application/x-www-form-urlencoded"
    )
