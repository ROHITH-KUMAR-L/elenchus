"""Attribute one ZAP-captured message to a (param, CWE), from the request itself.

ZAP alerts do not carry a hypothesis id, so the coordinator never links from an
alert. For each message of a finished scan it reads the request and works out:

- the param, by diffing the request against the job's seed request;
- the CWE, from the active-scan rule id ZAP injects into X-ZAP-Scan-ID.

A message is attributable only when the probe header carries the job canary, the
rule header maps to a CWE, the path still matches the seed, and exactly one param
changed. Anything else stays unlinked; lineage is never guessed. BS0 confirmed
this holds on VulnerableApp query, form, JSON and (scoped) path parameters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

PROBE_HEADER = "X-Elenchus-Probe"
RULE_HEADER = "X-ZAP-Scan-ID"


@dataclass(frozen=True)
class Attribution:
    param: str
    cwe: int
    rule_id: str
    param_location: str
    param_path: str | None = None


def header_value(request_header: str, name: str) -> str | None:
    """First value of a header in a raw request, case-insensitively."""
    for line in request_header.splitlines()[1:]:
        key, separator, value = line.partition(":")
        if separator and key.strip().casefold() == name.casefold():
            return value.strip()
    return None


def request_path(request_header: str) -> str | None:
    """Path of the request line's target, without query or fragment."""
    parts = request_header.splitlines()
    if not parts:
        return None
    fields = parts[0].split(" ")
    if len(fields) < 2:
        return None
    return urlsplit(fields[1]).path


def request_values(request_header: str, request_body: str) -> dict[str, str]:
    """Every readable input of a request, keyed by location and name.

    Query and path keys compare against the seed to find what a scan rule changed.
    A JSON or form body is flattened; an unparseable body is one opaque value.
    """
    target = ""
    parts = request_header.splitlines()
    if parts:
        fields = parts[0].split(" ")
        if len(fields) >= 2:
            target = fields[1]
    split = urlsplit(target)
    values = {f"path[{index}]": segment for index, segment in enumerate(split.path.split("/")) if segment}
    values.update({f"query.{key}": value for key, value in parse_qsl(split.query, keep_blank_values=True)})
    if not request_body:
        return values
    stripped = request_body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            decoded = json.loads(request_body)
        except json.JSONDecodeError:
            values["body"] = request_body
        else:
            if isinstance(decoded, dict):
                values.update({f"json.{key}": json.dumps(value) for key, value in decoded.items()})
            else:
                values["body"] = request_body
    elif "=" in request_body:
        values.update(
            {f"form.{key}": value for key, value in parse_qsl(request_body, keep_blank_values=True)}
        )
    else:
        values["body"] = request_body
    return values


def changed_keys(seed: dict[str, str], request: dict[str, str]) -> list[str]:
    return sorted(key for key in seed.keys() | request.keys() if seed.get(key) != request.get(key))


def _param_name(key: str) -> str:
    """The bare param name behind a diff key such as 'query.id' or 'json.user'."""
    if key.startswith(("query.", "form.", "json.")):
        return key.split(".", 1)[1]
    return key


def _param_location(key: str) -> str:
    if key.startswith("query."):
        return "query"
    if key.startswith("path["):
        return "path"
    if key.startswith(("form.", "json.")) or key == "body":
        return "body"
    raise ValueError(f"unrecognized request parameter key: {key}")


def attribute(
    request_header: str,
    request_body: str,
    *,
    seed_path: str,
    seed_values: dict[str, str],
    canary: str,
    rule_cwes: dict[str, int],
) -> Attribution | None:
    """The (param, CWE) a message probes, or None when it cannot be pinned to one."""
    if header_value(request_header, PROBE_HEADER) != canary:
        return None
    rule_id = header_value(request_header, RULE_HEADER)
    if rule_id is None or rule_id not in rule_cwes:
        return None
    if request_path(request_header) != seed_path:
        return None
    changed = changed_keys(seed_values, request_values(request_header, request_body))
    if len(changed) != 1:
        return None
    key = changed[0]
    return Attribution(
        param=_param_name(key),
        cwe=rule_cwes[rule_id],
        rule_id=rule_id,
        param_location=_param_location(key),
    )
