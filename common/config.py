"""Run configuration. Keys and defaults mirror the Config reference in
docs/architecture.md, and a test keeps the two in step.

Values come from the defaults, then an optional TOML file, then explicit
overrides. Unknown keys and wrong types are errors, not silently ignored.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from common.record import HEADER_COUNT_MODES, LOCALHOST_NAMES

# None means no default: a required input, or a value still to be measured.
DEFAULTS: dict[str, Any] = {
    "target.base_url": None,
    "target.source_path": None,
    "target.context_path": None,
    "target.auth.header_name": None,
    "target.auth.value_env": None,
    "judging.profile": False,
    "semgrep.enabled": False,
    "zap.enabled": True,
    "zap.api_url": "http://127.0.0.1:8090",
    "zap.api_key": None,
    "zap.version": "2.17.0",
    "zap.rule_map.89": ("40018", "40019", "40020", "40021", "40022", "40027"),
    "zap.rule_map.79": ("40012",),
    "zap.rule_map.78": ("90020",),
    "zap.rule_map.22": ("6",),
    "zap.rule_map.601": ("20019",),
    "zap.attack_strength.directed": "MEDIUM",
    "zap.attack_strength.sweep": "LOW",
    "zap.thread_per_host": 2,
    "logtail.enabled": False,
    "ai.enabled": False,
    "ai.max_calls": 30,
    "probe.max_job_seconds": 30,
    "probe.max_jobs": 60,
    "probe.drift_routes": 3,
    "probe.timing_repeats": None,
    "probe.stage_budget_seconds.index_static": 30,
    "probe.stage_budget_seconds.preflight": 20,
    "probe.stage_budget_seconds.zap_jobs": 170,
    "probe.stage_budget_seconds.replay": 40,
    "probe.stage_budget_seconds.output": 20,
    "replay.count": 3,
    "replay.min_hits": 2,
    "backguided.enabled": False,
    "backguided.max_unresolved_hops": 3,
    "backguided.start_confidence": 0.55,
    "backguided.hop_penalty": 0.1,
    "backguided.min_confidence_to_confirm": 0.4,
    "confidence.band.low_max": 0.4,
    "confidence.band.high_min": 0.7,
    "confidence.weight.oracle_fired": 0.5,
    "confidence.weight.path_exists": 0.2,
    "confidence.weight.unique_link": 0.15,
    "confidence.weight.ambiguous_penalty": -0.25,
    "confidence.weight.catalogue_gap_penalty": -0.1,
    "confidence.weight.family_match": 0.1,
    "export.include_alternatives": True,
    "export.include_suppressed": False,
    "export.suppress_cwes": (79, 78, 601, 22),
    "export.suppress_no_http_path": False,
    "export.no_http_path_suppress_cwes": (22, 78, 79, 89, 601),
    "export.count_multi_entry": None,
    "header.count_mode": "per_app",
}

# Keys with a free segment. Each pattern maps to the type its values must have.
_TEMPLATE_KEYS: tuple[tuple[re.Pattern[str], type], ...] = (
    (re.compile(r"ai\.tasks\.[a-z0-9_]+\.enabled"), bool),
    (re.compile(r"zap\.rule_map\.[0-9]+"), tuple),
)
# Keys whose default is None, with the type a set value must have.
_UNSET_KEY_TYPES: dict[str, type] = {
    "target.base_url": str,
    "target.source_path": str,
    "target.context_path": str,
    "target.auth.header_name": str,
    "target.auth.value_env": str,
    "zap.api_key": str,
    "probe.timing_repeats": int,
    "export.count_multi_entry": str,
}
_ATTACK_STRENGTHS = {"LOW", "MEDIUM", "HIGH", "INSANE"}
_FORCED_OFF_WHEN_JUDGING = ("semgrep.enabled", "logtail.enabled", "ai.enabled")


class Config(Mapping[str, Any]):
    """Read-only, validated settings. Its repr never shows values, so a stray log
    line cannot print the API key."""

    def __init__(self, values: Mapping[str, Any]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"Config({len(self._values)} keys)"

    def rule_map(self) -> dict[int, tuple[str, ...]]:
        prefix = "zap.rule_map."
        return {
            int(key.removeprefix(prefix)): value
            for key, value in self._values.items()
            if key.startswith(prefix)
        }

    def task_enabled(self, name: str) -> bool:
        return bool(self["ai.enabled"]) and bool(
            self._values.get(f"ai.tasks.{name}.enabled", False)
        )


def load_config(
    path: Path | None = None,
    overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] = os.environ,
) -> Config:
    values = dict(DEFAULTS)
    if environ.get("ZAP_API_KEY"):
        values["zap.api_key"] = environ["ZAP_API_KEY"]
    if path is not None:
        with path.open("rb") as handle:
            values.update(_checked(_flatten(tomllib.load(handle))))
    if overrides:
        values.update(_checked(overrides))
    _apply_judging_profile(values)
    _validate(values)
    return Config(values)


def _flatten(table: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in table.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            flat.update(_flatten(value, f"{name}."))
        else:
            flat[name] = value
    return flat


def _checked(raw: Mapping[str, Any]) -> dict[str, Any]:
    checked = {}
    for key, value in raw.items():
        if isinstance(value, list):
            value = tuple(value)
        expected = _expected_type(key)
        if isinstance(value, bool) != (expected is bool) or not isinstance(value, expected):
            if not (expected is float and isinstance(value, int) and not isinstance(value, bool)):
                raise ValueError(f"config {key} must be of type {expected.__name__}")
            value = float(value)
        checked[key] = value
    return checked


def _expected_type(key: str) -> type:
    if key in _UNSET_KEY_TYPES:
        return _UNSET_KEY_TYPES[key]
    if key in DEFAULTS:
        return type(DEFAULTS[key])
    for pattern, expected in _TEMPLATE_KEYS:
        if pattern.fullmatch(key):
            return expected
    raise ValueError(f"unknown config key: {key}")


def _apply_judging_profile(values: dict[str, Any]) -> None:
    if not values["judging.profile"]:
        return
    if not values["zap.enabled"]:
        raise ValueError("judging.profile requires zap.enabled: ZAP is the probe engine")
    for key in _FORCED_OFF_WHEN_JUDGING:
        values[key] = False
    for key in values:
        if key.startswith("ai.tasks."):
            values[key] = False


def _validate(values: Mapping[str, Any]) -> None:
    parts = urlsplit(values["zap.api_url"])
    if parts.scheme != "http" or parts.hostname not in LOCALHOST_NAMES:
        raise ValueError("zap.api_url must be an http URL on loopback")
    base_url = values["target.base_url"]
    if base_url is not None and urlsplit(base_url).hostname not in LOCALHOST_NAMES:
        raise ValueError("target.base_url must be on localhost")
    if values["header.count_mode"] not in HEADER_COUNT_MODES:
        raise ValueError(f"header.count_mode must be one of {', '.join(sorted(HEADER_COUNT_MODES))}")
    for key in ("zap.attack_strength.directed", "zap.attack_strength.sweep"):
        if values[key] not in _ATTACK_STRENGTHS:
            raise ValueError(f"{key} must be one of {', '.join(sorted(_ATTACK_STRENGTHS))}")
    if not 1 <= values["replay.min_hits"] <= values["replay.count"]:
        raise ValueError("replay.min_hits must be between 1 and replay.count")
    if not values["confidence.band.low_max"] < values["confidence.band.high_min"]:
        raise ValueError("confidence.band.low_max must be below confidence.band.high_min")
