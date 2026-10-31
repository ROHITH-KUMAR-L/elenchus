"""Supplemental ZAP passive-alert ingestion.

ZAP's passive scanner raises alerts by observing traffic — missing headers,
information leaks, cookie flags. They are advisory context, never a verdict: the
project's deterministic oracles own every verdict, and a passive alert never
creates, deletes or changes a Finding. This module reads the alerts ZAP recorded
and keeps the ones our active scanners did not raise, so the advisory list does
not duplicate what the oracles already judged.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AdvisoryAlert:
    plugin_id: str
    name: str
    risk: str
    url: str
    param: str
    cwe: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "risk": self.risk,
            "url": self.url,
            "param": self.param,
            "cwe": self.cwe,
            "advisory": True,
        }


def ingest(
    alerts: Iterable[Mapping[str, Any]], active_rule_ids: Iterable[str]
) -> list[AdvisoryAlert]:
    """Advisory alerts from ZAP's history: every alert whose plugin is not one of
    our active scanners. Deduplicated by (plugin, url, param)."""
    active = {str(rule) for rule in active_rule_ids}
    seen: set[tuple[str, str, str]] = set()
    advisory: list[AdvisoryAlert] = []
    for alert in alerts:
        plugin_id = str(alert.get("pluginId", "")).strip()
        if not plugin_id or plugin_id in active:
            continue
        url = str(alert.get("url", ""))
        param = str(alert.get("param", ""))
        key = (plugin_id, url, param)
        if key in seen:
            continue
        seen.add(key)
        advisory.append(
            AdvisoryAlert(
                plugin_id=plugin_id,
                name=str(alert.get("alert") or alert.get("name") or ""),
                risk=str(alert.get("risk", "")),
                url=url,
                param=param,
                cwe=_int_or_none(alert.get("cweid")),
            )
        )
    return advisory


def _int_or_none(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None
