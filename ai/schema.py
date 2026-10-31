"""A tiny JSON-schema check, so AI output is machine-validated without a new
dependency. It covers the shapes the advisory tasks use: an object with required
string, number, boolean, array and nested-object fields.
"""

from __future__ import annotations

from typing import Any

_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
}


def valid(value: Any, schema: dict[str, Any]) -> bool:
    """True when value matches schema. A wrong answer fails here and is dropped."""
    expected = schema.get("type")
    if expected is not None:
        check = _CHECKS.get(expected)
        if check is None or not check(value):
            return False
    if expected == "object":
        for name in schema.get("required", ()):
            if name not in value:
                return False
        for name, sub in schema.get("properties", {}).items():
            if name in value and not valid(value[name], sub):
                return False
    if expected == "array":
        item = schema.get("items")
        if item is not None and not all(valid(element, item) for element in value):
            return False
    return True
