"""Stage 2: the own secrets and weak-crypto pass.

Finds hard-coded credentials (CWE-798), weak hashing and ciphers (CWE-327) and
weak random number generation (CWE-330) by matching general JDK APIs with
tree-sitter. There is no dataflow. Rules live in secrets.yaml.

Findings here are Code-only: they have no HTTP route and are never labelled
no_http_path. A target that hides a weakness behind its own wrapper is missed,
and that miss is a measured baseline, not fitted away.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from producers.sast.spring_routes import _text, _walk

RULES_FILE = Path(__file__).parent / "secrets.yaml"


@dataclass(frozen=True)
class SecretFinding:
    cwe: int
    type_name: str
    severity: str
    file: str
    line: int
    rule: str
    snippet: str


def load_rules(path: Path = RULES_FILE) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())


def _literal_value(node) -> str | None:
    """The text of a string literal argument, without quotes, or None."""
    if node is None or node.type != "string_literal":
        return None
    text = _text(node)
    return text[1:-1] if len(text) >= 2 else ""


def _call_parts(call) -> tuple[str | None, str, list[Any]]:
    """(receiver simple name, method name, argument nodes) for a method_invocation."""
    receiver = call.child_by_field_name("object")
    receiver_name = _text(receiver).split(".")[-1] if receiver is not None else None
    method = _text(call.child_by_field_name("name"))
    args_node = call.child_by_field_name("arguments")
    args = [a for a in args_node.named_children if a.type != "comment"] if args_node else []
    return receiver_name, method, args


def _weak_hash(call, rule) -> bool:
    receiver, method, args = _call_parts(call)
    if receiver not in rule["receiver_types"] or method not in rule["methods"]:
        return False
    value = _literal_value(args[rule["arg"]]) if len(args) > rule["arg"] else None
    if value is None:
        return False
    return value.upper() in {v.upper() for v in rule["weak_values"]}


def _weak_cipher(call, rule) -> bool:
    receiver, method, args = _call_parts(call)
    if receiver not in rule["receiver_types"] or method not in rule["methods"]:
        return False
    value = _literal_value(args[rule["arg"]]) if len(args) > rule["arg"] else None
    if value is None:
        return False
    algorithm = value.upper()
    prefix = algorithm.split("/")[0]
    if prefix in {p.upper() for p in rule["weak_prefixes"]}:
        return True
    parts = algorithm.split("/")
    return len(parts) > 1 and parts[1] in {m.upper() for m in rule["weak_modes"]}


def _static_call_matches(call, spec) -> bool:
    receiver, method, _ = _call_parts(call)
    return receiver == spec["receiver"] and method == spec["method"]


def find_secrets(files: list[tuple[str, Any]], rules: dict[str, Any] | None = None) -> list[SecretFinding]:
    rules = rules if rules is not None else load_rules()
    findings: list[SecretFinding] = []

    def add(rule_key: str, node) -> None:
        rule = rules[rule_key]
        findings.append(
            SecretFinding(
                cwe=rule["cwe"],
                type_name=rule["type"],
                severity=rule["severity"],
                file=rel,
                line=node.start_point[0] + 1,
                rule=rule_key,
                snippet=" ".join(_text(node).split())[:200],
            )
        )

    name_pattern = re.compile(rules["hardcoded_secret"]["name_pattern"])
    min_length = rules["hardcoded_secret"]["min_length"]
    random_ctors = set(rules["weak_random"]["constructors"])

    for rel, root in files:
        for call in _walk(root, "method_invocation"):
            if _weak_hash(call, rules["weak_hash"]):
                add("weak_hash", call)
            elif _weak_cipher(call, rules["weak_cipher"]):
                add("weak_cipher", call)
            elif any(_static_call_matches(call, spec) for spec in rules["weak_random"]["static_calls"]):
                add("weak_random", call)
        for creation in _walk(root, "object_creation_expression"):
            type_node = creation.child_by_field_name("type")
            if type_node is not None and _text(type_node).split(".")[-1] in random_ctors:
                add("weak_random", creation)
        for declarator in _walk(root, "variable_declarator"):
            name_node = declarator.child_by_field_name("name")
            value = _literal_value(declarator.child_by_field_name("value"))
            if (
                name_node is not None
                and value is not None
                and len(value) >= min_length
                and name_pattern.match(_text(name_node))
            ):
                add("hardcoded_secret", declarator)

    return sorted(findings, key=lambda f: (f.file, f.line, f.cwe))
