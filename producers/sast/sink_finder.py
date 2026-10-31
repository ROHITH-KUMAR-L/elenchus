"""Stage 2: the own sink finder. Matches call name and receiver type against the
YAML catalogue. There is no dataflow.

arg_shape is a syntax check on the sink's argument at the call site. Anything it
cannot read is dynamic, so a sink is only cleared on clear evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from common.pipeline import SinkSite
from common.record import SinkId
from producers.sast.call_graph import MethodScope
from producers.sast.spring_routes import SourceIndex, _children, _supertype_chain, _text, _walk

CATALOGUE_DIR = Path(__file__).parent / "catalogue"
_NOT_A_TEXT_ARGUMENT = {"lambda_expression", "method_reference"}
_TEXT_TYPES = {"String", "CharSequence", "StringBuilder", "StringBuffer"}


@dataclass(frozen=True)
class CatalogueEntry:
    entry_id: str
    api: str
    kind: str
    receiver_types: frozenset[str]
    methods: frozenset[str]
    sink_arg: int
    cwe: int
    type_name: str
    severity: str
    lambda_of: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Catalogue:
    entries: tuple[CatalogueEntry, ...]
    sanitisers: frozenset[tuple[str, str]]  # (receiver simple name, method)

    @property
    def method_names(self) -> frozenset[str]:
        return frozenset(name for entry in self.entries for name in entry.methods)

    def find(self, receiver_names: set[str], method: str) -> CatalogueEntry | None:
        for entry in self.entries:
            if method in entry.methods and entry.receiver_types & receiver_names:
                return entry
        return None

    def find_by_lambda(self, outer_names: set[str], method: str) -> CatalogueEntry | None:
        for entry in self.entries:
            if method in entry.methods and entry.lambda_of & outer_names:
                return entry
        return None


def load_catalogue(directory: Path = CATALOGUE_DIR) -> Catalogue:
    entries: list[CatalogueEntry] = []
    sanitisers: set[tuple[str, str]] = set()
    for path in sorted(directory.glob("*.yaml")):
        document: dict[str, Any] = yaml.safe_load(path.read_text())
        for raw in document["entries"]:
            if not raw.get("api"):
                raise ValueError(f"{path.name}: entry {raw.get('id')} must name its source API")
            entries.append(
                CatalogueEntry(
                    entry_id=raw["id"],
                    api=raw["api"],
                    kind=raw["kind"],
                    receiver_types=frozenset(raw["receiver_types"]),
                    methods=frozenset(raw["methods"]),
                    sink_arg=raw["sink_arg"],
                    cwe=document["cwe"],
                    type_name=document["type"],
                    severity=document["severity"],
                    lambda_of=frozenset(raw.get("lambda_of", ())),
                )
            )
        sanitisers.update((s["receiver"], s["method"]) for s in document.get("sanitisers", ()))
    return Catalogue(tuple(entries), frozenset(sanitisers))


def _lineage(index: SourceIndex, type_name: str | None) -> set[str]:
    """A type's simple name and those of its supertypes, external ones included."""
    if type_name is None:
        return set()
    names = {type_name}
    for info in index.types.get(type_name, []):
        names |= info["supertypes"]
        for parent in _supertype_chain(index, info):
            names.add(parent["name"])
            names |= parent["supertypes"]
    return names


def _enclosing_lambda_receiver(node, name: str, scope: MethodScope) -> str | None:
    """Type of the call a lambda is passed to, when name is that lambda's param."""
    current = node.parent
    while current is not None:
        if current.type == "lambda_expression":
            params = current.child_by_field_name("parameters")
            names = (
                {_text(params)}
                if params.type == "identifier"
                else {_text(p) for p in _walk(params, "identifier")}
            )
            if name in names:
                invocation = current.parent.parent if current.parent is not None else None
                if invocation is None or invocation.type != "method_invocation":
                    return None
                return scope.expression_type(invocation.child_by_field_name("object"))
        current = current.parent
    return None


def _is_constant_expression(index: SourceIndex, node, owner: str, literal_locals: set[str]) -> bool:
    kind = node.type
    if kind in {"string_literal", "text_block"}:
        return True
    if kind == "parenthesized_expression":
        return _is_constant_expression(index, node.named_children[0], owner, literal_locals)
    if kind == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
        return all(
            _is_constant_expression(index, node.child_by_field_name(side), owner, literal_locals)
            for side in ("left", "right")
        )
    if kind == "identifier":
        name = _text(node)
        return name in literal_locals or bool(index.resolve_strings(node, owner))
    if kind == "field_access":
        return bool(index.resolve_strings(node, owner))
    return False


def _constant_locals(index: SourceIndex, method, owner: str) -> set[str]:
    """Locals assigned exactly once, from a constant expression."""
    declared: dict[str, Any] = {}
    duplicates: set[str] = set()
    for declaration in _walk(method, "local_variable_declaration"):
        for declarator in _children(declaration, "variable_declarator"):
            name = _text(declarator.child_by_field_name("name"))
            if name in declared:
                duplicates.add(name)
            declared[name] = declarator.child_by_field_name("value")
    formal_names = {
        _text(formal.child_by_field_name("name"))
        for formal in _walk(method, "formal_parameter")
    }
    assigned = set()
    for assignment in _walk(method, "assignment_expression"):
        left = assignment.child_by_field_name("left")
        if left.type == "identifier":
            assigned.add(_text(left))
    for update in _walk(method, "update_expression"):
        assigned.update(_text(n) for n in update.named_children if n.type == "identifier")
    candidates = {
        name: value
        for name, value in declared.items()
        if value is not None
        and name not in duplicates | assigned | formal_names
    }
    # Repeat, because one constant local may be built from another.
    constant: set[str] = set()
    while True:
        found = {
            name
            for name, value in candidates.items()
            if name not in constant and _is_constant_expression(index, value, owner, constant)
        }
        if not found:
            return constant
        constant |= found


def _is_sanitised(argument, catalogue: Catalogue, scope: MethodScope) -> bool:
    if argument.type != "method_invocation":
        return False
    receiver = argument.child_by_field_name("object")
    name = _text(argument.child_by_field_name("name"))
    receiver_type = scope.expression_type(receiver) if receiver is not None else None
    return receiver_type is not None and (receiver_type, name) in catalogue.sanitisers


def arg_shape(
    index: SourceIndex, argument, owner: str, literal_locals: set[str], catalogue: Catalogue, scope: MethodScope
) -> str:
    if _is_constant_expression(index, argument, owner, literal_locals):
        return "constant"
    if _is_sanitised(argument, catalogue, scope):
        return "sanitised"
    return "dynamic"


def _sink_at_call(index, catalogue, scope, call) -> tuple[CatalogueEntry, str] | None:
    """The catalogue entry a call matches, by receiver type only, and how it matched."""
    method = _text(call.child_by_field_name("name"))
    if method not in catalogue.method_names:
        return None
    target = call.child_by_field_name("object")
    if target is None:
        return None
    receiver_type = scope.expression_type(target)
    if receiver_type is not None:
        entry = catalogue.find(_lineage(index, receiver_type), method)
        return (entry, "strict") if entry is not None else None
    if target.type != "identifier":
        return None
    outer = _enclosing_lambda_receiver(call, _text(target), scope)
    entry = catalogue.find_by_lambda(_lineage(index, outer), method)
    return (entry, "strict") if entry is not None else None


def find_sinks(index: SourceIndex, catalogue: Catalogue) -> list[SinkSite]:
    sites: list[SinkSite] = []
    for infos in index.types.values():
        for info in infos:
            body = info["decl"].child_by_field_name("body")
            for member in body.named_children if body is not None else []:
                if member.type == "method_declaration":
                    method_name = _text(member.child_by_field_name("name"))
                elif member.type == "constructor_declaration":
                    method_name = "<init>"
                else:
                    continue
                scope = MethodScope(index, info, member)
                literal_locals = _constant_locals(index, member, info["name"])
                for call in _walk(member, "method_invocation"):
                    matched = _sink_at_call(index, catalogue, scope, call)
                    if matched is not None:
                        site = _site(index, catalogue, scope, info, method_name,
                                     literal_locals, call, matched, require_text=True)
                        if site is not None:
                            sites.append(site)
                for creation in _walk(member, "object_creation_expression"):
                    matched = _sink_at_new(index, catalogue, scope, creation)
                    if matched is not None:
                        site = _site(index, catalogue, scope, info, method_name,
                                     literal_locals, creation, matched, require_text=False)
                        if site is not None:
                            sites.append(site)
    return sorted(sites, key=lambda s: (s.sink_id.file, s.sink_id.start_line, s.sink_id.start_col))


def _site(
    index, catalogue, scope, info, method_name, literal_locals, node, matched, *, require_text
) -> SinkSite | None:
    """One SinkSite for a matched call or constructor, or None if its argument is
    not a text sink. A constructor (ProcessBuilder) takes a String[] or List, not a
    bare String, so the text-type guard applies only to plain calls."""
    entry, match_mode = matched
    arguments = [
        n for n in node.child_by_field_name("arguments").named_children if n.type != "comment"
    ]
    if len(arguments) <= entry.sink_arg:
        return None
    argument = arguments[entry.sink_arg]
    if argument.type in _NOT_A_TEXT_ARGUMENT:
        return None
    if require_text:
        # A typed object, such as a CriteriaQuery, carries no query text.
        argument_type = scope.expression_type(argument)
        if argument_type is not None and argument_type not in _TEXT_TYPES:
            return None
    return SinkSite(
        sink_id=SinkId(
            info["file"],
            f"{info['name']}.{method_name}",
            node.start_point[0] + 1,
            node.start_point[1],
        ),
        cwe=entry.cwe,
        kind=entry.kind,
        arg_shape=arg_shape(index, argument, info["name"], literal_locals, catalogue, scope),
        catalogue_entry=entry.entry_id,
        match_mode=match_mode,
        line=argument.start_point[0] + 1,
        type_name=entry.type_name,
        severity=entry.severity,
        snippet=" ".join(_text(argument).split())[:300],
    )


def _sink_at_new(index, catalogue, scope, creation) -> tuple[CatalogueEntry, str] | None:
    """The catalogue entry a constructor call matches, by the created type."""
    type_node = creation.child_by_field_name("type")
    if type_node is None:
        return None
    simple = _text(type_node).split("<")[0].split("[")[0].strip().split(".")[-1]
    entry = catalogue.find(_lineage(index, simple), "<init>")
    return (entry, "strict") if entry is not None else None
