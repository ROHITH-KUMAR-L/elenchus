"""Whole-program call graph over the Java source index.

Every call site becomes an edge. A site whose receiver type cannot be worked out
is kept with resolved=False, under the name as written: unresolved calls are
flagged, never dropped. There is no dataflow here.
"""

from __future__ import annotations

from common.pipeline import CallGraphEdge
from producers.sast.spring_routes import (
    SourceIndex,
    _children,
    _simple_name,
    _supertype_chain,
    _text,
    _walk,
)

CONSTRUCTOR = "<init>"
_SCOPE_NODES = ("method_declaration", "constructor_declaration")


def _is_type_name(name: str) -> bool:
    return name[:1].isupper()


def _written(node) -> str:
    """Source text of an expression on one line."""
    return " ".join(_text(node).split())


class MethodScope:
    """What one method body can see: its fields, params and local variables.

    A name declared twice with different types in one method resolves to nothing,
    since scoping is not modelled.
    """

    def __init__(self, index: SourceIndex, owner: dict, node) -> None:
        self.index = index
        self.owner = owner
        self.locals: dict[str, str | None] = {}
        for formal in _walk_formals(node):
            self._declare(_text(formal.child_by_field_name("name")), formal.child_by_field_name("type"))
        for declaration in _walk(node, "local_variable_declaration"):
            type_node = declaration.child_by_field_name("type")
            for declarator in _children(declaration, "variable_declarator"):
                self._declare_local(declarator, type_node)
        for loop in _walk(node, "enhanced_for_statement"):
            self._declare(_text(loop.child_by_field_name("name")), loop.child_by_field_name("type"))
        for catch in _walk(node, "catch_formal_parameter"):
            name = catch.child_by_field_name("name")
            types = _children(catch, "catch_type")
            if name is not None and types:
                self._declare(_text(name), types[0])

    def _declare(self, name: str, type_node) -> None:
        declared = _simple_name(_text(type_node)) if type_node is not None else None
        self._record(name, None if declared == "var" else declared)

    def _declare_local(self, declarator, type_node) -> None:
        name = _text(declarator.child_by_field_name("name"))
        declared = _simple_name(_text(type_node))
        if declared != "var":
            self._record(name, declared)
            return
        value = declarator.child_by_field_name("value")
        self._record(name, self.expression_type(value) if value is not None else None)

    def _record(self, name: str, declared: str | None) -> None:
        if name in self.locals and self.locals[name] != declared:
            self.locals[name] = None
        else:
            self.locals[name] = declared

    def field_type(self, name: str) -> str | None:
        for info in [self.owner, *_supertype_chain(self.index, self.owner)]:
            if name in info["fields"]:
                return info["fields"][name]
        return None

    def expression_type(self, node) -> str | None:
        """Static type of an expression, or None when it cannot be worked out."""
        if node is None:
            return None
        kind = node.type
        if kind == "this":
            return self.owner["name"]
        if kind == "identifier":
            name = _text(node)
            if name in self.locals:
                return self.locals[name]
            declared = self.field_type(name)
            if declared is not None:
                return declared
            return name if _is_type_name(name) else None
        if kind == "field_access":
            target = node.child_by_field_name("object")
            field = _text(node.child_by_field_name("field"))
            if target.type == "this":
                return self.field_type(field)
            target_type = self.expression_type(target)
            for info in self.index.types.get(target_type or "", []):
                if field in info["fields"]:
                    return info["fields"][field]
            return None
        if kind == "object_creation_expression":
            return _simple_name(_text(node.child_by_field_name("type")))
        if kind == "cast_expression":
            return _simple_name(_text(node.child_by_field_name("type")))
        if kind == "parenthesized_expression":
            return self.expression_type(node.named_children[0])
        if kind == "string_literal":
            return "String"
        if kind == "method_invocation":
            return self._invocation_type(node)
        return None

    def _invocation_type(self, node) -> str | None:
        receiver = self.expression_type(node.child_by_field_name("object"))
        if node.child_by_field_name("object") is None:
            receiver = self.owner["name"]
        if receiver is None:
            return None
        name = _text(node.child_by_field_name("name"))
        targets = _method_sites(self.index, receiver, name)
        returned = {site["return_type"] for _, site in targets}
        return returned.pop() if len(returned) == 1 else None


def _walk_formals(node):
    params = node.child_by_field_name("parameters")
    if params is not None:
        yield from _children(params, "formal_parameter")
    # Explicitly typed lambda params are formal parameters too.
    for lambda_node in _walk(node, "lambda_expression"):
        lambda_params = lambda_node.child_by_field_name("parameters")
        if lambda_params is not None and lambda_params.type == "formal_parameters":
            yield from _children(lambda_params, "formal_parameter")


def _method_sites(index: SourceIndex, type_name: str, method: str) -> list[tuple[dict, dict]]:
    """(owner, site) for a method on a project type: its implementations if it is
    abstract or an interface, else the nearest declaration up the hierarchy."""
    infos = index.types.get(type_name, [])
    sites = []
    for info in infos:
        if info["kind"] == "interface_declaration" or _is_abstract_method_owner(info, method):
            for implementor in index.implementations(type_name):
                for site in implementor["methods"].get(method, []):
                    sites.append((implementor, site))
            if sites:
                return sites
        for owner in [info, *_supertype_chain(index, info)]:
            found = owner["methods"].get(method)
            if found:
                return [(owner, site) for site in found]
    return sites


def _is_abstract_method_owner(info: dict, method: str) -> bool:
    return any(
        site["node"].child_by_field_name("body") is None for site in info["methods"].get(method, [])
    )


def _edges_for_target(caller, file, node, receiver, callee, index) -> list[CallGraphEdge]:
    line = node.start_point[0] + 1
    col = node.start_point[1]
    if receiver is None:
        return [CallGraphEdge(caller, callee, file, line, False, None, col, None)]
    name = callee.rsplit(".", 1)[-1]
    if name == CONSTRUCTOR or receiver not in index.types:
        return [CallGraphEdge(caller, f"{receiver}.{name}", file, line, True, None, col, receiver)]
    sites = _method_sites(index, receiver, name)
    if not sites:
        # On a project type but not declared there: Lombok, or an external base class.
        return [CallGraphEdge(caller, f"{receiver}.{name}", file, line, True, None, col, receiver)]
    return [
        CallGraphEdge(caller, f"{owner['name']}.{name}", file, line, True, site["file"], col, receiver)
        for owner, site in sites
    ]


def _edges_in_method(index: SourceIndex, owner: dict, node, caller: str) -> list[CallGraphEdge]:
    scope = MethodScope(index, owner, node)
    file = owner["file"]
    edges: list[CallGraphEdge] = []
    for call in _walk(node, "method_invocation"):
        name = _text(call.child_by_field_name("name"))
        target = call.child_by_field_name("object")
        if target is None:
            receiver = owner["name"]
            callee = name
        else:
            receiver = scope.expression_type(target)
            callee = f"{_written(target)}.{name}"
        edges += _edges_for_target(caller, file, call, receiver, callee, index)
    for creation in _walk(node, "object_creation_expression"):
        created = _simple_name(_text(creation.child_by_field_name("type")))
        edges += _edges_for_target(caller, file, creation, created, f"{created}.{CONSTRUCTOR}", index)
    for reference in _walk(node, "method_reference"):
        parts = reference.named_children
        if len(parts) >= 2:
            receiver = scope.expression_type(parts[0])
            name = _text(parts[-1])
            callee = CONSTRUCTOR if name == "new" else name
            edges += _edges_for_target(caller, file, reference, receiver, f"{_written(parts[0])}.{callee}", index)
    return edges


def build_call_graph(index: SourceIndex) -> tuple[CallGraphEdge, ...]:
    edges: list[CallGraphEdge] = []
    for infos in index.types.values():
        for info in infos:
            body = info["decl"].child_by_field_name("body")
            for member in body.named_children if body is not None else []:
                if member.type == "method_declaration":
                    name = _text(member.child_by_field_name("name"))
                elif member.type == "constructor_declaration":
                    name = CONSTRUCTOR
                else:
                    continue
                edges += _edges_in_method(index, info, member, f"{info['name']}.{name}")
    return tuple(sorted(edges, key=lambda e: (e.file, e.line, e.col, e.callee)))
