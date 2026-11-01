"""Own flow engine (Should, off until measured).

Intraprocedural forward taint: which of a method's formal parameters reach a
target expression (a sink argument), through local assignments, string
concatenation, `String.format`, `StringBuilder.append`/`insert` and for-each
binding, within one method. It narrows candidate_params from every route param
to the ones that syntactically flow to the sink.

A value that passes through a known sanitiser call (an HTML escaper) is treated
as clean: the identifiers inside that call contribute no taint. This is how a
response-body sink tells an escaped (safe) variant from an unescaped one.

No interprocedural analysis. A value that leaves the method, or arrives through a
field or an unresolved call, is not tracked, so a formal that cannot be shown to
reach the sink is simply dropped from the narrowed set. Gate for turning the
narrowing on by default: it must match the offline Semgrep count on VulnerableApp
(flow.enabled, default off). The sanitiser-aware taint gate for response-body
sinks (CWE-79) is separate and always on, because without it every handler that
returns a String would look vulnerable.
"""

from __future__ import annotations

from collections.abc import Iterable

from producers.sast.spring_routes import _text, _walk

# Builder-style methods that carry their argument's taint into the receiver.
_APPEND_METHODS = frozenset({"append", "insert", "add"})


def _formal_names(method) -> set[str]:
    names = set()
    for formal in _walk(method, "formal_parameter"):
        name = formal.child_by_field_name("name")
        if name is not None:
            names.add(_text(name))
    return names


def _sanitiser_pruned_identifiers(node, sanitisers: frozenset[str]) -> set[str]:
    """Identifiers in `node`, skipping the arguments of any sanitiser call.

    A call `escapeHtml4(x)` whose name is a sanitiser contributes nothing: the
    taint in `x` is considered neutralised at that point.
    """
    if sanitisers and node.type == "method_invocation":
        name = node.child_by_field_name("name")
        if name is not None and _text(name) in sanitisers:
            return set()
    if node.type == "identifier":
        return {_text(node)}
    result: set[str] = set()
    for child in node.named_children:
        result |= _sanitiser_pruned_identifiers(child, sanitisers)
    return result


def _leftmost_identifier(node):
    """The receiver identifier of a (possibly chained) call: `a.b().c()` -> `a`."""
    current = node
    while current is not None:
        if current.type == "identifier":
            return current
        if current.type == "method_invocation":
            current = current.child_by_field_name("object")
            continue
        if current.type == "field_access":
            current = current.child_by_field_name("object")
            continue
        return None
    return None


def reaching_formals(method, target, sanitisers: Iterable[str] = ()) -> set[str]:
    """The formal parameters of `method` whose value can reach `target`.

    origins[name] is the set of formals a local derives from. Locals start empty;
    formals derive from themselves. Assignments, for-each bindings and builder
    appends propagate origins to a fixpoint, then the formals reaching target are
    the origins of the identifiers in it.
    """
    sanitiser_set = frozenset(sanitisers)
    formals = _formal_names(method)
    origins: dict[str, set[str]] = {name: {name} for name in formals}

    def expr_origins(expr) -> set[str]:
        result: set[str] = set()
        for name in _sanitiser_pruned_identifiers(expr, sanitiser_set):
            result |= origins.get(name, set())
        return result

    assignments: list[tuple[str, object]] = []
    for declaration in _walk(method, "local_variable_declaration"):
        for declarator in _walk(declaration, "variable_declarator"):
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None and value is not None:
                assignments.append((_text(name), value))
    for assignment in _walk(method, "assignment_expression"):
        left = assignment.child_by_field_name("left")
        right = assignment.child_by_field_name("right")
        if left is not None and left.type == "identifier" and right is not None:
            assignments.append((_text(left), right))
    # for (T v : iterable) binds v to the taint of iterable.
    for loop in _walk(method, "enhanced_for_statement"):
        name = loop.child_by_field_name("name")
        value = loop.child_by_field_name("value")
        if name is not None and value is not None:
            assignments.append((_text(name), value))
    # sb.append(x) / list.add(x): x's taint flows into the receiver sb/list.
    for call in _walk(method, "method_invocation"):
        name = call.child_by_field_name("name")
        receiver = call.child_by_field_name("object")
        args = call.child_by_field_name("arguments")
        if name is None or receiver is None or args is None:
            continue
        if _text(name) not in _APPEND_METHODS:
            continue
        root = _leftmost_identifier(receiver)
        if root is None:
            continue
        for arg in args.named_children:
            if arg.type != "comment":
                assignments.append((_text(root), arg))

    for _ in range(len(assignments) + 1):  # propagate to a fixpoint
        changed = False
        for name, value in assignments:
            new = origins.get(name, set()) | expr_origins(value)
            if new != origins.get(name, set()):
                origins[name] = new
                changed = True
        if not changed:
            break

    return expr_origins(target) & formals
