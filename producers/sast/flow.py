"""Own flow engine (Should, off until measured).

Intraprocedural forward taint: which of a method's formal parameters reach a
target expression (a sink argument), through local assignments and string
concatenation, within one method. It narrows candidate_params from every route
param to the ones that syntactically flow to the sink.

No interprocedural analysis. A value that leaves the method, or arrives through a
field or an unresolved call, is not tracked, so a formal that cannot be shown to
reach the sink is simply dropped from the narrowed set. Gate for turning it on:
it must match the offline Semgrep count on VulnerableApp (flow.enabled, default
off).
"""

from __future__ import annotations

from producers.sast.spring_routes import _text, _walk


def _formal_names(method) -> set[str]:
    names = set()
    for formal in _walk(method, "formal_parameter"):
        name = formal.child_by_field_name("name")
        if name is not None:
            names.add(_text(name))
    return names


def _identifiers(node) -> set[str]:
    return {_text(n) for n in _walk(node, "identifier")}


def reaching_formals(method, target) -> set[str]:
    """The formal parameters of `method` whose value can reach `target`.

    origins[name] is the set of formals a local derives from. Locals start empty;
    formals derive from themselves. Assignments propagate origins to a fixpoint,
    then the formals reaching target are the origins of the identifiers in it.
    """
    formals = _formal_names(method)
    origins: dict[str, set[str]] = {name: {name} for name in formals}

    def expr_origins(expr) -> set[str]:
        result: set[str] = set()
        for name in _identifiers(expr):
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
