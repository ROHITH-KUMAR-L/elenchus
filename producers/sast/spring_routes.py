"""Spring MVC route-map parser.

Reads Java source with tree-sitter and returns one entry per (route, method)
handler, in the RouteMap field shape from docs/finding-schema.md:
route, method, file, func, line_start, line_end, params, calls.

Entries are plain dicts until common/record.py defines RouteMap.

Generic over the target app: custom annotations are resolved through their
Spring meta-annotations (@RequestMapping, @RestController, @AliasFor), and
path/param values are resolved through string constants, so no route or
annotation name from a specific test app is hard-coded.
"""

import json
import re
import sys
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Parser

JAVA = Language(tree_sitter_java.language())

CONTROLLER_ANNOTATIONS = {"RestController", "Controller"}

# Built-in Spring mapping annotations: name -> fixed HTTP method (None = from attribute).
MAPPING_ANNOTATIONS = {
    "RequestMapping": None,
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

PARAM_ANNOTATIONS = {"RequestParam": "query", "PathVariable": "path"}
MAP_PARAM_GETTERS = {"get", "getOrDefault", "getFirst", "containsKey"}
TYPE_DECLARATIONS = ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration")
ANY_METHOD = "ANY"


def _text(node):
    return node.text.decode("utf-8")


def _simple_name(name):
    """Last segment of a possibly qualified name, without generics."""
    return re.sub(r"<.*>", "", name).split(".")[-1].strip()


def _line_span(node):
    return node.start_point[0] + 1, node.end_point[0] + 1


def _children(node, *types):
    return [c for c in node.named_children if c.type in types]


def _annotations(decl):
    """(name, args_node) for each annotation in a declaration's modifiers."""
    result = []
    for mods in _children(decl, "modifiers"):
        for ann in _children(mods, "annotation", "marker_annotation"):
            result.append((_simple_name(_text(ann.child_by_field_name("name"))), ann.child_by_field_name("arguments")))
    return result


def _annotation_args(args_node):
    """Map attribute name -> value node. A bare value is attribute 'value'."""
    if args_node is None:
        return {}
    args = {}
    for child in args_node.named_children:
        if child.type == "element_value_pair":
            args[_text(child.child_by_field_name("key"))] = child.child_by_field_name("value")
        elif child.type != "comment":
            args["value"] = child
    return args


class SourceIndex:
    """Cross-file facts the route pass needs: constants, meta-annotations, types."""

    def __init__(self):
        self.constants = {}  # "Class.FIELD" -> str
        self.constants_by_name = {}  # "FIELD" -> set of str
        self.types = {}  # simple name -> list of type info dicts
        self.mapping_meta = {}  # annotation name -> {"paths", "method_attr", "default_method", "fixed_method"}
        self.controller_meta = set(CONTROLLER_ANNOTATIONS)
        for name, fixed in MAPPING_ANNOTATIONS.items():
            self.mapping_meta[name] = {
                "paths": {"value", "path"},
                "method_attr": "method" if fixed is None else None,
                "default_method": None,
                "fixed_method": fixed,
            }

    def resolve_strings(self, node, owner):
        """Resolve an annotation value to a list of strings, following constants."""
        if node is None:
            return []
        kind = node.type
        if kind == "string_literal":
            parts = []
            for c in node.named_children:
                if c.type == "string_fragment":
                    parts.append(_text(c))
                elif c.type == "escape_sequence":
                    parts.append(_text(c).encode("utf-8").decode("unicode_escape"))
            return ["".join(parts)]
        if kind in ("element_value_array_initializer", "array_initializer"):
            return [s for c in node.named_children for s in self.resolve_strings(c, owner)]
        if kind == "parenthesized_expression":
            return self.resolve_strings(node.named_children[0], owner)
        if kind == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
            left = self.resolve_strings(node.child_by_field_name("left"), owner)
            right = self.resolve_strings(node.child_by_field_name("right"), owner)
            return [a + b for a in left for b in right]
        if kind == "field_access":
            key = f"{_simple_name(_text(node.child_by_field_name('object')))}.{_text(node.child_by_field_name('field'))}"
            return [self.constants[key]] if key in self.constants else []
        if kind == "identifier":
            name = _text(node)
            if f"{owner}.{name}" in self.constants:
                return [self.constants[f"{owner}.{name}"]]
            candidates = self.constants_by_name.get(name, set())
            return [next(iter(candidates))] if len(candidates) == 1 else []
        return []

    def resolve_methods(self, node):
        """Resolve RequestMethod.X (or a list of them) to method names."""
        if node is None:
            return []
        if node.type in ("element_value_array_initializer", "array_initializer"):
            return [m for c in node.named_children for m in self.resolve_methods(c)]
        return [_simple_name(_text(node))]

    def implementations(self, type_name):
        """Concrete types for a declared type: itself if a class, else its implementors."""
        infos = self.types.get(type_name, [])
        classes = [t for t in infos if t["kind"] == "class_declaration"]
        if classes:
            return classes
        return [t for infos in self.types.values() for t in infos if type_name in t["supertypes"]]


def _parse_files(root):
    parser = Parser(JAVA)
    files = []
    for path in sorted(root.rglob("*.java")):
        rel = path.relative_to(root).as_posix()
        if "/test/" in f"/{rel}":
            continue
        files.append((rel, parser.parse(path.read_bytes()).root_node))
    return files


def _type_declarations(node):
    """All type declarations, including nested ones."""
    for child in node.named_children:
        if child.type in TYPE_DECLARATIONS or child.type == "annotation_type_declaration":
            yield child
            body = child.child_by_field_name("body")
            if body is not None:
                yield from _type_declarations(body)


def _index_constants(index, decl, owner):
    is_interface = decl.type == "interface_declaration"
    body = decl.child_by_field_name("body")
    for field in _children(body, "field_declaration", "constant_declaration"):
        mods = " ".join(_text(m) for m in _children(field, "modifiers"))
        if not (is_interface or field.type == "constant_declaration" or ("static" in mods and "final" in mods)):
            continue
        for declarator in _children(field, "variable_declarator"):
            values = index.resolve_strings(declarator.child_by_field_name("value"), owner)
            if len(values) == 1:
                name = _text(declarator.child_by_field_name("name"))
                index.constants[f"{owner}.{name}"] = values[0]
                index.constants_by_name.setdefault(name, set()).add(values[0])


def _index_type(index, decl, rel):
    name = _text(decl.child_by_field_name("name"))
    supertypes = set()
    for clause in _children(decl, "superclass", "super_interfaces", "extends_interfaces"):
        for t in clause.named_children:
            for ident in [t] if t.type != "type_list" else t.named_children:
                supertypes.add(_simple_name(_text(ident)))
    fields = {}
    methods = {}
    body = decl.child_by_field_name("body")
    for member in body.named_children if body is not None else []:
        if member.type == "field_declaration":
            field_type = _simple_name(_text(member.child_by_field_name("type")))
            for declarator in _children(member, "variable_declarator"):
                fields[_text(declarator.child_by_field_name("name"))] = field_type
        elif member.type == "method_declaration":
            start, end = _line_span(member)
            methods.setdefault(_text(member.child_by_field_name("name")), []).append(
                {"file": rel, "line_start": start, "line_end": end, "node": member}
            )
    index.types.setdefault(name, []).append(
        {"name": name, "kind": decl.type, "file": rel, "decl": decl, "supertypes": supertypes, "fields": fields, "methods": methods}
    )


def _index_meta_annotation(index, decl):
    """Register an @interface that carries a Spring controller or mapping annotation."""
    name = _text(decl.child_by_field_name("name"))
    anns = _annotations(decl)
    changed = False
    if any(a in index.controller_meta for a, _ in anns) and name not in index.controller_meta:
        index.controller_meta.add(name)
        changed = True
    parent = next(((a, args) for a, args in anns if a in index.mapping_meta), None)
    if parent is None or name in index.mapping_meta:
        return changed
    parent_meta = index.mapping_meta[parent[0]]
    parent_methods = index.resolve_methods(_annotation_args(parent[1]).get(parent_meta["method_attr"] or ""))
    meta = {
        "paths": set(),
        "method_attr": None,
        "default_method": None,
        "fixed_method": parent_meta["fixed_method"] or (parent_methods[0] if parent_methods else None),
    }
    for element in _children(decl.child_by_field_name("body"), "annotation_type_element_declaration"):
        element_name = _text(element.child_by_field_name("name"))
        alias = next((args for a, args in _annotations(element) if a == "AliasFor"), None)
        if alias is None and element_name not in ("value", "path"):
            continue
        alias_args = _annotation_args(alias)
        target = alias_args.get("attribute")
        target = target and index.resolve_strings(target, name)
        target = target[0] if target else element_name if alias is None else "value"
        if target in ("value", "path"):
            meta["paths"].add(element_name)
        elif target == "method":
            meta["method_attr"] = element_name
            default = element.child_by_field_name("value")
            meta["default_method"] = (index.resolve_methods(default) or [None])[0]
    index.mapping_meta[name] = meta
    return True


def build_index(files):
    index = SourceIndex()
    decls = [(rel, decl) for rel, root in files for decl in _type_declarations(root)]
    # Constants can reference other constants; two passes cover one level of indirection.
    for _ in range(2):
        for rel, decl in decls:
            if decl.type in ("class_declaration", "interface_declaration"):
                _index_constants(index, decl, _text(decl.child_by_field_name("name")))
    for rel, decl in decls:
        if decl.type in TYPE_DECLARATIONS:
            _index_type(index, decl, rel)
    # Meta-annotations can stack; repeat until nothing new is registered.
    annotation_decls = [d for _, d in decls if d.type == "annotation_type_declaration"]
    while any([_index_meta_annotation(index, d) for d in annotation_decls]):
        pass
    return index


def _mapping(index, anns, owner):
    """(paths, methods) merged over all mapping annotations in a list, or None.

    A method may stack annotations, e.g. @GetMapping plus @RequestMapping("/x").
    """
    found = False
    paths, methods = [], []
    for name, args_node in anns:
        meta = index.mapping_meta.get(name)
        if meta is None:
            continue
        found = True
        args = _annotation_args(args_node)
        paths += [p for attr in meta["paths"] for p in index.resolve_strings(args.get(attr), owner)]
        if meta["fixed_method"]:
            methods.append(meta["fixed_method"])
        else:
            explicit = index.resolve_methods(args.get(meta["method_attr"] or ""))
            methods += explicit or ([meta["default_method"]] if meta["default_method"] else [])
    if not found:
        return None
    return list(dict.fromkeys(paths)) or [""], list(dict.fromkeys(methods)) or [ANY_METHOD]


def _join_route(base, path):
    segments = [s for part in (base, path) for s in part.split("/") if s]
    segments = [re.sub(r"\{([^}:]+):[^}]*\}", r"{\1}", s) for s in segments]
    return "/" + "/".join(segments)


def _walk(node, kind):
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == kind:
            yield current
        stack.extend(current.named_children)


def _params(index, method, owner):
    params = []
    map_params = set()
    for formal in _children(method.child_by_field_name("parameters"), "formal_parameter"):
        param_name = _text(formal.child_by_field_name("name"))
        param_type = _simple_name(_text(formal.child_by_field_name("type")))
        for ann, args_node in _annotations(formal):
            if ann not in PARAM_ANNOTATIONS:
                continue
            if param_type in ("Map", "MultiValueMap", "HashMap"):
                map_params.add(param_name)
                continue
            args = _annotation_args(args_node)
            names = index.resolve_strings(args.get("name") or args.get("value"), owner)
            params.append({"name": names[0] if names else param_name, "source": PARAM_ANNOTATIONS[ann]})
    body = method.child_by_field_name("body")
    for call in _walk(body, "method_invocation") if body is not None else []:
        call_name = _text(call.child_by_field_name("name"))
        obj = call.child_by_field_name("object")
        is_map_get = obj is not None and _text(obj) in map_params and call_name in MAP_PARAM_GETTERS
        if is_map_get or call_name == "getParameter":
            arguments = call.child_by_field_name("arguments").named_children
            for name in index.resolve_strings(arguments[0], owner) if arguments else []:
                params.append({"name": name, "source": "query"})
    unique = {(p["name"], p["source"]): p for p in params}
    return list(unique.values())


def _direct_calls(index, method, owner_info, same_class_only):
    """(target type info, call site) for each project method a method body calls."""
    body = method.child_by_field_name("body")
    for call in _walk(body, "method_invocation") if body is not None else []:
        call_name = _text(call.child_by_field_name("name"))
        obj = call.child_by_field_name("object")
        if obj is None or obj.type == "this":
            targets = [owner_info]
        elif same_class_only:
            continue
        else:
            receiver = _text(obj.child_by_field_name("field")) if obj.type == "field_access" else _text(obj)
            declared = owner_info["fields"].get(receiver) or (receiver if receiver in index.types else None)
            targets = index.implementations(declared) if declared else []
        for target in targets:
            for site in target["methods"].get(call_name, []):
                yield target, call_name, site


def _calls(index, method, owner_info):
    """Call edges from a handler: one hop across classes, plus same-class helpers.

    From the handler, and from each method one hop away, same-class calls
    (private helpers) are followed transitively. Calls into a further class
    are not followed.
    """
    edges = {}
    queue = [(owner_info, method, False)]
    seen = {(owner_info["name"], method.start_point[0])}
    while queue:
        info, node, same_class_only = queue.pop()
        for target, call_name, site in _direct_calls(index, node, info, same_class_only):
            key = (target["name"], site["file"], site["line_start"])
            if key in edges or (target["name"], site["node"].start_point[0]) in seen:
                continue
            edges[key] = {"class": target["name"], "method": call_name,
                          **{k: v for k, v in site.items() if k != "node"}}
            seen.add((target["name"], site["node"].start_point[0]))
            # Crossing into another class uses up the one hop; same-class helpers do not.
            crossed = same_class_only or target["name"] != owner_info["name"]
            queue.append((target, site["node"], crossed))
    return list(edges.values())


def build_route_map(source_root):
    """Route map for every Spring handler under source_root."""
    root = Path(source_root)
    index = build_index(_parse_files(root))
    entries = []
    for infos in index.types.values():
        for info in infos:
            decl = info["decl"]
            class_anns = _annotations(decl)
            if not any(a in index.controller_meta for a, _ in class_anns):
                continue
            base = _mapping(index, class_anns, info["name"])
            base_paths = base[0] if base else [""]
            body = decl.child_by_field_name("body")
            for method in _children(body, "method_declaration"):
                mapping = _mapping(index, _annotations(method), info["name"])
                if mapping is None:
                    continue
                paths, http_methods = mapping
                start, end = _line_span(method)
                params = _params(index, method, info["name"])
                calls = _calls(index, method, info)
                for base_path in base_paths:
                    for path in paths:
                        for http_method in http_methods:
                            entries.append({
                                "route": _join_route(base_path, path),
                                "method": http_method,
                                "file": info["file"],
                                "func": f"{info['name']}.{_text(method.child_by_field_name('name'))}",
                                "line_start": start,
                                "line_end": end,
                                "params": params,
                                "calls": calls,
                            })
    return sorted(entries, key=lambda e: (e["route"], e["method"]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m producers.sast.spring_routes <target-source-root>")
    json.dump(build_route_map(sys.argv[1]), sys.stdout, indent=2)
