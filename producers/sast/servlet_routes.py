"""Stage 1-2 adapter: Jakarta/Java EE Servlet route detection (B-7).

A second framework behind the same adapter boundary as Spring MVC. A servlet is
a class carrying `@WebServlet`, whose URL pattern(s) are the route and whose
`doGet`/`doPost`/... methods are the handlers. Client parameters come from
`request.getParameter`/`getHeader` on the `HttpServletRequest` formal, which the
shared `_params` already reads.

The generic parser (`build_index`), the call graph, the sink catalogue and the
secrets pass are framework-agnostic and are reused unchanged. Only route
detection is servlet-specific and lives here.
"""

from __future__ import annotations

from pathlib import Path

from producers.sast.spring_routes import (
    _annotation_args,
    _annotations,
    _calls,
    _is_abstract,
    _line_span,
    _params,
    _parse_files,  # the parser is framework-agnostic; shared with Spring
    _text,
    build_index,
)

# Servlet service methods -> the HTTP method they answer. `service` dispatches
# every method, so it maps to ANY.
_SERVICE_METHODS = {
    "doGet": "GET",
    "doPost": "POST",
    "doPut": "PUT",
    "doDelete": "DELETE",
    "doHead": "HEAD",
    "doOptions": "OPTIONS",
    "doTrace": "TRACE",
    "service": "ANY",
}


def _servlet_urls(index, info) -> list[str]:
    """URL pattern(s) from a class's @WebServlet, or [] if it has none."""
    for name, args in _annotations(info["decl"]):
        if name != "WebServlet":
            continue
        attributes = _annotation_args(args)
        node = attributes.get("urlPatterns") or attributes.get("value")
        urls = index.resolve_strings(node, info["name"]) if node is not None else []
        return [u for u in urls if u]
    return []


def _handler_methods(decl):
    """(method_node, http_method) for each servlet service method of a class."""
    body = decl.child_by_field_name("body")
    for member in body.named_children if body is not None else []:
        if member.type != "method_declaration":
            continue
        name = _text(member.child_by_field_name("name"))
        http_method = _SERVICE_METHODS.get(name)
        if http_method is not None:
            yield member, name, http_method


def _build_entries(index):
    """Route entries for every servlet under the index, same shape as Spring's."""
    entries = []
    for infos in index.types.values():
        for info in infos:
            decl = info["decl"]
            if info["kind"] != "class_declaration" or _is_abstract(decl):
                continue
            urls = _servlet_urls(index, info)
            if not urls:
                continue
            for method, method_name, http_method in _handler_methods(decl):
                start, end = _line_span(method)
                params, status = _params(index, method, info["name"], None, http_method)
                calls = _calls(index, method, info)
                for url in urls:
                    entries.append(
                        {
                            "route": url,
                            "method": http_method,
                            "file": info["file"],
                            "func": f"{info['name']}.{method_name}",
                            "line_start": start,
                            "line_end": end,
                            "params": params,
                            "params_status": status,
                            "route_origin": "source",
                            "calls": calls,
                        }
                    )
    return sorted(entries, key=lambda e: (e["route"], e["method"]))


def build_route_map(source_root):
    """Route map for every servlet under source_root."""
    return _build_entries(build_index(_parse_files(Path(source_root))))
