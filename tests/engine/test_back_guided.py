"""Back-guided relaxed search: find a candidate sink for a Runtime-only hit."""

from common.pipeline import CallGraphEdge, CodeIndex
from common.record import RouteEntry
from engine.correlate.back_guided import apply_back_guided, candidate_sinks
from engine.correlate.models import Issue
from producers.sast.sink_finder import load_catalogue

CATALOGUE = load_catalogue()
ROUTES = (RouteEntry("/q", "GET", "C.java", "C.get", 10, 20, (), ()),)
# C.get -> helper (resolved), helper -> executeQuery (unresolved receiver): a
# relaxed SQL sink one unresolved hop from the route handler.
GRAPH = (
    CallGraphEdge("C.get", "C.helper", "C.java", 12, True, callee_file="C.java"),
    CallGraphEdge("C.helper", "executeQuery", "C.java", 15, False, col=4),
)
INDEX = CodeIndex(routes=ROUTES, call_graph=GRAPH)


def runtime_only_issue():
    return Issue(
        issue_key="k", label="Runtime-only", cwe=89, type="SQL Injection",
        severity="high", risk_score=50.0, route="/q", method="GET", param="id",
    )


def test_relaxed_walk_finds_the_unresolved_sql_sink():
    found = candidate_sinks(INDEX, CATALOGUE, "/q", "GET", 89, max_hops=3)
    assert len(found) == 1
    sink, hops = found[0]
    assert sink.start_line == 15
    assert hops == 1


def test_one_candidate_confirms_as_a_unique_back_guided_link():
    [issue] = apply_back_guided([runtime_only_issue()], INDEX, CATALOGUE, {})
    assert issue.link_origin == "back_guided"
    assert issue.link_status == "unique"
    # start_confidence 0.55 - hop_penalty 0.1 = 0.45 >= confirm 0.4
    assert issue.label == "Confirmed"
    assert issue.sink is not None and issue.sink.start_line == 15


def test_no_candidate_leaves_the_issue_untouched():
    empty = CodeIndex(routes=ROUTES, call_graph=())
    [issue] = apply_back_guided([runtime_only_issue()], empty, CATALOGUE, {})
    assert issue.label == "Runtime-only"
    assert issue.link_origin is None
