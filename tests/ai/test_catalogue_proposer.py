"""AI catalogue-gap proposer: advisory, symbol-checked, twin-gated.

The proposer never changes the live catalogue. A proposal survives only when every
symbol it names resolves in the parsed index; it is accepted only when a decoy twin
shows adding it flags the vulnerable twin and no safe twin. With no twin it is
tagged needs_human_review and never applied.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

from ai.catalogue_proposer import (
    TASK,
    Proposal,
    Twin,
    augment,
    propose,
    wrapper_candidates,
    write_proposals,
)
from ai.client import AiClient
from common.config import load_config
from common.pipeline import CallGraphEdge, CodeIndex
from producers.sast.sink_finder import find_sinks, load_catalogue
from producers.sast.spring_routes import _parse_files, build_index

ENV = {"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "http://127.0.0.1:1/v1", "OPENAI_MODEL": "m"}

_DAO = """
    class Dao {
        private JdbcTemplate jdbc;
        public Object runQuery(String sql) { return jdbc.query(sql, mapper); }
    }
"""


def write(root: Path, rel: str, source: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source))


def source_index(root: Path):
    return build_index(_parse_files(root))


def wrapper_sink_twin(tmp_path: Path) -> Twin:
    """A Dao.runQuery wrapper: the vulnerable twin calls it with a request param,
    the safe twin with a constant."""
    vuln = tmp_path / "vuln"
    safe = tmp_path / "safe"
    write(vuln, "src/V.java", f"""
        @RestController
        public class V {{
            private Dao dao;
            @GetMapping("/v")
            public Object v(String id) {{ return dao.runQuery(id); }}
        }}
        {_DAO}
    """)
    write(safe, "src/S.java", f"""
        @RestController
        public class S {{
            private Dao dao;
            @GetMapping("/s")
            public Object s() {{ return dao.runQuery("select 1"); }}
        }}
        {_DAO}
    """)
    return Twin(cwe=89, vulnerable_root=vuln, safe_root=safe)


def sink_proposal() -> Proposal:
    return Proposal(
        kind="sink", cwe=89, receiver_type="Dao", method="runQuery", sink_arg=0,
        api_anchor="org.springframework.jdbc.core.JdbcOperations",
        evidence_symbol="Dao.java:4", confidence=0.8, rationale="forwards to jdbc.query",
    )


def client(transport, **overrides):
    values = {"ai.enabled": True, f"ai.tasks.{TASK}.enabled": True}
    values.update(overrides)
    return AiClient(load_config(overrides=values, environ={}), environ=ENV, transport=transport)


def test_wrapper_candidates_keeps_only_unresolved_sites():
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
            CallGraphEdge(caller="C.x", callee="query", file="C.java", line=9, resolved=True),
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
        ),
    )
    candidates = wrapper_candidates(index)
    assert [c["method"] for c in candidates] == ["runQuery"]


def test_augment_does_not_touch_the_live_catalogue():
    base = load_catalogue()
    augmented = augment(base, [sink_proposal()])
    assert len(augmented.entries) == len(base.entries) + 1
    assert load_catalogue().entries == base.entries  # reloading shows no change on disk


def test_valid_sink_proposal_is_accepted_when_the_twin_passes(tmp_path):
    twin = wrapper_sink_twin(tmp_path)
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
        ),
    )
    reviewed = propose(
        index, source_index(twin.vulnerable_root), load_catalogue(),
        client(lambda m, msgs: json.dumps({"proposals": [sink_proposal().to_dict()]})),
        twins=[twin],
    )
    assert len(reviewed) == 1
    assert reviewed[0].status == "accepted"


def test_proposal_naming_an_unreal_symbol_is_rejected(tmp_path):
    twin = wrapper_sink_twin(tmp_path)
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="ghost", file="C.java", line=9, resolved=False),
        ),
    )
    ghost = sink_proposal().to_dict() | {"receiver_type": "Nowhere", "method": "ghost"}
    reviewed = propose(
        index, source_index(twin.vulnerable_root), load_catalogue(),
        client(lambda m, msgs: json.dumps({"proposals": [ghost]})),
        twins=[twin],
    )
    assert reviewed[0].status == "rejected:symbol_unreal"


def test_a_real_symbol_with_no_twin_needs_human_review(tmp_path):
    twin = wrapper_sink_twin(tmp_path)
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
        ),
    )
    reviewed = propose(
        index, source_index(twin.vulnerable_root), load_catalogue(),
        client(lambda m, msgs: json.dumps({"proposals": [sink_proposal().to_dict()]})),
        twins=[],  # no twin available
    )
    assert reviewed[0].status == "needs_human_review"


def test_a_proposal_that_adds_no_detection_in_the_vulnerable_twin_is_rejected(tmp_path):
    # Dao.runQuery is declared but never called in the twin trees, so promoting it to
    # a sink flags nothing: the twin check fails.
    vuln = tmp_path / "vuln"
    safe = tmp_path / "safe"
    write(vuln, "src/V.java", f"""
        @RestController
        public class V {{
            private JdbcTemplate jdbc;
            @GetMapping("/v")
            public Object v(String id) {{ return jdbc.query(id, mapper); }}
        }}
        {_DAO}
    """)
    write(safe, "src/S.java", f"""
        @RestController
        public class S {{
            @GetMapping("/s")
            public Object s() {{ return 1; }}
        }}
        {_DAO}
    """)
    twin = Twin(cwe=89, vulnerable_root=vuln, safe_root=safe)
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
        ),
    )
    reviewed = propose(
        index, source_index(vuln), load_catalogue(),
        client(lambda m, msgs: json.dumps({"proposals": [sink_proposal().to_dict()]})),
        twins=[twin],
    )
    assert reviewed[0].status == "rejected:twin_failed"


def test_accepted_sink_actually_surfaces_the_wrapped_low_level_sink(tmp_path):
    twin = wrapper_sink_twin(tmp_path)
    base = load_catalogue()
    augmented = augment(base, [sink_proposal()])
    index = source_index(twin.vulnerable_root)
    base_methods = {s.sink_id.enclosing_method for s in find_sinks(index, base)}
    aug_methods = {s.sink_id.enclosing_method for s in find_sinks(index, augmented)}
    assert "V.v" in aug_methods - base_methods  # the caller is now a sink site


def test_propose_is_a_no_op_when_the_task_is_off(tmp_path):
    twin = wrapper_sink_twin(tmp_path)
    index = CodeIndex(
        routes=(),
        call_graph=(
            CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
        ),
    )
    calls = []

    def transport(model, messages):
        calls.append(messages)
        return json.dumps({"proposals": []})

    off = AiClient(load_config(environ={}), environ=ENV, transport=transport)
    assert propose(index, source_index(twin.vulnerable_root), load_catalogue(), off, [twin]) == []
    assert calls == []


def test_write_proposals_groups_by_status(tmp_path):
    reviewed = propose(
        CodeIndex(
            routes=(),
            call_graph=(
                CallGraphEdge(caller="C.x", callee="runQuery", file="C.java", line=9, resolved=False),
            ),
        ),
        source_index(wrapper_sink_twin(tmp_path).vulnerable_root),
        load_catalogue(),
        client(lambda m, msgs: json.dumps({"proposals": [sink_proposal().to_dict()]})),
        twins=[],
    )
    path = tmp_path / "catalogue_proposals.json"
    write_proposals(reviewed, path)
    payload = json.loads(path.read_text())
    assert payload["task"] == TASK
    assert len(payload["needs_human_review"]) == 1
    assert payload["accepted"] == [] and payload["rejected"] == []
