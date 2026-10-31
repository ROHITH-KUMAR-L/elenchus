"""Sink finder, arg_shape, backward walk and hypotheses on small Java sources.

The decoy tests are the static layer of the decoy plan. Each decoy has a
vulnerable twin, so a rule that clears too much also fails.
"""

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from common.record import ScanTarget
from producers.hypotheses.builder import build_directed, build_sweep, skipped_by_type
from producers.sast.code_index import build_code_index
from producers.sast.sink_finder import CATALOGUE_DIR, load_catalogue
from producers.sast.static_stage import run_static


def write(root, rel, source):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source))


def findings(root):
    index = build_code_index(root)
    return run_static(ScanTarget(str(root), "http://localhost/", "r", "spring-mvc"), index), index


def one_method(tmp_path, body, fields="private JdbcTemplate jdbc;", params="String id"):
    write(tmp_path, "src/C.java", f"""
        @RestController
        public class C {{
            private static final String FIXED = "select 1";
            {fields}
            @GetMapping("/x")
            public Object x({params}) {{
                {dedent(body).strip()}
            }}
        }}
        """)
    return findings(tmp_path)[0]


@pytest.mark.parametrize(
    "body",
    [
        'return jdbc.query("select * from t where id=?", mapper, id);',
        'return jdbc.query("select * " + "from t", mapper);',
        'String sql = "select * from t where id=?"; return jdbc.query(sql, mapper, id);',
        'String a = "select *"; String b = a + " from t"; return jdbc.query(b, mapper);',
        "return jdbc.query(FIXED, mapper);",
        "return jdbc.query(C.FIXED, mapper);",
    ],
    ids=["literal", "literal-concat", "local-once", "local-chain", "constant", "qualified-constant"],
)
def test_decoys_are_constant(tmp_path, body):
    [finding] = one_method(tmp_path, body)
    assert finding.arg_shape == "constant"


@pytest.mark.parametrize(
    "body",
    [
        'return jdbc.query("select * from t where id=" + id, mapper);',
        'String sql = "select * from t where id=" + id; return jdbc.query(sql, mapper);',
        'String sql = "select 1"; sql = sql + id; return jdbc.query(sql, mapper);',
        'String sql = "select 1"; sql += id; return jdbc.query(sql, mapper);',
        "return jdbc.query(id, mapper);",
        "return jdbc.query(build(id), mapper);",
        'return jdbc.query(String.format("select %s", id), mapper);',
        'if (a) { String s = "x"; return jdbc.query(s, m); } else { String s = id; return jdbc.query(s, m); }',
    ],
    ids=[
        "concat", "local-concat", "reassigned", "appended", "param", "call", "format", "shadowed",
    ],
)
def test_vulnerable_twins_are_dynamic(tmp_path, body):
    found = one_method(tmp_path, body)
    assert found
    assert "dynamic" in {f.arg_shape for f in found}


def test_a_constant_method_param_with_a_literal_name_is_dynamic(tmp_path):
    [finding] = one_method(tmp_path, "return jdbc.query(FIXED2, mapper);", params="String FIXED2")
    assert finding.arg_shape == "dynamic"


def test_sanitiser_gives_sanitised_only_when_catalogued(tmp_path):
    catalogue = tmp_path / "catalogue"
    catalogue.mkdir()
    (catalogue / "x.yaml").write_text(
        yaml.safe_dump(
            {
                "cwe": 79, "type": "XSS", "severity": "medium",
                "sanitisers": [{"receiver": "HtmlUtils", "method": "htmlEscape"}],
                "entries": [
                    {"id": "w", "api": "Writer", "kind": "call", "receiver_types": ["Writer"],
                     "methods": ["write"], "sink_arg": 0},
                ],
            }
        )
    )
    source = tmp_path / "src"
    write(source, "C.java", """
        public class C {
            private Writer w;
            public void a(String v) { w.write(HtmlUtils.htmlEscape(v)); }
            public void b(String v) { w.write(Other.htmlEscape(v)); }
        }
        """)
    from producers.sast.sink_finder import find_sinks
    from producers.sast.spring_routes import _parse_files, build_index

    sites = find_sinks(build_index(_parse_files(source)), load_catalogue(catalogue))
    assert {s.sink_id.enclosing_method: s.arg_shape for s in sites} == {
        "C.a": "sanitised",
        "C.b": "dynamic",
    }


def test_line_is_the_argument_line_and_sink_id_is_the_call(tmp_path):
    [finding] = one_method(
        tmp_path,
        """
        return jdbc.query(
                "select * from t where id=" + id,
                mapper);
        """,
    )
    assert finding.line == finding.sink_id.start_line + 1


def test_match_requires_the_receiver_type_not_just_the_name(tmp_path):
    assert one_method(tmp_path, "return other.query(id);", fields="private Other other;") == []
    assert one_method(tmp_path, "return unknown().query(id);") == []


def test_lambda_receiver_resolves_only_through_a_catalogued_outer_call(tmp_path):
    [finding] = one_method(
        tmp_path,
        'return jdbc.query((conn) -> conn.prepareStatement("select " + id), setter, mapper);',
    )
    assert finding.detail("catalogue_entry") == "jdbc-connection"
    assert finding.arg_shape == "dynamic"
    assert finding.match_mode == "strict"
    assert one_method(tmp_path, 'return run((conn) -> conn.prepareStatement("select " + id));') == []


def test_non_text_arguments_are_not_sinks(tmp_path):
    fields = "private EntityManager em;"
    body = "CriteriaQuery<Car> cq = build(); return em.createQuery(cq);"
    assert one_method(tmp_path, body, fields=fields) == []
    assert one_method(tmp_path, "return em.createQuery(id);", fields=fields) != []


def test_subclass_of_a_catalogued_type_matches(tmp_path):
    write(tmp_path, "src/Mine.java", "public class Mine extends JdbcTemplate {}")
    [finding] = one_method(tmp_path, "return mine.query(id, mapper);", fields="private Mine mine;")
    assert finding.arg_shape == "dynamic"


def test_wrapper_in_source_is_found_through_the_sink_inside_it(tmp_path):
    write(tmp_path, "src/Db.java", """
        public class Db {
            private JdbcTemplate jdbc;
            public Object run(String sql) { return jdbc.query(sql, null); }
        }
        """)
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            private Db db;
            @GetMapping("/x")
            public Object x(@RequestParam String id) { return db.run("select " + id); }
            @GetMapping("/y")
            public Object y(@RequestParam String z) { return db.run("select " + z); }
        }
        """)
    [finding], _ = findings(tmp_path)
    assert finding.file == "src/Db.java"
    assert finding.route is None  # Two routes reach it.
    assert {(p.route, p.hops) for p in finding.entry_paths} == {("/x", 1), ("/y", 1)}
    assert finding.candidate_params == ("id", "z")
    assert finding.param is None


def test_backward_walk_gives_the_chain_handler_first(tmp_path):
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            private Svc svc;
            @GetMapping("/x")
            public Object x(@RequestParam String id) { return svc.run(id); }
        }
        """)
    write(tmp_path, "src/Svc.java", """
        public class Svc {
            private JdbcTemplate jdbc;
            public Object run(String id) { return load(id); }
            private Object load(String id) { return jdbc.query(id, null); }
        }
        """)
    [finding], _ = findings(tmp_path)
    [path] = finding.entry_paths
    assert finding.route == "/x"
    assert path.hops == 2
    assert [hop.method for hop in path.call_chain] == ["C.x", "Svc.run", "Svc.load"]


def test_no_http_path_reason_codes(tmp_path):
    write(tmp_path, "src/A.java", """
        public class A {
            private JdbcTemplate jdbc;
            public Object orphan(String id) { return jdbc.query(id, null); }
            public Object hidden(String id) { return jdbc.query(id, null); }
            public void caller() { factory().hidden("x"); }
        }
        """)
    found, _ = findings(tmp_path)
    reasons = {f.sink_id.enclosing_method: (f.status, f.unlinked_reason) for f in found}
    assert reasons == {
        "A.orphan": ("no_http_path", "no_callers"),
        "A.hidden": ("no_http_path", "walk_unresolved"),
    }
    assert all(f.entry_paths is None for f in found)


def test_hypotheses_directed_only_from_dynamic_reachable_sinks(tmp_path):
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            private JdbcTemplate jdbc;
            @GetMapping("/bad")
            public Object bad(@RequestParam String id, @RequestParam String sort) {
                return jdbc.query("select " + id, null);
            }
            @GetMapping("/safe")
            public Object safe(@RequestParam String id) {
                return jdbc.query("select ?", null, id);
            }
            public Object orphan(String id) { return jdbc.query(id, null); }
        }
        """)
    found, index = findings(tmp_path)
    [directed] = build_directed(found, index)
    assert (directed.kind, directed.route) == ("directed", "/bad")
    assert directed.candidate_params == ("id", "sort")
    assert directed.sink_id is not None


def test_sweep_skips_params_that_cannot_carry_a_payload_and_lists_them(tmp_path):
    write(tmp_path, "src/Color.java", "public enum Color { RED }")
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            @GetMapping("/x")
            public Object x(@RequestParam String name, @RequestParam Long id, @RequestParam UUID u,
                            @RequestParam Color color, @RequestHeader("X-A") String header) {
                return "x";
            }
        }
        """)
    index = build_code_index(tmp_path)
    sweep = build_sweep(index, (89, 79))
    assert {(h.candidate_params, h.cwe) for h in sweep} == {(("name",), 89), (("name",), 79)}
    assert len({h.hypothesis_id for h in sweep}) == 2
    assert {param for _, _, param in skipped_by_type(index)} == {"id", "u", "color"}


def test_every_catalogue_entry_names_its_api():
    for path in Path(CATALOGUE_DIR).glob("*.yaml"):
        for entry in yaml.safe_load(path.read_text())["entries"]:
            assert entry["api"], entry["id"]
    assert load_catalogue().entries


def test_catalogue_without_an_api_is_rejected(tmp_path):
    (tmp_path / "x.yaml").write_text(
        yaml.safe_dump(
            {"cwe": 1, "type": "t", "severity": "low",
             "entries": [{"id": "e", "kind": "call", "receiver_types": ["A"], "methods": ["b"], "sink_arg": 0}]}
        )
    )
    with pytest.raises(ValueError, match="must name its source API"):
        load_catalogue(tmp_path)
