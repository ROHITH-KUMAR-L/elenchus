"""Stage 1 tests on small synthetic Java sources."""

from textwrap import dedent

from producers.sast.code_index import build_code_index, summary


def write(root, rel, source):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source))


def route(index, path, method="GET"):
    return next(r for r in index.routes if r.route == path and r.method == method)


def params(entry):
    return {p.name: (p.source, p.java_type, p.body_format) for p in entry.params}


def edge(index, caller, suffix):
    return [e for e in index.call_graph if e.caller == caller and e.callee.endswith(suffix)]


def test_param_types_and_locations(tmp_path):
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            @GetMapping("/a/{id}")
            public String a(@PathVariable Long id, @RequestParam("q") String query,
                            @RequestHeader("X-T") String token, @CookieValue String sid,
                            String implicit, HttpServletResponse response) {
                return "x";
            }
        }
        """)
    entry = route(build_code_index(tmp_path), "/a/{id}")
    assert params(entry) == {
        "id": ("path", "Long", None),
        "q": ("query", "String", None),
        "X-T": ("header", "String", None),
        "sid": ("cookie", "String", None),
        "implicit": ("query", "String", None),
    }
    assert entry.params_status == "complete"
    assert entry.route_origin == "source"


def test_request_body_dto_fields_nested_and_renamed(tmp_path):
    write(tmp_path, "src/Dto.java", """
        public class Dto {
            private static final String IGNORED = "x";
            @JsonProperty("user_name") private String name;
            private int age;
            private Address address;
            @JsonIgnore private String hidden;
        }
        """)
    write(tmp_path, "src/Address.java", "public record Address(String city, String zip) {}")
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            @PostMapping("/b")
            public String b(@RequestBody Dto dto) { return "x"; }
        }
        """)
    entry = route(build_code_index(tmp_path), "/b", "POST")
    assert params(entry) == {
        "user_name": ("body", "String", "json"),
        "age": ("body", "int", "json"),
        "address.city": ("body", "String", "json"),
        "address.zip": ("body", "String", "json"),
    }
    assert entry.params_status == "complete"


def test_model_attribute_binds_query_on_get_and_form_on_post(tmp_path):
    write(tmp_path, "src/Form.java", "public class Form { private String name; }")
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            @GetMapping("/g")
            public String g(Form form) { return "x"; }
            @PostMapping("/p")
            public String p(@ModelAttribute Form form) { return "x"; }
        }
        """)
    index = build_code_index(tmp_path)
    assert params(route(index, "/g")) == {"name": ("query", "String", None)}
    assert params(route(index, "/p", "POST")) == {"name": ("body", "String", "form")}


def test_params_status_is_honest_about_what_it_cannot_read(tmp_path):
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            @GetMapping("/known")
            public String known(@RequestParam Map<String, String> q) { return q.get("id"); }

            @GetMapping("/computed")
            public String computed(@RequestParam Map<String, String> q) { return q.get(key()); }

            @GetMapping("/iterated")
            public String iterated(@RequestParam Map<String, String> q) {
                for (Map.Entry<String, String> e : q.entrySet()) { use(e); }
                return "x";
            }

            @GetMapping("/forwarded")
            public String forwarded(@RequestParam Map<String, String> q) { return svc.run(q); }

            @GetMapping("/raw")
            public String raw(@RequestParam String a, RequestEntity<String> entity) { return "x"; }

            @PostMapping("/external")
            public String external(@RequestBody ExternalDto dto) { return "x"; }

            @PostMapping("/rawbody")
            public String rawBody(@RequestBody String body) { return "x"; }

            @GetMapping("/servlet")
            public String servlet(HttpServletRequest request) {
                return request.getParameter("a") + request.getHeader("X-B");
            }

            @GetMapping("/opaque")
            public String opaque(HttpServletRequest request) { return request.getQueryString(); }
        }
        """)
    index = build_code_index(tmp_path)
    status = {r.route: r.params_status for r in index.routes}
    assert status == {
        "/known": "complete",
        "/computed": "unknown",
        "/iterated": "unknown",
        "/forwarded": "unknown",
        "/raw": "partial",
        "/external": "unknown",
        "/rawbody": "unknown",
        "/servlet": "complete",
        "/opaque": "unknown",
    }
    assert params(route(index, "/known")) == {"id": ("query", "String", None)}
    assert params(route(index, "/servlet")) == {
        "a": ("query", "String", None),
        "X-B": ("header", "String", None),
    }


def test_inherited_mappings_from_interface_and_abstract_base(tmp_path):
    write(tmp_path, "src/Api.java", """
        @RequestMapping("/api")
        public interface Api {
            @GetMapping("/iface")
            String iface(@RequestParam("q") String q);
        }
        """)
    write(tmp_path, "src/Impl.java", """
        @RestController
        public class Impl implements Api {
            public String iface(String q) { return q; }
        }
        """)
    write(tmp_path, "src/Base.java", """
        public abstract class Base {
            @GetMapping("/inherited")
            public String inherited() { return "x"; }
        }
        """)
    write(tmp_path, "src/Child.java", """
        @RestController
        @RequestMapping("/child")
        public class Child extends Base {}
        """)
    index = build_code_index(tmp_path)
    assert {(r.route, r.func) for r in index.routes} == {
        ("/api/iface", "Impl.iface"),
        ("/child/inherited", "Base.inherited"),
    }
    assert params(route(index, "/api/iface")) == {"q": ("query", "String", None)}


def test_call_graph_walks_several_hops_through_an_interface(tmp_path):
    write(tmp_path, "src/C.java", """
        @RestController
        public class C {
            private final Svc svc;
            @GetMapping("/x")
            public String x() { return svc.run(); }
        }
        """)
    write(tmp_path, "src/Svc.java", "public interface Svc { String run(); }")
    write(tmp_path, "src/SvcImpl.java", """
        public class SvcImpl implements Svc {
            private final Repo repo;
            public String run() { return repo.load(); }
        }
        """)
    write(tmp_path, "src/Repo.java", """
        public class Repo {
            private JdbcTemplate jdbc;
            public String load() { return helper(); }
            private String helper() { return jdbc.query("q"); }
        }
        """)
    index = build_code_index(tmp_path)
    [first] = edge(index, "C.x", ".run")
    assert (first.callee, first.callee_file, first.resolved) == ("SvcImpl.run", "src/SvcImpl.java", True)
    [second] = edge(index, "SvcImpl.run", ".load")
    assert second.callee == "Repo.load"
    [third] = edge(index, "Repo.load", ".helper")
    assert third.callee == "Repo.helper"
    [sink] = edge(index, "Repo.helper", ".query")
    assert (sink.callee, sink.receiver_type, sink.resolved, sink.callee_file) == (
        "JdbcTemplate.query", "JdbcTemplate", True, None,
    )


def test_receivers_from_locals_var_casts_chains_and_inherited_fields(tmp_path):
    write(tmp_path, "src/Base.java", "public class Base { protected Stmt inherited; }")
    write(tmp_path, "src/Maker.java", "public class Maker { public Stmt make() { return null; } }")
    write(tmp_path, "src/C.java", """
        public class C extends Base {
            private Maker maker;
            public void m(Stmt param) {
                Stmt local = open();
                var inferred = new Stmt();
                local.a();
                param.b();
                inferred.c();
                inherited.d();
                ((Stmt) thing).e();
                maker.make().f();
                Files.readAllBytes(path);
                new ProcessBuilder(cmd);
            }
        }
        """)
    index = build_code_index(tmp_path)
    for name in ("a", "b", "c", "d", "e", "f"):
        [found] = edge(index, "C.m", f".{name}")
        assert (found.receiver_type, found.resolved) == ("Stmt", True), name
    [static] = edge(index, "C.m", ".readAllBytes")
    assert static.callee == "Files.readAllBytes"
    [created] = edge(index, "C.m", "ProcessBuilder.<init>")
    assert created.resolved


def test_unresolved_calls_are_flagged_and_kept(tmp_path):
    write(tmp_path, "src/C.java", """
        public class C {
            public void m() {
                run((conn) -> conn.prepareStatement("q"));
                external().chained().execute("q");
            }
        }
        """)
    index = build_code_index(tmp_path)
    [lambda_call] = edge(index, "C.m", ".prepareStatement")
    assert not lambda_call.resolved
    assert lambda_call.callee == "conn.prepareStatement"
    assert lambda_call.receiver_type is None
    [chained] = edge(index, "C.m", ".execute")
    assert not chained.resolved
    assert summary(index)["edges_unresolved"] >= 2


def test_a_name_with_two_types_in_one_method_does_not_guess(tmp_path):
    write(tmp_path, "src/C.java", """
        public class C {
            public void m() {
                if (a) { Stmt x = open(); x.go(); }
                else { Other x = open(); x.go(); }
            }
        }
        """)
    edges = edge(build_code_index(tmp_path), "C.m", ".go")
    assert len(edges) == 2
    assert not any(e.resolved for e in edges)


def test_test_sources_stay_out_of_the_index(tmp_path):
    write(tmp_path, "src/test/java/T.java", """
        @RestController
        public class T {
            @GetMapping("/t")
            public String t() { return run(); }
        }
        """)
    index = build_code_index(tmp_path)
    assert index.routes == ()
    assert index.call_graph == ()
