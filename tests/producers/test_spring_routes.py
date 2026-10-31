"""Route-map parser tests on small synthetic Spring sources.

Run from the repo root: python -m pytest tests/producers
"""

from textwrap import dedent

from producers.sast.spring_routes import build_route_map


def write(root, rel, source):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source))


def routes(tmp_path):
    return {(e["route"], e["method"]): e for e in build_route_map(tmp_path)}


def test_standard_annotations_base_path_and_params(tmp_path):
    write(tmp_path, "src/main/java/shop/OrderController.java", """
        @RestController
        @RequestMapping("/api/orders")
        public class OrderController {
            @GetMapping("/{id:\\\\d+}")
            public String get(@PathVariable("id") String orderId, @RequestParam String sort) {
                return "x";
            }

            @PostMapping
            public String create() { return "y"; }
        }
        """)
    found = routes(tmp_path)
    assert set(found) == {("/api/orders/{id}", "GET"), ("/api/orders", "POST")}
    get = found[("/api/orders/{id}", "GET")]
    assert get["func"] == "OrderController.get"
    assert get["file"] == "src/main/java/shop/OrderController.java"
    assert {(p["name"], p["source"]) for p in get["params"]} == {("id", "path"), ("sort", "query")}


def test_escape_sequences_kept_in_paths(tmp_path):
    write(tmp_path, "src/main/java/A.java", """
        @RestController
        public class A {
            @GetMapping("/files/a\\\\b")
            public String f() { return ""; }
        }
        """)
    assert set(routes(tmp_path)) == {("/files/a\\b", "GET")}


def test_request_mapping_method_attribute(tmp_path):
    write(tmp_path, "src/main/java/A.java", """
        @Controller
        public class A {
            @RequestMapping(value = {"/a", "/b"}, method = {RequestMethod.GET, RequestMethod.POST})
            public String both() { return ""; }

            @RequestMapping("/any")
            public String any() { return ""; }
        }
        """)
    assert set(routes(tmp_path)) == {
        ("/a", "GET"), ("/a", "POST"), ("/b", "GET"), ("/b", "POST"), ("/any", "ANY"),
    }


def test_stacked_mapping_annotations_merge(tmp_path):
    write(tmp_path, "src/main/java/A.java", """
        @RestController
        public class A {
            @GetMapping
            @RequestMapping("/list")
            public String list() { return ""; }
        }
        """)
    assert set(routes(tmp_path)) == {("/list", "GET")}


def test_constants_resolve_paths_and_map_params(tmp_path):
    write(tmp_path, "src/main/java/Paths.java", """
        public interface Paths {
            String BASE = "items";
            String LEVEL = "LEVEL_" + "1";
            String ID = "id";
        }
        """)
    write(tmp_path, "src/main/java/Items.java", """
        @RestController
        @RequestMapping(Paths.BASE)
        public class Items {
            private static final String NAME = "name";

            @GetMapping(Paths.LEVEL)
            public String get(@RequestParam Map<String, String> query, HttpServletRequest req) {
                String id = query.get(Paths.ID);
                String name = req.getParameter(NAME);
                return id + name;
            }
        }
        """)
    entry = routes(tmp_path)[("/items/LEVEL_1", "GET")]
    assert {p["name"] for p in entry["params"]} == {"id", "name"}


def test_custom_meta_annotations_resolved_via_alias_for(tmp_path):
    write(tmp_path, "src/main/java/ann/AppController.java", """
        @Target({ElementType.TYPE})
        @RestController
        @RequestMapping
        public @interface AppController {
            @AliasFor(annotation = RequestMapping.class)
            String value();
        }
        """)
    write(tmp_path, "src/main/java/ann/AppMapping.java", """
        @Target(ElementType.METHOD)
        @RequestMapping
        public @interface AppMapping {
            @AliasFor(annotation = RequestMapping.class)
            String value();
            String template() default "";
            @AliasFor(attribute = "method", annotation = RequestMapping.class)
            RequestMethod verb() default RequestMethod.GET;
        }
        """)
    write(tmp_path, "src/main/java/Vuln.java", """
        @AppController(value = "Vuln")
        public class Vuln {
            @AppMapping(value = "L1", template = "t")
            public String one() { return ""; }

            @AppMapping(value = "L2", verb = RequestMethod.POST)
            public String two() { return ""; }
        }
        """)
    assert set(routes(tmp_path)) == {("/Vuln/L1", "GET"), ("/Vuln/L2", "POST")}


def test_call_edges_resolve_interface_to_implementation(tmp_path):
    write(tmp_path, "src/main/java/OrderService.java", """
        public interface OrderService {
            String find(String id);
        }
        """)
    write(tmp_path, "src/main/java/OrderServiceImpl.java", """
        public class OrderServiceImpl implements OrderService {
            private Repo repo;

            public String find(String id) {
                return query(id) + repo.load(id);
            }

            private String query(String id) {
                return "select * from orders where id=" + id;
            }
        }
        """)
    write(tmp_path, "src/main/java/Repo.java", """
        public class Repo {
            public String load(String id) { return id; }
        }
        """)
    write(tmp_path, "src/main/java/OrderController.java", """
        @RestController
        public class OrderController {
            private final OrderService orderService;

            @GetMapping("/orders")
            public String get(@RequestParam String id) {
                return format(orderService.find(id));
            }

            private String format(String s) { return s; }
        }
        """)
    calls = {(c["class"], c["method"]) for c in routes(tmp_path)[("/orders", "GET")]["calls"]}
    # One hop across classes, plus same-class helpers on both sides.
    assert ("OrderServiceImpl", "find") in calls
    assert ("OrderServiceImpl", "query") in calls
    assert ("OrderController", "format") in calls
    # A second class hop is not followed.
    assert ("Repo", "load") not in calls


def test_call_edge_spans_cover_the_called_method(tmp_path):
    write(tmp_path, "src/main/java/Svc.java", """
        public class Svc {
            public String run(String x) {
                return x;
            }
        }
        """)
    write(tmp_path, "src/main/java/C.java", """
        @RestController
        public class C {
            private Svc svc;

            @GetMapping("/c")
            public String c(@RequestParam String x) { return svc.run(x); }
        }
        """)
    (edge,) = routes(tmp_path)[("/c", "GET")]["calls"]
    assert edge["file"] == "src/main/java/Svc.java"
    assert (edge["line_start"], edge["line_end"]) == (3, 5)


def test_non_controller_classes_and_test_sources_are_ignored(tmp_path):
    write(tmp_path, "src/main/java/Plain.java", """
        public class Plain {
            @GetMapping("/not-a-route")
            public String x() { return ""; }
        }
        """)
    write(tmp_path, "src/test/java/T.java", """
        @RestController
        public class T {
            @GetMapping("/test-only")
            public String t() { return ""; }
        }
        """)
    assert routes(tmp_path) == {}
