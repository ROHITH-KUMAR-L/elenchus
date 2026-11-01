"""Servlet adapter (B-7): routes from @WebServlet, params from the request."""

from textwrap import dedent

from producers.sast.code_index import build_code_index


def write(root, rel, source):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source))


def routes(tmp_path, source):
    write(tmp_path, "src/S.java", source)
    return {(r.route, r.method): r for r in build_code_index(tmp_path, "servlet").routes}


def test_webservlet_doget_dopost_become_routes(tmp_path):
    rs = routes(tmp_path, """
        @WebServlet(value = "/pay/charge")
        public class S extends HttpServlet {
            public void doGet(HttpServletRequest request, HttpServletResponse response) {
                String id = request.getParameter("id");
                response.getWriter().write(id);
            }
            public void doPost(HttpServletRequest request, HttpServletResponse response) {
                String amount = request.getParameter("amount");
            }
        }
        """)
    assert ("/pay/charge", "GET") in rs
    assert ("/pay/charge", "POST") in rs
    assert rs[("/pay/charge", "GET")].func == "S.doGet"
    assert "id" in {p.name for p in rs[("/pay/charge", "GET")].params}
    assert "amount" in {p.name for p in rs[("/pay/charge", "POST")].params}


def test_urlpatterns_array_yields_a_route_each(tmp_path):
    rs = routes(tmp_path, """
        @WebServlet(urlPatterns = {"/a", "/b"})
        public class S extends HttpServlet {
            public void doGet(HttpServletRequest request, HttpServletResponse response) {}
        }
        """)
    assert ("/a", "GET") in rs and ("/b", "GET") in rs


def test_a_class_without_webservlet_is_not_a_route(tmp_path):
    rs = routes(tmp_path, """
        public class S extends HttpServlet {
            public void doGet(HttpServletRequest request, HttpServletResponse response) {}
        }
        """)
    assert rs == {}
