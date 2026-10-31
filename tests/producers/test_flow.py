"""The own flow engine: which formal params reach a target expression."""

from textwrap import dedent

from producers.sast.flow import reaching_formals
from producers.sast.spring_routes import JAVA, Parser, _walk


def method_and_last_call_arg(source):
    root = Parser(JAVA).parse(dedent(source).encode()).root_node
    method = next(_walk(root, "method_declaration"))
    call = list(_walk(method, "method_invocation"))[-1]
    args = call.child_by_field_name("arguments")
    return method, args.named_children[0]


def test_only_the_param_that_flows_to_the_sink_is_reached():
    method, arg = method_and_last_call_arg("""
        class C {
            void run(String id, String name) {
                String q = "select * from t where id = " + id;
                st.executeQuery(q);
            }
        }
        """)
    assert reaching_formals(method, arg) == {"id"}


def test_a_literal_only_argument_reaches_no_param():
    method, arg = method_and_last_call_arg("""
        class C {
            void run(String id) {
                st.executeQuery("select 1");
            }
        }
        """)
    assert reaching_formals(method, arg) == set()


def test_transitive_assignment_is_followed():
    method, arg = method_and_last_call_arg("""
        class C {
            void run(String a, String b) {
                String x = a;
                String y = x + b;
                st.executeQuery(y);
            }
        }
        """)
    assert reaching_formals(method, arg) == {"a", "b"}
