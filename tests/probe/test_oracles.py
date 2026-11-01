"""The oracles are differential and deterministic."""

from probe.oracles import (
    Response,
    command_output,
    open_redirect,
    oracle_for,
    path_traversal,
    sql_error,
    timing_slower,
    xss_reflected,
)

OK = Response(200, "", '{"isCarPresent": true}')
H2_ERROR = Response(
    200, "", "bad SQL grammar [select * from cars where id=1']; JdbcSQLSyntaxErrorException"
)
HTML = "Content-Type: text/html;charset=UTF-8\r\n"
PLAIN = "Content-Type: text/plain\r\n"
ATTACK = '<img src=x onerror=alert(1)>'


def test_sql_fires_when_the_payload_adds_a_sql_error():
    assert sql_error(OK, H2_ERROR) is True


def test_sql_does_not_fire_when_the_baseline_already_errors():
    # A route that always errors is not proof of injection.
    assert sql_error(H2_ERROR, H2_ERROR) is False


def test_sql_does_not_fire_without_an_error_signature():
    assert sql_error(OK, OK) is False


def test_xss_fires_on_verbatim_markup_in_an_html_response():
    baseline = Response(200, HTML, "<p>hello</p>")
    probe = Response(200, HTML, f"<p>hello {ATTACK}</p>")
    assert xss_reflected(baseline, probe, ATTACK) is True


def test_xss_does_not_fire_on_an_escaped_reflection():
    baseline = Response(200, HTML, "<p>hello</p>")
    escaped = Response(200, HTML, "<p>hello &lt;img src=x onerror=alert(1)&gt;</p>")
    assert xss_reflected(baseline, escaped, ATTACK) is False


def test_xss_does_not_fire_on_text_plain_even_if_the_markup_comes_back():
    # VulnerableApp's XSS routes reply text/plain: not confirmed by this oracle.
    baseline = Response(200, PLAIN, "hello")
    probe = Response(200, PLAIN, f"hello {ATTACK}")
    assert xss_reflected(baseline, probe, ATTACK) is False


def test_xss_needs_markup_in_the_attack_value():
    baseline = Response(200, HTML, "x")
    probe = Response(200, HTML, "x plain text")
    assert xss_reflected(baseline, probe, "plain text") is False


def test_xss_does_not_fire_when_the_baseline_already_shows_it():
    both = Response(200, HTML, f"<p>{ATTACK}</p>")
    assert xss_reflected(both, both, ATTACK) is False


def test_redirect_fires_on_a_location_host_taken_from_the_attack():
    baseline = Response(200, "", "")
    probe = Response(302, "Location: https://evil.example/landing\r\n", "")
    assert open_redirect(baseline, probe, "https://evil.example/landing") is True


def test_redirect_does_not_fire_on_a_local_location():
    probe = Response(302, "Location: http://localhost:9090/home\r\n", "")
    assert open_redirect(OK, probe, "http://localhost:9090/home") is False


def test_redirect_does_not_fire_when_the_host_is_not_in_the_attack():
    probe = Response(302, "Location: https://evil.example/\r\n", "")
    assert open_redirect(OK, probe, "/search?q=1") is False


def test_redirect_needs_a_3xx_status():
    probe = Response(200, "Location: https://evil.example/\r\n", "")
    assert open_redirect(OK, probe, "https://evil.example/") is False


def test_command_injection_fires_on_command_output_in_the_probe():
    baseline = Response(200, "", "PING 1 (1.1.1.1): 56 data bytes")
    probe = Response(200, "", "PING\nuid=0(root) gid=0(root) groups=0(root)")
    assert command_output(baseline, probe) is True


def test_command_injection_does_not_fire_without_command_output():
    assert command_output(OK, OK) is False


def test_command_injection_does_not_fire_when_the_baseline_already_shows_output():
    both = Response(200, "", "uid=0(root) gid=0(root)")
    assert command_output(both, both) is False


def test_path_traversal_fires_on_passwd_content_with_a_traversal_payload():
    baseline = Response(200, "", "file not found")
    probe = Response(200, "", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    assert path_traversal(baseline, probe, "../../../../etc/passwd") is True


def test_path_traversal_needs_a_traversal_sequence_in_the_attack():
    probe = Response(200, "", "root:x:0:0:root:/root:/bin/bash")
    assert path_traversal(Response(200, "", ""), probe, "info.txt") is False


def test_path_traversal_does_not_fire_when_the_baseline_already_shows_it():
    both = Response(200, "", "root:x:0:0:root")
    assert path_traversal(both, both, "../../etc/passwd") is False


def test_path_traversal_fires_on_a_leaked_private_key():
    baseline = Response(200, "", "not found")
    probe = Response(200, "", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r")
    assert path_traversal(baseline, probe, "..%2f..%2f.ssh/id_rsa") is True


def test_registry_maps_the_single_response_classes():
    assert oracle_for(89) is sql_error
    assert oracle_for(79) is xss_reflected
    assert oracle_for(601) is open_redirect
    assert oracle_for(78) is command_output
    assert oracle_for(22) is path_traversal


def test_timing_fires_only_past_the_threshold():
    assert timing_slower(0.1, 5.3, 4.0) is True
    assert timing_slower(0.1, 2.0, 4.0) is False


def test_boolean_sql_fires_when_true_matches_baseline_and_false_differs():
    from probe.oracles import sql_boolean

    baseline = Response(200, "", '{"isCarPresent": true}')
    true_probe = Response(200, "", '{"isCarPresent": true}')
    false_probe = Response(200, "", '{"isCarPresent": false}')
    assert sql_boolean(baseline, true_probe, false_probe) is True


def test_boolean_sql_does_not_fire_when_both_conditions_answer_alike():
    from probe.oracles import sql_boolean

    same = Response(200, "", '{"isCarPresent": true}')
    assert sql_boolean(same, same, same) is False


def test_boolean_sql_does_not_fire_on_a_non_200_baseline():
    from probe.oracles import sql_boolean

    assert sql_boolean(Response(401, "", ""), Response(200, "", ""), Response(200, "", "x")) is False
