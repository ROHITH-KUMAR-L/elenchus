"""The error-based SQL oracle is differential and deterministic."""

from probe.oracles import Response, oracle_for, sql_error

OK = Response(200, "", '{"isCarPresent": true}')
H2_ERROR = Response(
    200, "", "bad SQL grammar [select * from cars where id=1']; JdbcSQLSyntaxErrorException"
)


def test_fires_when_the_payload_adds_a_sql_error():
    assert sql_error(OK, H2_ERROR) is True


def test_does_not_fire_when_the_baseline_already_errors():
    # A route that always errors is not proof of injection.
    assert sql_error(H2_ERROR, H2_ERROR) is False


def test_does_not_fire_without_an_error_signature():
    assert sql_error(OK, OK) is False


def test_registry_exposes_sql_and_nothing_unbuilt_yet():
    assert oracle_for(89) is sql_error
    assert oracle_for(79) is None
