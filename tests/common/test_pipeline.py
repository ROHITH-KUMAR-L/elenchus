"""Contract tests for common/pipeline.py."""

import pytest

from common.pipeline import (
    ExcludedParam,
    Hypothesis,
    ProbeJob,
    SeedRequest,
    SinkSite,
    hypothesis_id,
)
from common.record import CallHop, SinkId

SINK = SinkId("A.java", "A.find", 8, 2)
PATH = (CallHop("C.get", "C.java", 3), CallHop("A.find", "A.java", 7))


def directed(**overrides):
    values = {
        "kind": "directed", "route": "/o", "method": "GET", "cwe": 89,
        "candidate_params": ("id", "sort"), "sink_id": SINK, "call_path": PATH,
    }
    return Hypothesis(**{**values, **overrides})


def sweep(param="id"):
    return Hypothesis("sweep", "/o", "GET", 89, (param,))


def test_hypothesis_id_is_stable_and_round_trips():
    assert directed().hypothesis_id == directed().hypothesis_id
    assert Hypothesis.from_dict(directed().to_dict()) == directed()
    assert Hypothesis.from_dict(sweep().to_dict()) == sweep()


def test_hypothesis_id_separates_sinks_and_sweep_params():
    other_sink = SinkId("B.java", "B.find", 8, 2)
    assert directed().hypothesis_id != directed(sink_id=other_sink).hypothesis_id
    assert sweep("id").hypothesis_id != sweep("sort").hypothesis_id
    # A directed hypothesis keeps its id if the route gains a param.
    assert directed().hypothesis_id == directed(candidate_params=("id",)).hypothesis_id
    assert hypothesis_id("directed", "/o", "get", 89, SINK, ()) == directed().hypothesis_id


@pytest.mark.parametrize(
    "build, message",
    [
        (lambda: directed(sink_id=None), "needs sink_id"),
        (lambda: directed(call_path=None), "needs sink_id"),
        (lambda: Hypothesis("sweep", "/o", "GET", 89, ("a", "b")), "exactly one param"),
        (lambda: Hypothesis("sweep", "/o", "GET", 89, ("a",), sink_id=SINK), "no sink_id"),
        (lambda: Hypothesis("guess", "/o", "GET", 89, ("a",)), "kind"),
    ],
)
def test_hypothesis_rejects(build, message):
    with pytest.raises(ValueError, match=message):
        build()


def job(**overrides):
    values = {
        "job_id": "j-1", "route": "/o", "method": "GET", "job_pass": "directed",
        "hypothesis_ids": ("h-1",), "cwes": (89,),
        "seed_request": SeedRequest("http://localhost/o?id=1", "GET"), "canary": "elx-1",
    }
    return ProbeJob(**{**values, **overrides})


def test_probe_job_is_valid_before_its_scan_starts():
    assert job().scan_id is None and job().outcome is None


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"job_pass": "other"}, "job_pass"),
        ({"outcome": "other"}, "outcome"),
        ({"cwes": ()}, "at least one CWE"),
    ],
)
def test_probe_job_rejects(overrides, message):
    with pytest.raises(ValueError, match=message):
        job(**overrides)


def test_excluded_param_and_sink_site_reject_unknown_codes():
    with pytest.raises(ValueError, match="sub_code"):
        ExcludedParam("id", "bogus")
    with pytest.raises(ValueError, match="kind"):
        SinkSite(SINK, 89, "macro", "dynamic", "entry")
