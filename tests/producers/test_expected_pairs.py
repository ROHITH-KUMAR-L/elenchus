"""expected_pairs must stay well formed, and must agree with the target's source
when a checkout is present in .targets/."""

from pathlib import Path

import pytest
import yaml

from common.record import ScanTarget
from producers.hypotheses.builder import build_directed
from producers.sast.code_index import build_code_index
from producers.sast.static_stage import run_static

ROOT = Path(__file__).parents[2]
PAIRS = yaml.safe_load((ROOT / "common/fixtures/expected_pairs/vulnerableapp.yaml").read_text())
SOURCE = ROOT / ".targets" / "VulnerableApp"


def test_every_pair_is_complete():
    assert PAIRS["source_commit"]
    assert PAIRS["pairs"]
    for pair in PAIRS["pairs"]:
        assert set(pair) == {"route", "method", "params", "cwe", "file", "line"}
        assert pair["params"]


@pytest.mark.skipif(not SOURCE.is_dir(), reason="needs a VulnerableApp checkout in .targets/")
def test_pairs_match_the_routes_and_params_the_index_finds():
    routes = {(r.route, r.method): r for r in build_code_index(SOURCE).routes}
    for pair in PAIRS["pairs"]:
        entry = routes[(pair["route"], pair["method"])]
        assert set(pair["params"]) <= {p.name for p in entry.params}, pair["route"]
        lines = (SOURCE / pair["file"]).read_text().splitlines()
        assert len(lines) >= pair["line"], pair["file"]


@pytest.mark.skipif(not SOURCE.is_dir(), reason="needs a VulnerableApp checkout in .targets/")
def test_every_pair_has_a_dynamic_sink_on_the_line_and_a_directed_hypothesis():
    index = build_code_index(SOURCE)
    target = ScanTarget(str(SOURCE), "http://localhost/", "r", "spring-mvc")
    findings = run_static(target, index)
    by_location = {(f.file, f.line): f for f in findings}
    directed = build_directed(findings, index)
    for pair in PAIRS["pairs"]:
        assert by_location[(pair["file"], pair["line"])].arg_shape == "dynamic", pair
        assert any(
            h.route == pair["route"] and h.method == pair["method"] and h.cwe == pair["cwe"]
            and h.sink_id.file == pair["file"]
            for h in directed
        ), pair
