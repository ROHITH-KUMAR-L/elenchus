"""Tests for common/config.py, including its agreement with the docs."""

import re
from pathlib import Path

import pytest

from common.config import DEFAULTS, load_config

ARCHITECTURE = Path(__file__).parents[2] / "docs" / "architecture.md"
ROW = re.compile(r"^\| `([a-z0-9_.<>]+)` \| \[([^\]]*)\]", re.MULTILINE)


def documented() -> dict[str, str]:
    section = ARCHITECTURE.read_text().split("## Config reference", 1)[1].split("\n## ", 1)[0]
    return dict(ROW.findall(section))


def test_every_documented_key_has_a_default_and_every_default_is_documented():
    docs = documented()
    assert docs
    expected = {key for key in docs if "<" not in key}
    expected |= {f"zap.rule_map.{cwe}" for cwe in (89, 79, 78, 22, 601)}
    assert set(DEFAULTS) == expected


def test_numeric_and_boolean_defaults_match_the_docs():
    for key, text in documented().items():
        if "<" in key:
            continue
        value = DEFAULTS[key]
        literal = text.removeprefix("proposed: ").strip()
        if isinstance(value, bool):
            assert literal == str(value).lower(), key
        elif isinstance(value, (int, float)):
            assert float(literal) == float(value), key


def test_documented_rule_map_matches():
    text = documented()["zap.rule_map.<cwe>"]
    for part in text.split(";"):
        cwe, rules = part.split("=")
        assert DEFAULTS[f"zap.rule_map.{cwe.strip()}"] == tuple(r.strip() for r in rules.split(","))


def test_stage_budgets_leave_a_margin_under_five_minutes():
    total = sum(v for k, v in DEFAULTS.items() if k.startswith("probe.stage_budget_seconds."))
    assert total < 300


def test_defaults_load_without_a_file():
    config = load_config(environ={})
    assert config["zap.enabled"] is True
    assert config.rule_map()[79] == ("40012",)


def test_sql_injection_is_suppressible_once_blind_and_union_are_confirmed():
    # BS10b wired sql_boolean, so the live run confirms blind and union SQL
    # instead of marking them tested_negative: wrong_suppression_count for CWE-89
    # fell to 0 and 89 returns to suppress_cwes.
    assert 89 in DEFAULTS["export.suppress_cwes"]


def test_toml_file_then_overrides(tmp_path):
    path = tmp_path / "elenchus.toml"
    path.write_text(
        'zap.thread_per_host = 4\n[replay]\ncount = 5\n[zap.rule_map]\n"352" = ["1"]\n'
        "[ai.tasks.fix_text]\nenabled = true\n"
    )
    config = load_config(path, {"replay.count": 7, "ai.enabled": True}, environ={})
    assert config["zap.thread_per_host"] == 4
    assert config["replay.count"] == 7
    assert config.rule_map()[352] == ("1",)
    assert config.task_enabled("fix_text")
    assert not config.task_enabled("other")


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"no.such.key": 1}, "unknown config key"),
        ({"replay.count": "3"}, "must be of type int"),
        ({"semgrep.enabled": 1}, "must be of type bool"),
        ({"replay.count": True}, "must be of type int"),
        ({"zap.api_url": "http://10.0.0.1:8090"}, "loopback"),
        ({"target.base_url": "http://example.com"}, "localhost"),
        ({"header.count_mode": "per_moon"}, "header.count_mode"),
        ({"zap.attack_strength.sweep": "NONE"}, "attack_strength"),
        ({"replay.min_hits": 9}, "replay.min_hits"),
        ({"confidence.band.low_max": 0.9}, "confidence.band"),
    ],
)
def test_bad_values_are_errors(overrides, message):
    with pytest.raises(ValueError, match=message):
        load_config(overrides=overrides, environ={})


def test_integer_is_accepted_for_a_float_key():
    assert load_config(overrides={"backguided.hop_penalty": 0}, environ={})["backguided.hop_penalty"] == 0.0


def test_judging_profile_forces_adapters_and_ai_off():
    config = load_config(
        overrides={
            "judging.profile": True,
            "semgrep.enabled": True,
            "logtail.enabled": True,
            "ai.enabled": True,
            "ai.tasks.fix_text.enabled": True,
        },
        environ={},
    )
    assert not config["semgrep.enabled"]
    assert not config["logtail.enabled"]
    assert not config["ai.enabled"]
    assert not config.task_enabled("fix_text")
    assert config["zap.enabled"]


def test_judging_profile_refuses_to_run_without_zap():
    with pytest.raises(ValueError, match="requires zap.enabled"):
        load_config(overrides={"judging.profile": True, "zap.enabled": False}, environ={})


def test_api_key_comes_from_the_environment_and_stays_out_of_repr():
    config = load_config(environ={"ZAP_API_KEY": "s3cret"})
    assert config["zap.api_key"] == "s3cret"
    assert "s3cret" not in repr(config)
