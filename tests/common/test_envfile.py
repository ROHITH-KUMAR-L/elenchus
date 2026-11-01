"""The .env loader fills unset variables only; the real environment always wins."""

from __future__ import annotations

import os
from textwrap import dedent

from common.envfile import load_env_file


def test_missing_file_is_a_no_op(tmp_path):
    assert load_env_file(tmp_path / "absent.env") == []


def test_loads_keys_and_strips_quotes_comments_and_export(tmp_path, monkeypatch):
    for key in ("GROQ_API_KEY", "GROQ_BASE_URL", "GROQ_MODEL", "BARE"):
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / ".env"
    env.write_text(dedent("""
        # a comment
        GROQ_API_KEY=gsk_123
        export GROQ_BASE_URL="https://api.groq.com/openai/v1"
        GROQ_MODEL='llama-3.3-70b-versatile'

        BARE=value
        not_a_pair
    """))
    loaded = load_env_file(env)
    assert set(loaded) == {"GROQ_API_KEY", "GROQ_BASE_URL", "GROQ_MODEL", "BARE"}
    assert os.environ["GROQ_API_KEY"] == "gsk_123"
    assert os.environ["GROQ_BASE_URL"] == "https://api.groq.com/openai/v1"
    assert os.environ["GROQ_MODEL"] == "llama-3.3-70b-versatile"


def test_real_environment_wins_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "already-set")
    env = tmp_path / ".env"
    env.write_text("GROQ_MODEL=from-file\n")
    assert "GROQ_MODEL" not in load_env_file(env)
    assert os.environ["GROQ_MODEL"] == "already-set"
