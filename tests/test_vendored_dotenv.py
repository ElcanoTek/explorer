# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""The vendored python-dotenv subset (app/_vendor/dotenv).

Expected values were checked against python-dotenv 1.2.4 itself before it
was removed from requirements.
"""

from __future__ import annotations

import os

import pytest

from app._vendor.dotenv import dotenv_values, load_dotenv

PARSE_CASES = [
    ("A=b", {"A": "b"}),
    ("export A=b", {"A": "b"}),
    ("A = b ", {"A": "b"}),
    ('A="b c"', {"A": "b c"}),
    ("A='b c'", {"A": "b c"}),
    ('A="b\\nc"', {"A": "b\nc"}),
    ("A='b\\nc'", {"A": "b\\nc"}),
    ('A="b\\"c"', {"A": 'b"c'}),
    ("A='b\\'c'", {"A": "b'c"}),
    ('A="b\\\\"', {"A": "b\\"}),
    ('A="multi\nline"', {"A": "multi\nline"}),
    ("A=b # comment", {"A": "b"}),
    ("A=b#notcomment", {"A": "b#notcomment"}),
    ("A= # comment", {"A": ""}),
    ("A=#novalue", {"A": "#novalue"}),
    ('A="b" # comment', {"A": "b"}),
    ("# only a comment\nA=b", {"A": "b"}),
    ("A=", {"A": ""}),
    ("A", {"A": None}),
    ("'A'=b", {"A": "b"}),
    ("﻿A=b", {"A": "b"}),
    ("A=b\r\nC=d\rE=f", {"A": "b", "C": "d", "E": "f"}),
    ("A=b\nA=c", {"A": "c"}),
    ("=b\nC=d", {"C": "d"}),
    ('A="unterminated\nC=d', {"C": "d"}),
    ("A=x\nB=${A}y", {"A": "x", "B": "xy"}),
    ("B=${MISSING:-dflt}", {"B": "dflt"}),
    ("B='${A}'", {"B": ""}),
    ("A=x\nB=$A", {"A": "x", "B": "$A"}),
]


@pytest.mark.parametrize(("text", "expected"), PARSE_CASES)
def test_parse(tmp_path, monkeypatch, text, expected):
    monkeypatch.delenv("A", raising=False)
    monkeypatch.delenv("MISSING", raising=False)
    path = tmp_path / ".env"
    path.write_text(text, newline="")
    assert dotenv_values(path) == expected


def test_missing_file_is_empty(tmp_path):
    assert dotenv_values(tmp_path / "absent") == {}
    assert load_dotenv(tmp_path / "absent") is False


def test_load_respects_existing_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLORER_T_KEEP", "env")
    monkeypatch.delenv("EXPLORER_T_NEW", raising=False)
    path = tmp_path / ".env"
    path.write_text("EXPLORER_T_KEEP=file\nEXPLORER_T_NEW=file\n")
    assert load_dotenv(path) is True
    assert os.environ["EXPLORER_T_KEEP"] == "env"
    assert os.environ["EXPLORER_T_NEW"] == "file"


def test_override_replaces_existing_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLORER_T_KEEP", "env")
    path = tmp_path / ".env"
    path.write_text("EXPLORER_T_KEEP=file\n")
    assert load_dotenv(path, override=True) is True
    assert os.environ["EXPLORER_T_KEEP"] == "file"


def test_shared_then_local_layering(tmp_path, monkeypatch):
    """app/config.py's order: .env.shared first, then .env with override."""
    for key in ("EXPLORER_T_A", "EXPLORER_T_B"):
        monkeypatch.delenv(key, raising=False)
    (tmp_path / ".env.shared").write_text("EXPLORER_T_A=shared\nEXPLORER_T_B=shared\n")
    (tmp_path / ".env").write_text("EXPLORER_T_B=local\n")
    load_dotenv(tmp_path / ".env.shared")
    load_dotenv(tmp_path / ".env", override=True)
    assert os.environ["EXPLORER_T_A"] == "shared"
    assert os.environ["EXPLORER_T_B"] == "local"


def test_interpolation_prefers_file_with_override(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLORER_T_X", "env")
    path = tmp_path / ".env"
    path.write_text("EXPLORER_T_X=file\nEXPLORER_T_Y=${EXPLORER_T_X}\n")
    assert dotenv_values(path, override=True)["EXPLORER_T_Y"] == "file"
    assert dotenv_values(path, override=False)["EXPLORER_T_Y"] == "env"


def test_key_without_value_is_not_exported(tmp_path, monkeypatch):
    monkeypatch.delenv("EXPLORER_T_BARE", raising=False)
    path = tmp_path / ".env"
    path.write_text("EXPLORER_T_BARE\n")
    load_dotenv(path)
    assert "EXPLORER_T_BARE" not in os.environ


def test_disabled_by_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv("EXPLORER_T_OFF", raising=False)
    path = tmp_path / ".env"
    path.write_text("EXPLORER_T_OFF=1\n")
    assert load_dotenv(path) is False
    assert "EXPLORER_T_OFF" not in os.environ
