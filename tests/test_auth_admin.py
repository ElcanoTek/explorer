# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Operator-facing account lifecycle commands."""

from __future__ import annotations

from pathlib import Path

from app import auth_admin
from app.local_auth import LocalAuthStore


def _cancel_password_input(_prompt: str) -> str:
    raise EOFError


def test_admin_can_create_reset_disable_and_enable_user(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "auth.db"
    first_password = "harbor violet lantern quartz"
    reset_password = "meadow compass glacier copper"
    entered = iter([first_password, first_password, reset_password, reset_password])
    monkeypatch.setenv("EXPLORER_ARGON2_MEMORY_COST", "1024")
    monkeypatch.setenv("EXPLORER_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("EXPLORER_AUTH_ALLOW_WEAK_HASH_FOR_TESTS", "1")
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "local")

    def password_reader(_prompt: str) -> str:
        return next(entered)

    assert (
        auth_admin.main(
            ["--db", str(db_path), "user", "add", "Alice@example.com"],
            password_reader=password_reader,
        )
        == 0
    )
    create_output = capsys.readouterr().out
    assert first_password not in create_output
    store = LocalAuthStore(db_path)
    created = store.authenticate("alice@example.com", first_password)
    assert created is not None and created.must_change_password

    issued = store.create_session(created.id)
    assert (
        auth_admin.main(
            ["--db", str(db_path), "user", "reset-password", "alice@example.com"],
            password_reader=password_reader,
        )
        == 0
    )
    reset_output = capsys.readouterr().out
    assert reset_password not in reset_output
    assert store.authenticate("alice@example.com", first_password) is None
    assert store.authenticate("alice@example.com", reset_password) is not None
    assert store.get_identity(issued.token) is None

    assert (
        auth_admin.main(["--db", str(db_path), "user", "disable", "alice@example.com"])
        == 0
    )
    capsys.readouterr()
    assert store.authenticate("alice@example.com", reset_password) is None

    assert (
        auth_admin.main(["--db", str(db_path), "user", "enable", "alice@example.com"])
        == 0
    )
    capsys.readouterr()
    assert store.authenticate("alice@example.com", reset_password) is not None


def test_admin_list_never_prints_password_hashes(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "auth.db"
    password = "harbor violet lantern quartz"
    monkeypatch.setenv("EXPLORER_ARGON2_MEMORY_COST", "1024")
    monkeypatch.setenv("EXPLORER_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("EXPLORER_AUTH_ALLOW_WEAK_HASH_FOR_TESTS", "1")
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "local")
    store = LocalAuthStore(db_path)
    user = store.create_user("alice@example.com", password)

    assert auth_admin.main(["--db", str(db_path), "user", "list"]) == 0
    output = capsys.readouterr().out

    assert "alice@example.com" in output
    assert password not in output
    assert user.password_hash not in output


def test_add_fails_before_mutating_database_when_password_entry_is_cancelled(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "local")
    result = auth_admin.main(
        ["--db", str(db_path), "user", "add", "alice@example.com"],
        password_reader=_cancel_password_input,
    )

    assert result == 1
    assert "no account was changed" in capsys.readouterr().err
    assert not db_path.exists()
