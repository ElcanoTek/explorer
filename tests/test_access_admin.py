# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Operator-facing Explorer access-list commands."""

from __future__ import annotations

from app import access_admin
from app.central_auth import CentralAuthStore


def test_admin_can_grant_list_and_revoke_access(tmp_path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "access.db"
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "central")

    assert (
        access_admin.main(
            ["--db", str(db_path), "access", "grant", "Alice@Example.com"]
        )
        == 0
    )
    assert "alice@example.com" in capsys.readouterr().out

    assert access_admin.main(["--db", str(db_path), "access", "list"]) == 0
    assert "alice@example.com\tallowed" in capsys.readouterr().out

    store = CentralAuthStore(db_path)
    session = store.create_session("account-123", "alice@example.com")
    assert (
        access_admin.main(
            ["--db", str(db_path), "access", "revoke", "alice@example.com"]
        )
        == 0
    )
    assert store.get_identity(session.token) is None
    assert "revoked" in capsys.readouterr().out.lower()


def test_access_commands_refuse_noncentral_deployments(
    tmp_path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "access.db"
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "elcano")

    result = access_admin.main(
        ["--db", str(db_path), "access", "grant", "alice@example.com"]
    )

    assert result == 1
    assert "EXPLORER_AUTH_MODE=central" in capsys.readouterr().err
    assert not db_path.exists()
