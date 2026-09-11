# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Security behavior for Explorer's central-auth access boundary."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import urllib.parse

import pytest

from app.central_auth import (
    AccessDeniedError,
    CentralAuthClient,
    CentralAuthError,
    CentralAuthStore,
    csrf_token_for_session,
    verify_csrf_token,
)


@pytest.fixture()
def store(tmp_path) -> CentralAuthStore:
    return CentralAuthStore(
        tmp_path / "access.db", idle_seconds=3_600, absolute_seconds=43_200
    )


def test_access_is_default_deny_and_email_matching_is_case_insensitive(
    store: CentralAuthStore,
) -> None:
    assert not store.is_allowed("alice@example.com")

    store.grant_access("Alice@Example.com", now=1_000)

    assert store.is_allowed("alice@example.com")
    assert store.list_access()[0].email == "alice@example.com"
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_session_secret_is_hashed_at_rest(store: CentralAuthStore) -> None:
    store.grant_access("alice@example.com", now=1_000)

    issued = store.create_session("account-123", "alice@example.com", now=1_000)

    with sqlite3.connect(store.path) as connection:
        stored = connection.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored == hashlib.sha256(issued.token.encode("ascii")).hexdigest()
    assert stored != issued.token
    assert store.get_identity(issued.token, now=1_001).email == "alice@example.com"


def test_session_obeys_idle_and_absolute_expiration(store: CentralAuthStore) -> None:
    store.grant_access("alice@example.com", now=1_000)
    idle = store.create_session("account-123", "alice@example.com", now=1_000)

    assert store.get_identity(idle.token, now=4_599) is not None
    assert store.get_identity(idle.token, now=8_200) is None

    absolute = store.create_session("account-123", "alice@example.com", now=10_000)
    for timestamp in range(13_000, 52_001, 3_000):
        assert store.get_identity(absolute.token, now=timestamp) is not None
    assert store.get_identity(absolute.token, now=53_199) is not None
    assert store.get_identity(absolute.token, now=53_200) is None


def test_revoking_access_immediately_invalidates_existing_sessions(
    store: CentralAuthStore,
) -> None:
    store.grant_access("alice@example.com", now=1_000)
    issued = store.create_session("account-123", "alice@example.com", now=1_000)

    assert store.revoke_access("ALICE@example.com")

    assert store.get_identity(issued.token, now=1_001) is None
    with pytest.raises(AccessDeniedError):
        store.create_session("account-123", "alice@example.com", now=1_002)


def test_logout_revokes_only_the_presented_session(store: CentralAuthStore) -> None:
    store.grant_access("alice@example.com", now=1_000)
    first = store.create_session("account-123", "alice@example.com", now=1_000)
    second = store.create_session("account-123", "alice@example.com", now=1_000)

    assert store.revoke_session(first.token, now=1_001)

    assert store.get_identity(first.token, now=1_002) is None
    assert store.get_identity(second.token, now=1_002) is not None


def test_csrf_token_is_bound_to_the_app_session_secret() -> None:
    token = "browser-only-app-session-secret"
    csrf = csrf_token_for_session(token)

    assert verify_csrf_token(token, csrf)
    assert not verify_csrf_token("a-different-session", csrf)
    assert not verify_csrf_token(token, "")


def test_code_exchange_authenticates_client_and_validates_nonce(monkeypatch) -> None:
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, _limit):
            return json.dumps(
                {
                    "sub": "account-123",
                    "email": "Alice@Example.com",
                    "nonce": "expected-nonce",
                }
            ).encode()

    def fake_open(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("app.central_auth._open_token_request", fake_open)
    client = CentralAuthClient(
        issuer_url="https://auth.example.com",
        public_url="https://explorer.example.com",
        client_id="explorer",
        client_secret="a-random-client-secret-with-32-bytes",
    )

    principal = client.exchange(
        code="single-use-code",
        code_verifier="pkce-verifier",
        expected_nonce="expected-nonce",
    )

    assert principal.email == "alice@example.com"
    assert captured["timeout"] == 10
    request = captured["request"]
    assert request.full_url == "https://auth.example.com/token"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization").startswith("Basic ")
    form = urllib.parse.parse_qs(request.data.decode())
    assert form == {
        "grant_type": ["authorization_code"],
        "code": ["single-use-code"],
        "redirect_uri": ["https://explorer.example.com/auth/callback"],
        "client_id": ["explorer"],
        "code_verifier": ["pkce-verifier"],
    }


def test_authorization_url_uses_exact_callback_and_pkce() -> None:
    client = CentralAuthClient(
        issuer_url="https://auth.example.com",
        public_url="https://explorer.example.com",
        client_id="explorer",
        client_secret="a-random-client-secret-with-32-bytes",
    )

    parsed = urllib.parse.urlsplit(
        client.authorization_url(
            state="browser-state", code_challenge="s256-challenge", nonce="nonce"
        )
    )
    query = urllib.parse.parse_qs(parsed.query)

    assert parsed.geturl().startswith("https://auth.example.com/authorize?")
    assert query == {
        "response_type": ["code"],
        "client_id": ["explorer"],
        "redirect_uri": ["https://explorer.example.com/auth/callback"],
        "scope": ["email"],
        "state": ["browser-state"],
        "code_challenge": ["s256-challenge"],
        "code_challenge_method": ["S256"],
        "nonce": ["nonce"],
    }


def test_code_exchange_rejects_wrong_nonce(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, _limit):
            return b'{"sub":"account-123","email":"alice@example.com","nonce":"wrong"}'

    monkeypatch.setattr(
        "app.central_auth._open_token_request", lambda *_args: Response()
    )
    client = CentralAuthClient(
        issuer_url="https://auth.example.com",
        public_url="https://explorer.example.com",
        client_id="explorer",
        client_secret="a-random-client-secret-with-32-bytes",
    )

    with pytest.raises(CentralAuthError, match="invalid"):
        client.exchange(
            code="single-use-code",
            code_verifier="pkce-verifier",
            expected_nonce="expected-nonce",
        )
