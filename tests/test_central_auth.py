# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Security behavior for Explorer's central-auth access boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import stat
import time
import urllib.error
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.central_auth import (
    AccessDeniedError,
    AuthKeyResolver,
    CentralAuthClient,
    CentralAuthError,
    CentralAuthStore,
    CodeExchangeRejectedError,
    csrf_token_for_session,
    verify_csrf_token,
    verify_logout_token,
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


def test_backchannel_logout_is_idempotent_and_scoped_to_subject(
    store: CentralAuthStore,
) -> None:
    store.grant_access("alice@example.com", now=1_000)
    first = store.create_session("account-123", "alice@example.com", now=1_000)
    second = store.create_session("account-456", "alice@example.com", now=1_000)

    assert store.consume_logout_event(
        "event-123", "https://auth.example.com", "account-123", 1_001, now=1_002
    )
    assert not store.consume_logout_event(
        "event-123", "https://auth.example.com", "account-123", 1_001, now=1_003
    )
    assert store.get_identity(first.token, now=1_004) is None
    assert store.get_identity(second.token, now=1_004) is not None


def _mint_logout(
    private_key, *, audience="explorer", issuer="https://auth.example.com", **overrides
):
    public = private_key.public_key().public_bytes_raw()
    kid = (
        base64.urlsafe_b64encode(hashlib.sha256(public).digest()[:16])
        .rstrip(b"=")
        .decode()
    )
    header = {"typ": "logout+jwt", "alg": "EdDSA", "kid": kid}
    payload = {
        "iss": issuer,
        "sub": "account-123",
        "aud": audience,
        "email": "alice@example.com",
        "iat": 1_000,
        "exp": 1_300,
        "jti": "event-123",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    payload.update(overrides)

    def encode(value):
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

    body = f"{encode(header)}.{encode(payload)}"
    signature = (
        base64.urlsafe_b64encode(private_key.sign(body.encode())).rstrip(b"=").decode()
    )
    return f"{body}.{signature}", base64.b64encode(public).decode()


def test_logout_token_verification_checks_signature_issuer_and_audience() -> None:
    private_key = Ed25519PrivateKey.generate()
    raw, public_key = _mint_logout(private_key)
    event = verify_logout_token(
        raw,
        issuer="https://auth.example.com",
        audience="explorer",
        public_keys=[public_key],
        now=1_010,
    )
    assert event.event_id == "event-123"
    assert event.subject == "account-123"

    with pytest.raises(CentralAuthError):
        verify_logout_token(
            raw,
            issuer="https://auth.example.com",
            audience="lens",
            public_keys=[public_key],
            now=1_010,
        )

    malformed_issuer, _ = _mint_logout(private_key, issuer=123)
    with pytest.raises(CentralAuthError):
        verify_logout_token(
            malformed_issuer,
            issuer="https://auth.example.com",
            audience="explorer",
            public_keys=[public_key],
            now=1_010,
        )


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
                    "iss": "https://auth.example.com",
                    "aud": "explorer",
                    "exp": int(time.time()) + 300,
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
            return json.dumps(
                {
                    "sub": "account-123",
                    "email": "alice@example.com",
                    "nonce": "wrong",
                    "iss": "https://auth.example.com",
                    "aud": "explorer",
                    "exp": int(time.time()) + 300,
                }
            ).encode()

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


def _client() -> CentralAuthClient:
    return CentralAuthClient(
        issuer_url="https://auth.example.com",
        public_url="https://explorer.example.com",
        client_id="explorer",
        client_secret="a-random-client-secret-with-32-bytes",
    )


def _fake_response(payload: dict):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return json.dumps(payload).encode()

    return Response()


def _valid_payload() -> dict:
    return {
        "sub": "account-123",
        "email": "alice@example.com",
        "nonce": "expected-nonce",
        "iss": "https://auth.example.com",
        "aud": "explorer",
        "exp": int(time.time()) + 300,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"aud": "lens"},
        {"iss": "https://other-auth.example.com"},
        {"exp": int(time.time()) - 120},
        {"exp": "soon"},
        {"exp": True},
    ],
)
def test_code_exchange_rejects_wrong_audience_issuer_or_expired(
    monkeypatch, mutation
) -> None:
    payload = _valid_payload() | mutation
    monkeypatch.setattr(
        "app.central_auth._open_token_request",
        lambda *_args: _fake_response(payload),
    )
    with pytest.raises(CentralAuthError, match="invalid"):
        _client().exchange(
            code="code", code_verifier="v" * 43, expected_nonce="expected-nonce"
        )


def test_code_exchange_tolerates_small_clock_skew(monkeypatch) -> None:
    payload = _valid_payload() | {"exp": int(time.time()) - 10}
    monkeypatch.setattr(
        "app.central_auth._open_token_request",
        lambda *_args: _fake_response(payload),
    )
    principal = _client().exchange(
        code="code", code_verifier="v" * 43, expected_nonce="expected-nonce"
    )
    assert principal.subject == "account-123"


def test_non_ascii_nonce_from_issuer_is_rejected_not_crashed(monkeypatch) -> None:
    payload = _valid_payload() | {"nonce": "expected-nonc\u00e9"}
    monkeypatch.setattr(
        "app.central_auth._open_token_request",
        lambda *_args: _fake_response(payload),
    )
    with pytest.raises(CentralAuthError, match="invalid"):
        _client().exchange(
            code="code", code_verifier="v" * 43, expected_nonce="expected-nonce"
        )


def test_http_400_from_token_endpoint_is_a_rejected_code(monkeypatch) -> None:
    def refuse(*_args):
        raise urllib.error.HTTPError(
            "https://auth.example.com/token", 400, "Bad Request", {}, None
        )

    monkeypatch.setattr("app.central_auth._open_token_request", refuse)
    with pytest.raises(CodeExchangeRejectedError):
        _client().exchange(code="code", code_verifier="v" * 43, expected_nonce="n")


def test_http_401_from_token_endpoint_is_an_outage_not_a_retry(monkeypatch) -> None:
    def refuse(*_args):
        raise urllib.error.HTTPError(
            "https://auth.example.com/token", 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr("app.central_auth._open_token_request", refuse)
    with pytest.raises(CentralAuthError) as excinfo:
        _client().exchange(code="code", code_verifier="v" * 43, expected_nonce="n")
    assert not isinstance(excinfo.value, CodeExchangeRejectedError)


@pytest.mark.parametrize("overrides", [{"exp": 1_000}, {"exp": "soon"}, {"exp": True}])
def test_logout_token_requires_a_live_expiry(overrides) -> None:
    private_key = Ed25519PrivateKey.generate()
    raw, public_key = _mint_logout(private_key, **overrides)
    with pytest.raises(CentralAuthError):
        verify_logout_token(
            raw,
            issuer="https://auth.example.com",
            audience="explorer",
            public_keys=[public_key],
            now=1_200,
        )


def test_logout_token_missing_expiry_is_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    raw, public_key = _mint_logout(private_key)
    # Strip exp by re-minting without it: overrides cannot delete, so build by hand.
    header_b64, payload_b64, _sig = raw.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    del payload["exp"]
    body = (
        header_b64
        + "."
        + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    signature = (
        base64.urlsafe_b64encode(private_key.sign(body.encode())).rstrip(b"=").decode()
    )
    with pytest.raises(CentralAuthError):
        verify_logout_token(
            f"{body}.{signature}",
            issuer="https://auth.example.com",
            audience="explorer",
            public_keys=[public_key],
            now=1_010,
        )


def test_replay_table_is_pruned_after_retention(store: CentralAuthStore) -> None:
    assert store.consume_logout_event(
        "old-event", "https://auth.example.com", "account-1", 1_000, now=1_000
    )
    week = 7 * 24 * 60 * 60
    assert store.consume_logout_event(
        "new-event",
        "https://auth.example.com",
        "account-2",
        1_000 + week,
        now=1_000 + week + 1,
    )
    with sqlite3.connect(store.path) as connection:
        ids = {
            row[0]
            for row in connection.execute("SELECT event_id FROM revocation_events")
        }
    assert ids == {"new-event"}


def test_session_touch_is_rate_limited_to_one_write_per_minute(
    store: CentralAuthStore,
) -> None:
    store.grant_access("alice@example.com", now=1_000)
    issued = store.create_session("account-123", "alice@example.com", now=1_000)

    def stamps():
        with sqlite3.connect(store.path) as connection:
            return connection.execute(
                "SELECT last_seen_at, idle_expires_at FROM sessions WHERE token_hash = ?",
                (issued.token_hash,),
            ).fetchone()

    assert stamps() == (1_000, 1_000 + store.idle_seconds)
    # Inside the interval: validated, but no write.
    assert store.get_identity(issued.token, now=1_030) is not None
    assert store.get_identity(issued.token, now=1_059) is not None
    assert stamps() == (1_000, 1_000 + store.idle_seconds)
    # Past the interval: one write, idle clock moves forward from the request.
    assert store.get_identity(issued.token, now=1_060) is not None
    assert stamps() == (1_060, 1_060 + store.idle_seconds)
    # The idle limit is enforced against the last touch, never longer than the
    # limit: a request at exactly idle_expires_at is rejected.
    assert store.get_identity(issued.token, now=1_060 + store.idle_seconds) is None


def _jwks_for(*public_keys_b64: str) -> bytes:
    keys = []
    for encoded in public_keys_b64:
        raw = base64.b64decode(encoded)
        keys.append(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:16])
                .rstrip(b"=")
                .decode(),
                "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
            }
        )
    return json.dumps({"keys": keys}).encode()


def test_key_resolver_merges_static_and_published_keys_and_survives_fetch_failure() -> (
    None
):
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    old_b64 = base64.b64encode(old_key.public_key().public_bytes_raw()).decode()
    new_b64 = base64.b64encode(new_key.public_key().public_bytes_raw()).decode()
    clock = {"now": 1_000.0}
    calls = {"n": 0, "fail": False}

    def fetch(url, timeout):
        calls["n"] += 1
        assert url == "https://auth.example.com/jwks.json"
        if calls["fail"]:
            raise OSError("auth unreachable")
        return _jwks_for(new_b64)

    resolver = AuthKeyResolver(
        "https://auth.example.com/", [old_b64], fetch=fetch, now=lambda: clock["now"]
    )
    assert resolver.public_keys() == [old_b64, new_b64]
    assert calls["n"] == 1
    # Cached: no second fetch inside the TTL.
    assert resolver.public_keys() == [old_b64, new_b64]
    assert calls["n"] == 1
    # A fetch failure after the TTL keeps the cached keys.
    clock["now"] += 11 * 60
    calls["fail"] = True
    assert resolver.public_keys() == [old_b64, new_b64]
    assert calls["n"] == 2

    # A token signed by a key that only exists in a newer JWKS triggers one
    # refresh, rate-limited to once a minute.
    rotated_key = Ed25519PrivateKey.generate()
    rotated_b64 = base64.b64encode(rotated_key.public_key().public_bytes_raw()).decode()
    raw, _ = _mint_logout(rotated_key)
    calls["fail"] = False
    responses = {"body": _jwks_for(new_b64, rotated_b64)}
    resolver._fetch = lambda url, timeout: responses["body"]
    clock["now"] += 61
    assert rotated_b64 in resolver.keys_for_token(raw)
    fetched_after = calls["n"]
    # Unknown kid again inside the minute: no extra fetch.
    unknown_key = Ed25519PrivateKey.generate()
    unknown_raw, _ = _mint_logout(unknown_key)
    resolver.keys_for_token(unknown_raw)
    assert calls["n"] == fetched_after


def test_key_resolver_ignores_malformed_jwks_entries() -> None:
    good = Ed25519PrivateKey.generate()
    good_b64 = base64.b64encode(good.public_key().public_bytes_raw()).decode()
    document = json.loads(_jwks_for(good_b64))
    document["keys"].extend(
        [
            {"kty": "RSA", "n": "x", "e": "AQAB"},
            {"kty": "OKP", "crv": "Ed25519", "x": "dG9vLXNob3J0"},
            "not-a-key",
        ]
    )
    resolver = AuthKeyResolver(
        "https://auth.example.com",
        [],
        fetch=lambda url, timeout: json.dumps(document).encode(),
        now=lambda: 1_000.0,
    )
    assert resolver.public_keys() == [good_b64]


def test_logout_token_verifies_against_a_key_only_published_in_jwks() -> None:
    signer = Ed25519PrivateKey.generate()
    signer_b64 = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
    raw, _ = _mint_logout(signer)
    resolver = AuthKeyResolver(
        "https://auth.example.com",
        [],
        fetch=lambda url, timeout: _jwks_for(signer_b64),
        now=lambda: 1_000.0,
    )
    event = verify_logout_token(
        raw,
        issuer="https://auth.example.com",
        audience="explorer",
        public_keys=resolver.keys_for_token(raw),
        now=1_010,
    )
    assert event.subject == "account-123"
