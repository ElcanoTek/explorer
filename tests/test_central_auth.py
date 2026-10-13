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
    AccessProvisionEvent,
    AuthKeyResolver,
    CentralAuthClient,
    CentralAuthError,
    CentralAuthStore,
    CodeExchangeRejectedError,
    csrf_token_for_session,
    verify_access_token,
    verify_csrf_token,
    verify_logout_token,
)


def _mint_access(private_key, *, action="grant", version=1, **overrides):
    public = private_key.public_key().public_bytes_raw()
    kid = (
        base64.urlsafe_b64encode(hashlib.sha256(public).digest()[:16])
        .rstrip(b"=")
        .decode()
    )
    header = {"typ": "access+jwt", "alg": "EdDSA", "kid": kid}
    payload = {
        "iss": "https://auth.example.com",
        "sub": "account-123",
        "aud": "explorer",
        "email": "alice@example.com",
        "iat": 1_000,
        "exp": 1_300,
        "jti": f"access-{version}",
        "events": {
            "urn:elcanotek:event:application-access": {
                "action": action,
                "version": version,
            }
        },
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


def test_access_token_verification_checks_signature_claims_and_version() -> None:
    private_key = Ed25519PrivateKey.generate()
    raw, public_key = _mint_access(private_key, version=7)

    event = verify_access_token(
        raw,
        issuer="https://auth.example.com",
        audience="explorer",
        public_keys=[public_key],
        now=1_010,
    )

    assert event == AccessProvisionEvent(
        event_id="access-7",
        subject="account-123",
        email="alice@example.com",
        issuer="https://auth.example.com",
        issued_at=1_000,
        version=7,
        allowed=True,
    )

    with pytest.raises(CentralAuthError):
        verify_access_token(
            raw,
            issuer="https://auth.example.com",
            audience="lens",
            public_keys=[public_key],
            now=1_010,
        )

    malformed, _ = _mint_access(private_key, version=True)
    with pytest.raises(CentralAuthError):
        verify_access_token(
            malformed,
            issuer="https://auth.example.com",
            audience="explorer",
            public_keys=[public_key],
            now=1_010,
        )


def test_access_provisioning_is_ordered_and_revocation_ends_sessions(
    store: CentralAuthStore,
) -> None:
    grant = AccessProvisionEvent(
        event_id="grant-2",
        subject="account-123",
        email="alice@example.com",
        issuer="https://auth.example.com",
        issued_at=1_000,
        version=2,
        allowed=True,
    )
    stale_revoke = AccessProvisionEvent(
        event_id="revoke-1",
        subject=grant.subject,
        email=grant.email,
        issuer=grant.issuer,
        issued_at=1_001,
        version=1,
        allowed=False,
    )
    revoke = AccessProvisionEvent(
        event_id="revoke-3",
        subject=grant.subject,
        email=grant.email,
        issuer=grant.issuer,
        issued_at=1_002,
        version=3,
        allowed=False,
    )

    assert store.apply_access_provisioning(grant, now=1_010)
    issued = store.create_session(grant.subject, grant.email, now=1_011)
    assert not store.apply_access_provisioning(stale_revoke, now=1_012)
    assert store.is_allowed(grant.email)

    assert store.apply_access_provisioning(revoke, now=1_013)
    assert not store.is_allowed(grant.email)
    assert store.get_identity(issued.token, now=1_014) is None
    assert not store.apply_access_provisioning(revoke, now=1_015)


def test_csrf_token_is_bound_to_the_app_session_secret() -> None:
    token = "browser-only-app-session-secret"
    csrf = csrf_token_for_session(token)

    assert verify_csrf_token(token, csrf)
    assert not verify_csrf_token("a-different-session", csrf)
    assert not verify_csrf_token(token, "")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _public_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode()


ID_TOKEN_KEY = Ed25519PrivateKey.generate()


def _mint_id_token(
    private_key: Ed25519PrivateKey = ID_TOKEN_KEY,
    *,
    header: dict | None = None,
    **overrides,
) -> str:
    """An id_token shaped exactly like Auth's token.SignIdentity output."""
    public = private_key.public_key().public_bytes_raw()
    now = int(time.time())
    claims = {
        "iss": "https://auth.example.com",
        "sub": "account-123",
        "aud": "explorer",
        "email": "Alice@Example.com",
        "iat": now,
        "exp": now + 300,
        "nonce": "expected-nonce",
        "auth_time": now,
        "amr": ["pwd"],
        "acr": "urn:elcanotek:loa:1",
    }
    claims.update(overrides)
    head = {
        "typ": "JWT",
        "alg": "EdDSA",
        "kid": _b64url(hashlib.sha256(public).digest()[:16]),
    }
    head.update(header or {})
    body = (
        _b64url(json.dumps(head, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    return f"{body}.{_b64url(private_key.sign(body.encode()))}"


def _token_response(id_token: str | None = None, **plain) -> dict:
    """Auth's /token body: the plain claims plus the signed id_token."""
    token = _mint_id_token() if id_token is None else id_token
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    return claims | plain | {"id_token": token}


def _static_keys(*private_keys: Ed25519PrivateKey):
    keys = [_public_b64(key) for key in private_keys or (ID_TOKEN_KEY,)]
    return lambda _raw: keys


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


def _exchange(monkeypatch, payload: dict, keys_for_token=None):
    monkeypatch.setattr(
        "app.central_auth._open_token_request",
        lambda *_args: _fake_response(payload),
    )
    return _client().exchange(
        code="code",
        code_verifier="v" * 43,
        expected_nonce="expected-nonce",
        keys_for_token=keys_for_token or _static_keys(),
    )


def test_code_exchange_authenticates_client_and_validates_nonce(monkeypatch) -> None:
    captured = {}

    def fake_open(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return _fake_response(_token_response())

    monkeypatch.setattr("app.central_auth._open_token_request", fake_open)

    principal = _client().exchange(
        code="single-use-code",
        code_verifier="pkce-verifier",
        expected_nonce="expected-nonce",
        keys_for_token=_static_keys(),
    )

    assert principal.subject == "account-123"
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


def test_identity_comes_from_the_signed_token_not_the_plain_claims(
    monkeypatch,
) -> None:
    payload = _token_response(sub="account-666", email="mallory@example.com")

    principal = _exchange(monkeypatch, payload)

    assert principal.subject == "account-123"
    assert principal.email == "alice@example.com"


@pytest.mark.parametrize(
    "payload",
    [
        {k: v for k, v in _token_response().items() if k != "id_token"},
        _token_response() | {"id_token": ""},
        _token_response() | {"id_token": 42},
        _token_response() | {"id_token": "not.a.jwt"},
    ],
    ids=["missing", "empty", "not-a-string", "garbage"],
)
def test_code_exchange_requires_an_id_token(monkeypatch, payload) -> None:
    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, payload)


def test_code_exchange_rejects_a_tampered_id_token(monkeypatch) -> None:
    head, body, signature = _mint_id_token().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["email"] = "mallory@example.com"
    forged = f"{head}.{_b64url(json.dumps(claims).encode())}.{signature}"

    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, _token_response(forged))


def test_code_exchange_rejects_a_token_from_an_unknown_key(monkeypatch) -> None:
    other = Ed25519PrivateKey.generate()

    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, _token_response(_mint_id_token(other)))


def test_code_exchange_rejects_a_known_kid_signed_by_another_key(monkeypatch) -> None:
    trusted = _public_b64(ID_TOKEN_KEY)
    kid = _b64url(hashlib.sha256(base64.b64decode(trusted)).digest()[:16])
    forged = _mint_id_token(Ed25519PrivateKey.generate(), header={"kid": kid})

    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, _token_response(forged))


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none"},
        {"alg": "HS256"},
        {"typ": "logout+jwt"},
        {"typ": "access+jwt"},
        {"kid": "\u00e9"},
        {"kid": 7},
        {"kid": None},
    ],
)
def test_code_exchange_rejects_the_wrong_alg_or_typ(monkeypatch, header) -> None:
    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, _token_response(_mint_id_token(header=header)))


@pytest.mark.parametrize(
    "claims",
    [
        {"nonce": "wrong"},
        {"nonce": "expected-nonc\u00e9"},
        {"aud": "lens"},
        {"aud": ["explorer"]},
        {"nonce": "\ud800"},
        {"iss": "https://other-auth.example.com"},
        {"iss": "https://auth.example.com/"},
        {"exp": int(time.time()) - 120},
        {"exp": "soon"},
        {"exp": True},
        {"iat": int(time.time()) + 600},
        {"sub": ""},
        {"email": "not-an-email"},
    ],
)
def test_code_exchange_checks_the_signed_claims(monkeypatch, claims) -> None:
    with pytest.raises(CentralAuthError, match="invalid"):
        _exchange(monkeypatch, _token_response(_mint_id_token(**claims)))


def test_code_exchange_tolerates_small_clock_skew(monkeypatch) -> None:
    token = _mint_id_token(exp=int(time.time()) - 10)

    principal = _exchange(monkeypatch, _token_response(token))

    assert principal.subject == "account-123"


def test_code_exchange_accepts_a_key_known_only_from_jwks(monkeypatch) -> None:
    rotated = Ed25519PrivateKey.generate()
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(rotated.public_key().public_bytes_raw()),
            }
        ]
    }
    fetched = []

    def fetch(url, _timeout):
        fetched.append(url)
        return json.dumps(jwks).encode()

    resolver = AuthKeyResolver(
        "https://auth.example.com", [_public_b64(ID_TOKEN_KEY)], fetch=fetch
    )

    principal = _exchange(
        monkeypatch,
        _token_response(_mint_id_token(rotated)),
        keys_for_token=resolver.keys_for_token,
    )

    assert principal.email == "alice@example.com"
    assert fetched == ["https://auth.example.com/jwks.json"]


def test_http_400_from_token_endpoint_is_a_rejected_code(monkeypatch) -> None:
    def refuse(*_args):
        raise urllib.error.HTTPError(
            "https://auth.example.com/token", 400, "Bad Request", {}, None
        )

    monkeypatch.setattr("app.central_auth._open_token_request", refuse)
    with pytest.raises(CodeExchangeRejectedError):
        _client().exchange(
            code="code",
            code_verifier="v" * 43,
            expected_nonce="n",
            keys_for_token=_static_keys(),
        )


def test_http_401_from_token_endpoint_is_an_outage_not_a_retry(monkeypatch) -> None:
    def refuse(*_args):
        raise urllib.error.HTTPError(
            "https://auth.example.com/token", 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr("app.central_auth._open_token_request", refuse)
    with pytest.raises(CentralAuthError) as excinfo:
        _client().exchange(
            code="code",
            code_verifier="v" * 43,
            expected_nonce="n",
            keys_for_token=_static_keys(),
        )
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


def _kid_token(private_key: Ed25519PrivateKey) -> str:
    """Only the header's kid matters to the resolver."""
    return _mint_id_token(private_key)


def _jwks(*private_keys: Ed25519PrivateKey) -> bytes:
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(key.public_key().public_bytes_raw()),
                }
                for key in private_keys
            ]
        }
    ).encode()


class _FakeJwks:
    def __init__(self, *private_keys: Ed25519PrivateKey) -> None:
        self.document = _jwks(*private_keys)
        self.fail = False
        self.calls = 0

    def __call__(self, _url, _timeout):
        self.calls += 1
        if self.fail:
            raise OSError("Auth is restarting")
        return self.document


def test_a_retired_jwks_key_stops_being_trusted_after_the_cache_window() -> None:
    clock = [10_000.0]
    retired = Ed25519PrivateKey.generate()
    jwks = _FakeJwks(retired)
    resolver = AuthKeyResolver(
        "https://auth.example.com",
        [_public_b64(ID_TOKEN_KEY)],
        fetch=jwks,
        now=lambda: clock[0],
    )
    assert _public_b64(retired) in resolver.keys_for_token(_kid_token(retired))

    jwks.document = _jwks(Ed25519PrivateKey.generate())
    clock[0] += 300
    assert _public_b64(retired) in resolver.keys_for_token(_kid_token(retired))

    clock[0] += 301
    assert _public_b64(retired) not in resolver.keys_for_token(_kid_token(retired))


def test_a_jwks_key_is_kept_when_the_refresh_fails() -> None:
    clock = [10_000.0]
    remote = Ed25519PrivateKey.generate()
    jwks = _FakeJwks(remote)
    resolver = AuthKeyResolver(
        "https://auth.example.com",
        [_public_b64(ID_TOKEN_KEY)],
        fetch=jwks,
        now=lambda: clock[0],
    )
    resolver.keys_for_token(_kid_token(remote))

    jwks.fail = True
    clock[0] += 3_600
    assert _public_b64(remote) in resolver.keys_for_token(_kid_token(remote))
    assert jwks.calls == 2


def test_a_static_key_never_waits_on_jwks() -> None:
    clock = [10_000.0]
    jwks = _FakeJwks(Ed25519PrivateKey.generate())
    resolver = AuthKeyResolver(
        "https://auth.example.com",
        [_public_b64(ID_TOKEN_KEY)],
        fetch=jwks,
        now=lambda: clock[0],
    )
    for _ in range(3):
        assert _public_b64(ID_TOKEN_KEY) in resolver.keys_for_token(
            _kid_token(ID_TOKEN_KEY)
        )
        clock[0] += 3_600
    assert jwks.calls == 0


def test_back_channel_tokens_refuse_a_non_ascii_kid() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = _public_b64(private_key)
    for minted, verify in (
        (_mint_logout(private_key)[0], verify_logout_token),
        (_mint_access(private_key)[0], verify_access_token),
    ):
        head, body, _signature = minted.split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=="))
        header["kid"] = "\u00e9"
        unsigned = f"{_b64url(json.dumps(header).encode())}.{body}"
        forged = f"{unsigned}.{_b64url(private_key.sign(unsigned.encode()))}"
        with pytest.raises(CentralAuthError):
            verify(
                forged,
                issuer="https://auth.example.com",
                audience="explorer",
                public_keys=[public_key],
                now=1_010,
            )
