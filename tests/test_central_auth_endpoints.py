# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Browser-level behavior for Explorer as a central-auth client."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import main
from app.auth import CentralAuthProvider
from app.central_auth import (
    CENTRAL_AUTH_COOKIE_NAME,
    AuthenticatedPrincipal,
    CentralAuthClient,
    CentralAuthError,
    CentralAuthStore,
    CodeExchangeRejectedError,
)


class FakeAuthClient:
    exchange_error: Exception | None = None
    exchanged_codes: list[str] = []
    email = "alice@example.com"
    signing_key: Ed25519PrivateKey | None = None

    def __init__(self, *args, **kwargs) -> None:
        pass

    @classmethod
    def from_env(cls):
        return cls()

    issuer_url = "https://auth.example.com"
    client_id = "explorer"

    def authorization_url(self, *, state: str, code_challenge: str, nonce: str) -> str:
        query = (
            f"response_type=code&client_id=explorer&"
            f"redirect_uri=https%3A%2F%2Fexplorer.example.com%2Fauth%2Fcallback&"
            f"scope=email&state={state}&code_challenge={code_challenge}&"
            f"code_challenge_method=S256&nonce={nonce}"
        )
        return f"https://auth.example.com/authorize?{query}"

    def exchange(
        self, *, code: str, code_verifier: str, expected_nonce: str
    ) -> AuthenticatedPrincipal:
        type(self).exchanged_codes.append(code)
        if type(self).exchange_error:
            raise type(self).exchange_error
        return AuthenticatedPrincipal(
            subject="account-123", email=type(self).email, nonce=expected_nonce
        )


@pytest.fixture(autouse=True)
def reset_fake_client() -> None:
    FakeAuthClient.exchange_error = None
    FakeAuthClient.exchanged_codes = []
    FakeAuthClient.email = "alice@example.com"
    FakeAuthClient.signing_key = None


@pytest.fixture()
def central_client(monkeypatch, tmp_path, asgi_client):
    db_path = tmp_path / "access.db"
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "central")
    monkeypatch.setenv("EXPLORER_ACCESS_DB", str(db_path))
    monkeypatch.setenv(
        "EXPLORER_SESSION_SECRET", "test-session-secret-with-32-bytes-minimum"
    )
    monkeypatch.setenv("EXPLORER_PUBLIC_URL", "https://explorer.example.com")
    monkeypatch.setenv("AUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("AUTH_CLIENT_ID", "explorer")
    monkeypatch.setenv(
        "AUTH_CLIENT_SECRET", "a-test-client-secret-with-at-least-32-bytes"
    )
    private_key = Ed25519PrivateKey.generate()
    FakeAuthClient.signing_key = private_key
    monkeypatch.setenv(
        "AUTH_SIGNING_PUBKEY",
        base64.b64encode(private_key.public_key().public_bytes_raw()).decode(),
    )
    monkeypatch.setattr(main, "CentralAuthClient", FakeAuthClient)
    monkeypatch.setattr(
        main,
        "settings",
        replace(
            main.settings,
            session_secret="test-session-secret-with-32-bytes-minimum",
        ),
    )
    store = CentralAuthStore(db_path)
    store.grant_access("alice@example.com")
    with asgi_client(main.app, base_url="https://explorer.example.com") as client:
        yield client, store


def begin_login(client, *, next_path: str = "/") -> tuple[str, str]:
    response = client.get(
        "/auth/login", params={"next": next_path}, follow_redirects=False
    )
    assert response.status_code == 303
    login_cookie = response.headers["set-cookie"]
    assert "explorer_ui=" in login_cookie
    assert "httponly" in login_cookie.lower()
    assert "secure" in login_cookie.lower()
    assert "samesite=lax" in login_cookie.lower()
    assert "domain=" not in login_cookie.lower()
    parsed = urlsplit(response.headers["location"])
    query = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.example.com"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["explorer"]
    assert query["redirect_uri"] == ["https://explorer.example.com/auth/callback"]
    assert query["scope"] == ["email"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) >= 43
    assert "a-test-client-secret" not in response.headers["location"]
    return query["state"][0], query["nonce"][0]


def complete_login(client, *, next_path: str = "/"):
    state, _nonce = begin_login(client, next_path=next_path)
    return client.get(
        "/auth/callback",
        params={"code": "one-time-code", "state": state},
        follow_redirects=False,
    )


def test_protected_request_starts_local_login_transaction(central_client) -> None:
    client, _store = central_client

    response = client.get("/email?s3_key=emails%2Fone", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/login?next=")


def test_callback_issues_app_scoped_cookie_for_allowlisted_email(
    central_client,
) -> None:
    client, _store = central_client

    response = complete_login(client, next_path="/?mode=view")

    assert response.status_code == 303
    assert response.headers["location"] == "/?mode=view"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert FakeAuthClient.exchanged_codes == ["one-time-code"]
    cookie = response.headers["set-cookie"]
    assert f"{CENTRAL_AUTH_COOKIE_NAME}=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=43200" in cookie
    assert "Domain=" not in cookie


def test_callback_rejects_mismatched_state_without_exchanging_code(
    central_client,
) -> None:
    client, _store = central_client
    begin_login(client)

    response = client.get(
        "/auth/callback",
        params={"code": "stolen-code", "state": "wrong-state"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert FakeAuthClient.exchanged_codes == []


def test_callback_denies_authenticated_but_unlisted_email(central_client) -> None:
    client, _store = central_client
    FakeAuthClient.email = "bob@example.com"

    response = complete_login(client)

    assert response.status_code == 403
    assert CENTRAL_AUTH_COOKIE_NAME not in client.cookies


def test_callback_fails_closed_when_code_exchange_fails(central_client) -> None:
    client, _store = central_client
    FakeAuthClient.exchange_error = CentralAuthError("auth unavailable")

    response = complete_login(client)

    assert response.status_code == 502
    assert CENTRAL_AUTH_COOKIE_NAME not in client.cookies


def test_rejected_code_is_a_retry_not_an_outage(central_client) -> None:
    client, _store = central_client
    FakeAuthClient.exchange_error = CodeExchangeRejectedError("code consumed")

    response = complete_login(client)

    assert response.status_code == 400
    assert "Try again" in response.text
    assert CENTRAL_AUTH_COOKIE_NAME not in client.cookies


def test_non_ascii_state_is_rejected_not_crashed(central_client) -> None:
    client, _store = central_client
    begin_login(client)

    response = client.get(
        "/auth/callback",
        params={"code": "irrelevant", "state": "\u00e9tat"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert FakeAuthClient.exchanged_codes == []


def test_external_next_url_is_not_used_after_callback(central_client) -> None:
    client, _store = central_client

    response = complete_login(client, next_path="https://evil.example/steal")

    assert response.headers["location"] == "/"


@pytest.mark.parametrize("unsafe_next", ["/\\evil.example/steal", "//evil.example"])
def test_authority_like_next_url_is_not_used_after_callback(
    central_client, unsafe_next
) -> None:
    client, _store = central_client

    response = complete_login(client, next_path=unsafe_next)

    assert response.headers["location"] == "/"


def test_central_mode_rejects_legacy_and_old_local_cookies(central_client) -> None:
    client, _store = central_client
    client.cookies.set("elcano_auth", "legacy.signed-token")
    client.cookies.set("__Host-explorer_session", "old-local-session")

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/login?next=")


def test_logout_requires_csrf_and_revokes_only_explorer_session(
    central_client,
) -> None:
    client, store = central_client
    complete_login(client)
    raw_token = client.cookies.get(CENTRAL_AUTH_COOKIE_NAME)
    assert raw_token
    csrf = store.csrf_token(raw_token)

    assert client.post("/logout", follow_redirects=False).status_code == 403
    response = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/signed-out"
    assert store.get_identity(raw_token) is None


def test_signed_backchannel_logout_revokes_all_sessions_for_subject(
    central_client,
) -> None:
    client, store = central_client
    complete_login(client)
    raw_token = client.cookies.get(CENTRAL_AUTH_COOKIE_NAME)
    assert raw_token and FakeAuthClient.signing_key

    public = FakeAuthClient.signing_key.public_key().public_bytes_raw()
    kid = (
        base64.urlsafe_b64encode(hashlib.sha256(public).digest()[:16])
        .rstrip(b"=")
        .decode()
    )

    def encode(value):
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

    header = {"typ": "logout+jwt", "alg": "EdDSA", "kid": kid}
    claims = {
        "iss": "https://auth.example.com",
        "sub": "account-123",
        "aud": "explorer",
        "iat": int(main.time.time()) if hasattr(main, "time") else 1_000,
        "exp": 2_000_000_000,
        "jti": "event-123",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    body = f"{encode(header)}.{encode(claims)}"
    signature = (
        base64.urlsafe_b64encode(FakeAuthClient.signing_key.sign(body.encode()))
        .rstrip(b"=")
        .decode()
    )
    raw_logout = f"{body}.{signature}"

    response = client.post(
        "/auth/backchannel-logout", data={"logout_token": raw_logout}
    )

    assert response.status_code == 204
    assert store.get_identity(raw_token) is None
    assert (
        client.post(
            "/auth/backchannel-logout", data={"logout_token": raw_logout}
        ).status_code
        == 204
    )


def test_auth_client_requires_https_and_a_strong_client_secret(monkeypatch) -> None:
    monkeypatch.setenv("AUTH_ISSUER_URL", "http://auth.example.com")
    monkeypatch.setenv("AUTH_CLIENT_SECRET", "short")

    with pytest.raises(RuntimeError, match="HTTPS"):
        CentralAuthClient.from_env()


def test_backchannel_logout_rejects_oversized_request(central_client) -> None:
    client, _store = central_client
    response = client.post(
        "/auth/backchannel-logout", data={"logout_token": "x" * 20_001}
    )
    assert response.status_code == 413


def test_central_mode_refuses_to_start_without_the_auth_public_key(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "central")
    monkeypatch.setenv("EXPLORER_ACCESS_DB", str(tmp_path / "access.db"))
    monkeypatch.setenv("AUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("EXPLORER_PUBLIC_URL", "https://explorer.example.com")
    monkeypatch.setenv(
        "AUTH_CLIENT_SECRET", "a-test-client-secret-with-at-least-32-bytes"
    )
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", "")
    monkeypatch.delenv("AUTH_SIGNING_PREVIOUS_PUBKEYS", raising=False)
    with pytest.raises(RuntimeError, match="AUTH_SIGNING_PUBKEY"):
        CentralAuthProvider.from_env(FakeAuthClient)
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", "not-32-bytes")
    with pytest.raises(RuntimeError, match="AUTH_SIGNING_PUBKEY"):
        CentralAuthProvider.from_env(FakeAuthClient)


def test_pages_carry_nonce_csp_and_other_responses_a_closed_one(central_client) -> None:
    import re

    client, _store = central_client
    complete_login(client)

    page = client.get("/", follow_redirects=False)
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    match = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_-]+)'", csp)
    assert match, csp
    nonce = match.group(1)
    assert "default-src 'self'" in csp
    assert "style-src 'self';" in csp
    assert "img-src 'self' data: https:" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action" not in csp
    body = page.text
    assert "<script>" not in body
    assert body.count(f'<script nonce="{nonce}">') >= 1
    assert not re.search(r' on[a-z]+="', body)
    assert ' style="' not in body

    second = client.get("/", follow_redirects=False)
    assert second.headers["content-security-policy"] != csp

    health = client.get("/health")
    assert health.headers["content-security-policy"] == main.CSP_NON_PAGE
