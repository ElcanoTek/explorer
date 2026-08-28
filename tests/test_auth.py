# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Tests for the unified Elcano cookie auth (app/auth.py).

These exercise the security-critical verifier: a token minted with the
auth service's signing key must verify, and everything else (expired,
tampered, foreign key, missing) must be rejected.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import auth


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _pub_b64(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _mint(priv: Ed25519PrivateKey, **claims) -> str:
    """Mint an elcano_auth token exactly like auth-server does."""
    payload = {
        "email": "alice@elcanotek.com",
        "tenant": "elcanotek.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    payload.update(claims)
    body = _b64url(json.dumps(payload).encode())
    sig = priv.sign(body.encode())
    return f"{body}.{_b64url(sig)}"


@pytest.fixture()
def signing_key(monkeypatch) -> Ed25519PrivateKey:
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", _pub_b64(priv))
    return priv


def test_valid_cookie_verifies(signing_key):
    sess = auth.verify_session(_mint(signing_key))
    assert sess is not None
    assert sess["email"] == "alice@elcanotek.com"
    assert sess["tenant"] == "elcanotek.com"


def test_expired_cookie_rejected(signing_key):
    assert auth.verify_session(_mint(signing_key, exp=int(time.time()) - 1)) is None


def test_missing_email_rejected(signing_key):
    assert auth.verify_session(_mint(signing_key, email="")) is None


def test_tampered_payload_rejected(signing_key):
    token = _mint(signing_key)
    body, sig = token.split(".")
    # Flip a byte in the payload; signature no longer matches.
    bad = (
        base64.urlsafe_b64encode(b'{"email":"mallory@evil.com","exp":9999999999}')
        .decode()
        .rstrip("=")
    )
    assert auth.verify_session(f"{bad}.{sig}") is None


def test_foreign_key_rejected(signing_key):
    # A token validly signed by a DIFFERENT key must not verify.
    other = Ed25519PrivateKey.generate()
    assert auth.verify_session(_mint(other)) is None


def test_garbage_and_empty_rejected(signing_key):
    for bad in (None, "", "not-a-token", "only-one-part", "a.b.c"):
        assert auth.verify_session(bad) is None


def test_no_pubkey_configured_rejects_everything(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    token = _mint(priv)
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", "")
    assert auth.verify_session(token) is None


def test_current_identity_reads_cookie(signing_key):
    class FakeRequest:
        def __init__(self, cookies):
            self.cookies = cookies

    assert auth.current_identity(FakeRequest({})) is None
    ident = auth.current_identity(
        FakeRequest({auth.AUTH_COOKIE_NAME: _mint(signing_key)})
    )
    assert ident is not None and ident["email"] == "alice@elcanotek.com"


def test_login_redirect_points_at_auth_with_return_to():
    class FakeRequest:
        url = "https://explorer.elcanotek.com/email?s3_key=x"

    resp = auth.login_redirect(FakeRequest())
    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith(auth.AUTH_LOGIN_URL + "/?return_to=")
    assert "explorer.elcanotek.com" in loc
