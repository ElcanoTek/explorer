# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Pluggable authentication for Explorer deployments.

``elcano`` mode preserves the external magic-link service: Explorer verifies
its Ed25519-signed cookie with ``AUTH_SIGNING_PUBKEY``. ``local`` mode owns a
deployment-local username/password store and opaque, revocable sessions.

Token format::

    base64url(payload_json) + "." + base64url(ed25519_sig)

where the signature is over the base64url body *string*. The payload is
``{"email", "tenant", "iat", "exp"}``; we read ``email`` and ``exp``.

Any service that mints the documented signed-cookie shape works with Elcano
mode. The public key can only verify, never sign, so a leak cannot forge a
session.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import time
from typing import Protocol
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request
from fastapi.responses import RedirectResponse

from app.local_auth import (
    LOCAL_AUTH_COOKIE_NAME,
    LocalAuthStore,
    LocalIdentity,
    csrf_token_for_session,
)

AUTH_COOKIE_NAME = os.getenv("AUTH_COOKIE_NAME", "elcano_auth")
# Where unauthenticated browsers are sent. auth bounces them back via
# ?return_to= after a successful magic-link sign-in.
AUTH_LOGIN_URL = os.getenv("AUTH_LOGIN_URL", "https://auth.elcanotek.com").rstrip("/")

# Parsed public key, cached and recomputed only when the env value changes
# (so a test or a key rotation that updates AUTH_SIGNING_PUBKEY is picked up
# without a process restart, while steady-state requests pay nothing).
_key_cache: dict[str, object] = {"src": None, "key": None}


def _parse_public_key(src: str) -> Ed25519PublicKey | None:
    if not src:
        return None
    try:
        raw = base64.b64decode(src, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return None


def _public_key() -> Ed25519PublicKey | None:
    src = os.getenv("AUTH_SIGNING_PUBKEY", "").strip()
    if src != _key_cache["src"]:
        _key_cache["src"] = src
        _key_cache["key"] = _parse_public_key(src)
    return _key_cache["key"]  # type: ignore[return-value]


def _b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify_session(token: str | None) -> dict | None:
    """Return the session payload for a valid ``elcano_auth`` value, else None.

    Every failure mode (no key configured, malformed, bad signature, expired,
    missing email) returns None — callers treat them all as "logged out".
    """
    key = _public_key()
    if key is None or not token:
        return None

    dot = token.find(".")
    if dot < 1 or dot == len(token) - 1:
        return None
    body, sig = token[:dot], token[dot + 1 :]

    try:
        signature = _b64url(sig)
    except (binascii.Error, ValueError):
        return None
    try:
        key.verify(signature, body.encode("utf-8"))
    except InvalidSignature:
        # cryptography raises InvalidSignature; treat any failure as invalid.
        return None

    try:
        payload = json.loads(_b64url(body))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    email = payload.get("email")
    exp = payload.get("exp")
    if not isinstance(email, str) or not email:
        return None
    if not isinstance(exp, (int, float)) or exp <= time.time():
        return None

    return {"email": email, "tenant": payload.get("tenant") or "", "exp": int(exp)}


def current_identity(request: Request) -> dict | None:
    """The verified identity for this request, or None if not signed in."""
    return verify_session(request.cookies.get(AUTH_COOKIE_NAME))


def login_redirect(request: Request) -> RedirectResponse:
    """Send the browser to the auth service, signed back to this URL."""
    return_to = quote(str(request.url), safe="")
    return RedirectResponse(
        url=f"{AUTH_LOGIN_URL}/?return_to={return_to}", status_code=303
    )


class AuthProvider(Protocol):
    """Common request-facing behavior shared by every auth mode."""

    mode: str

    def identity(self, request: Request) -> dict | LocalIdentity | None: ...

    def unauthenticated_response(self, request: Request) -> RedirectResponse: ...


class ElcanoAuthProvider:
    """Adapter around the existing Elcano magic-link cookie verifier."""

    mode = "elcano"

    def identity(self, request: Request) -> dict | None:
        return current_identity(request)

    def unauthenticated_response(self, request: Request) -> RedirectResponse:
        return login_redirect(request)

    def logout_response(self, request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url=f"{AUTH_LOGIN_URL}/logout", status_code=303)


class LocalAuthProvider:
    """Opaque-cookie adapter backed by a deployment-local SQLite store."""

    mode = "local"

    def __init__(self, store: LocalAuthStore, *, cookie_secure: bool = True) -> None:
        self.store = store
        self.cookie_secure = cookie_secure

    @classmethod
    def from_env(cls) -> LocalAuthProvider:
        raw_secure = os.getenv("EXPLORER_AUTH_COOKIE_SECURE", "1")
        cookie_secure = raw_secure.strip().lower() in {"1", "true", "yes", "on"}
        if not cookie_secure:
            raise RuntimeError(
                "Local auth requires Secure cookies and an HTTPS deployment"
            )
        return cls(LocalAuthStore.from_env(), cookie_secure=cookie_secure)

    def identity(self, request: Request) -> LocalIdentity | None:
        return self.store.get_identity(request.cookies.get(LOCAL_AUTH_COOKIE_NAME))

    def unauthenticated_response(self, request: Request) -> RedirectResponse:
        return RedirectResponse(url="/login", status_code=303)

    def set_session_cookie(self, response: RedirectResponse, token: str) -> None:
        response.set_cookie(
            key=LOCAL_AUTH_COOKIE_NAME,
            value=token,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
            path="/",
        )

    def clear_session_cookie(self, response: RedirectResponse) -> None:
        response.delete_cookie(
            key=LOCAL_AUTH_COOKIE_NAME,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
            path="/",
        )

    def csrf_token(self, request: Request) -> str:
        token = request.cookies.get(LOCAL_AUTH_COOKIE_NAME, "")
        return csrf_token_for_session(token) if token else ""


def build_auth_provider() -> AuthProvider:
    # Defaulting an existing installation to Elcano preserves its current
    # fail-closed behavior: without the signing key, no cookie can verify.
    mode = os.getenv("EXPLORER_AUTH_MODE", "elcano").strip().lower()
    if mode == "elcano":
        return ElcanoAuthProvider()
    if mode == "local":
        return LocalAuthProvider.from_env()
    raise RuntimeError("EXPLORER_AUTH_MODE must be either 'elcano' or 'local'")
