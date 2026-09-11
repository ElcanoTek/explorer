# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Pluggable authentication for Explorer deployments.

``elcano`` mode preserves the external magic-link service unchanged.
``central`` mode uses the new central password auth service, then applies an
Explorer-local email allowlist and issues an app-scoped opaque session.

The preserved Elcano cookie format is::

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
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Protocol
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request
from fastapi.responses import RedirectResponse

from app.central_auth import (
    CENTRAL_AUTH_COOKIE_NAME,
    LOGIN_TRANSACTION_SECONDS,
    AuthenticatedPrincipal,
    AuthTransactionError,
    CentralAuthClient,
    CentralAuthStore,
    CentralIdentity,
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
    cookie_name = os.getenv("AUTH_COOKIE_NAME", AUTH_COOKIE_NAME)
    return verify_session(request.cookies.get(cookie_name))


def login_redirect(request: Request) -> RedirectResponse:
    """Send the browser to the auth service, signed back to this URL."""
    return_to = quote(str(request.url), safe="")
    login_url = os.getenv("AUTH_LOGIN_URL", AUTH_LOGIN_URL).rstrip("/")
    return RedirectResponse(url=f"{login_url}/?return_to={return_to}", status_code=303)


class AuthProvider(Protocol):
    """Common request-facing behavior shared by every auth mode."""

    mode: str

    def identity(self, request: Request) -> dict | CentralIdentity | None: ...

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
        login_url = os.getenv("AUTH_LOGIN_URL", AUTH_LOGIN_URL).rstrip("/")
        return RedirectResponse(url=f"{login_url}/logout", status_code=303)


class CentralAuthProvider:
    """Central SSO client with local authorization and app-only sessions."""

    mode = "central"

    def __init__(
        self,
        store: CentralAuthStore,
        client: CentralAuthClient,
        *,
        cookie_secure: bool = True,
    ) -> None:
        self.store = store
        self.client = client
        self.cookie_secure = cookie_secure
        self.cookie_name = (
            CENTRAL_AUTH_COOKIE_NAME if cookie_secure else "explorer_session"
        )

    @classmethod
    def from_env(
        cls, client_factory: type[CentralAuthClient] = CentralAuthClient
    ) -> CentralAuthProvider:
        raw_secure = os.getenv("EXPLORER_AUTH_COOKIE_SECURE", "1")
        cookie_secure = raw_secure.strip().lower() in {"1", "true", "yes", "on"}
        raw_ui_secure = os.getenv("EXPLORER_UI_COOKIE_SECURE", "1")
        ui_cookie_secure = raw_ui_secure.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        allow_insecure = os.getenv("AUTH_ALLOW_INSECURE_HTTP", "0").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if (not cookie_secure or not ui_cookie_secure) and not allow_insecure:
            raise RuntimeError(
                "Central auth requires Secure app and UI cookies; insecure HTTP is only allowed for development"
            )
        client = client_factory.from_env()
        store = CentralAuthStore.from_env()
        return cls(
            store,
            client,
            cookie_secure=cookie_secure,
        )

    def identity(self, request: Request) -> CentralIdentity | None:
        return self.store.get_identity(request.cookies.get(self.cookie_name))

    def unauthenticated_response(self, request: Request) -> RedirectResponse:
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        if len(target) > 2048:
            target = "/"
        return RedirectResponse(
            url=f"/auth/login?next={quote(target, safe='')}", status_code=303
        )

    def begin_login(self, request: Request, next_path: str) -> RedirectResponse:
        if len(next_path) > 2048:
            next_path = "/"
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        request.session["central_auth_transaction"] = {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "next": next_path,
            "created_at": int(time.time()),
        }
        response = RedirectResponse(
            self.client.authorization_url(
                state=state, code_challenge=challenge, nonce=nonce
            ),
            status_code=303,
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def complete_login(
        self, request: Request, *, code: str, state: str
    ) -> tuple[AuthenticatedPrincipal, str, str]:
        transaction = request.session.pop("central_auth_transaction", None)
        if not isinstance(transaction, dict):
            raise AuthTransactionError("The sign-in transaction is missing or expired")
        expected_state = transaction.get("state")
        verifier = transaction.get("verifier")
        nonce = transaction.get("nonce")
        next_path = transaction.get("next")
        created_at = transaction.get("created_at")
        now = int(time.time())
        if (
            not isinstance(expected_state, str)
            or not isinstance(verifier, str)
            or not isinstance(nonce, str)
            or not isinstance(next_path, str)
            or not isinstance(created_at, int)
            or not hmac.compare_digest(expected_state, state)
            or now < created_at
            or now - created_at > LOGIN_TRANSACTION_SECONDS
        ):
            raise AuthTransactionError("The sign-in transaction is invalid or expired")
        principal = self.client.exchange(
            code=code, code_verifier=verifier, expected_nonce=nonce
        )
        issued = self.store.create_session(principal.subject, principal.email)
        return principal, issued.token, next_path

    def set_session_cookie(self, response: RedirectResponse, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
            path="/",
            max_age=self.store.absolute_seconds,
        )

    def clear_session_cookie(self, response: RedirectResponse) -> None:
        response.delete_cookie(
            key=self.cookie_name,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
            path="/",
        )

    def csrf_token(self, request: Request) -> str:
        token = request.cookies.get(self.cookie_name, "")
        return self.store.csrf_token(token) if token else ""


def build_auth_provider(
    client_factory: type[CentralAuthClient] = CentralAuthClient,
) -> AuthProvider:
    # Defaulting an existing installation to Elcano preserves its current
    # fail-closed behavior: without the signing key, no cookie can verify.
    mode = os.getenv("EXPLORER_AUTH_MODE", "elcano").strip().lower()
    if mode == "elcano":
        return ElcanoAuthProvider()
    if mode == "central":
        return CentralAuthProvider.from_env(client_factory)
    raise RuntimeError("EXPLORER_AUTH_MODE must be either 'elcano' or 'central'")
