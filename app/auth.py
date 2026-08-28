# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Cookie auth against an external magic-link sign-in service.

Explorer owns no login of its own. It verifies the session cookie minted by
a separate auth service using that service's Ed25519 **public** key
(``AUTH_SIGNING_PUBKEY``) and bounces unauthenticated browsers to
``AUTH_LOGIN_URL``, which signs them back via ``?return_to=``.

Token format::

    base64url(payload_json) + "." + base64url(ed25519_sig)

where the signature is over the base64url body *string*. The payload is
``{"email", "tenant", "iat", "exp"}``; we read ``email`` and ``exp``.

Any service that mints that shape works. The public key can only verify,
never sign, so it is safe to distribute in config and a leak of it cannot
forge a session.
"""

from __future__ import annotations

import base64
import json
import os
import time
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Request
from fastapi.responses import RedirectResponse

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
        raw = base64.b64decode(src)
    except Exception:
        return None
    if len(raw) != 32:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
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
    except Exception:
        return None
    try:
        key.verify(signature, body.encode("utf-8"))
    except Exception:
        # cryptography raises InvalidSignature; treat any failure as invalid.
        return None

    try:
        payload = json.loads(_b64url(body))
    except Exception:
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
