# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Central sign-in client, Explorer allowlist, and app-scoped sessions.

Passwords and primary login sessions belong to the central auth service.
Explorer receives a short-lived, one-time authorization code, exchanges it
over a TLS backchannel, applies its deployment-local email allowlist, and then
issues an opaque cookie that is useful only to this Explorer instance.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CENTRAL_AUTH_COOKIE_NAME = "__Host-explorer_session"
# Application sessions are deliberately short. Expiry costs the user only a
# redirect: the code handoff signs them back in silently while the 30-day
# central Auth session is live. The short limit bounds a stolen Explorer
# cookie and forces a daily re-check with Auth that the account is still
# enabled. One day absolute, 12 hours idle is the Elcano convention for every
# application session (owner decision 2026-09-15; see Auth's
# docs/AUTH_V2_IMPLEMENTATION.md "Application session conventions").
DEFAULT_IDLE_SECONDS = 12 * 60 * 60
DEFAULT_ABSOLUTE_SECONDS = 24 * 60 * 60
# How often a validated session rewrites last_seen_at / idle_expires_at. Every
# request reads the session; only a request more than this long after the
# previous touch writes. The idle limit therefore behaves as "12 hours minus
# at most one minute", never longer, and a page's burst of requests costs one
# SQLite write instead of one per request. One minute is the convention for
# every Elcano service with its own sessions (Auth, Explorer, Lens, and
# anything built later); keep it a constant, not a setting.
SESSION_TOUCH_SECONDS = 60
LOGIN_TRANSACTION_SECONDS = 10 * 60
SCHEMA_VERSION = 2
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
REVOCATION_EVENT_RETENTION_SECONDS = 7 * 24 * 60 * 60


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a client credential through a token-endpoint redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_token_request(request: urllib.request.Request, timeout: float):
    return urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout)


class CentralAuthError(Exception):
    """A safe, expected failure while completing central authentication."""


class AccessDeniedError(CentralAuthError):
    """The authenticated email is not enabled for this Explorer instance."""


class AuthTransactionError(CentralAuthError):
    """The browser callback did not match a live login transaction."""


class CodeExchangeRejectedError(CentralAuthError):
    """The auth service refused the code: expired, replayed, or superseded.

    This is the user's problem to retry, not an outage: a second tab, a slow
    click, or a stale bookmark produces it. Callers should say "try again",
    not "the service is unavailable".
    """


# Tolerated skew between this host's clock and the auth service's when
# checking the assertion expiry. The assertion lives five minutes.
CLOCK_SKEW_SECONDS = 60


def _constant_time_equal(expected: str, actual: str) -> bool:
    """compare_digest on str raises TypeError for non-ASCII; compare bytes."""
    return hmac.compare_digest(expected.encode("utf-8"), actual.encode("utf-8"))


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    email: str
    nonce: str


@dataclass(frozen=True)
class CentralIdentity:
    subject: str
    email: str
    provider: str = "central"


@dataclass(frozen=True)
class AccessEntry:
    email: str
    enabled: bool
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class IssuedSession:
    token: str
    token_hash: str


@dataclass(frozen=True)
class LogoutEvent:
    event_id: str
    subject: str
    issuer: str
    issued_at: int


def _decode_b64url(segment: str) -> bytes:
    if not segment or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in segment
    ):
        raise CentralAuthError("The logout token was invalid")
    try:
        return base64.b64decode(
            segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise CentralAuthError("The logout token was invalid") from exc


def verify_logout_token(
    raw: str,
    *,
    issuer: str,
    audience: str,
    public_keys: list[str],
    now: int | None = None,
) -> LogoutEvent:
    """Verify one OIDC back-channel logout token and return its replay key."""
    if len(raw) > 16_384:
        raise CentralAuthError("The logout token was invalid")
    parts = raw.split(".")
    if len(parts) != 3:
        raise CentralAuthError("The logout token was invalid")
    try:
        header = json.loads(_decode_b64url(parts[0]))
        claims = json.loads(_decode_b64url(parts[1]))
        signature = _decode_b64url(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CentralAuthError("The logout token was invalid") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise CentralAuthError("The logout token was invalid")
    if header.get("typ") != "logout+jwt" or header.get("alg") != "EdDSA":
        raise CentralAuthError("The logout token was invalid")

    verified = False
    for encoded_key in public_keys:
        try:
            raw_key = base64.b64decode(encoded_key.strip(), validate=True)
            if len(raw_key) != 32:
                continue
            kid = (
                base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest()[:16])
                .rstrip(b"=")
                .decode()
            )
            if not hmac.compare_digest(str(header.get("kid", "")), kid):
                continue
            Ed25519PublicKey.from_public_bytes(raw_key).verify(
                signature, f"{parts[0]}.{parts[1]}".encode("ascii")
            )
            verified = True
            break
        except (ValueError, InvalidSignature, UnicodeEncodeError):
            continue
    if not verified:
        raise CentralAuthError("The logout token was invalid")

    timestamp = int(time.time() if now is None else now)
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    subject = claims.get("sub")
    event_id = claims.get("jti")
    token_issuer = claims.get("iss")
    events = claims.get("events")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at + CLOCK_SKEW_SECONDS <= timestamp
        or not isinstance(token_issuer, str)
        or token_issuer.rstrip("/") != issuer.rstrip("/")
        or claims.get("aud") != audience
        or not isinstance(subject, str)
        or not subject
        or len(subject) > 255
        or not isinstance(event_id, str)
        or not event_id
        or len(event_id) > 255
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or issued_at <= 0
        or issued_at > timestamp + CLOCK_SKEW_SECONDS
        or not isinstance(events, dict)
        or not isinstance(events.get(BACKCHANNEL_LOGOUT_EVENT), dict)
        or "nonce" in claims
    ):
        raise CentralAuthError("The logout token was invalid")
    return LogoutEvent(
        event_id=event_id,
        subject=subject,
        issuer=issuer.rstrip("/"),
        issued_at=issued_at,
    )


def auth_signing_public_keys() -> list[str]:
    """Statically configured keys: AUTH_SIGNING_PUBKEY plus previous keys."""
    keys = [os.getenv("AUTH_SIGNING_PUBKEY", "")]
    keys.extend(os.getenv("AUTH_SIGNING_PREVIOUS_PUBKEYS", "").split(","))
    return [key.strip() for key in keys if key.strip()]


JWKS_CACHE_SECONDS = 10 * 60
JWKS_MIN_REFRESH_SECONDS = 60
MAX_JWKS_BYTES = 64 * 1024


def _fetch_jwks(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.build_opener(_NoRedirect).open(
        request, timeout=timeout
    ) as response:
        raw = response.read(MAX_JWKS_BYTES + 1)
    if len(raw) > MAX_JWKS_BYTES:
        raise CentralAuthError("The JWKS document was too large")
    return raw


class AuthKeyResolver:
    """Auth's Ed25519 public keys: static env keys plus Auth's published JWKS.

    Auth rotates its signing key by publishing the new key alongside the old
    one at /jwks.json. Reading that document here makes rotation a one-sided
    change on Auth instead of an env edit on every application host. Static
    keys stay as the bootstrap and offline fallback: the resolver never
    depends on Auth being reachable to verify a token whose key is already
    known, and a fetch failure keeps whatever was cached.

    Keys are returned in the base64 form verify_logout_token expects.
    """

    def __init__(
        self,
        issuer_url: str,
        static_keys: list[str],
        *,
        fetch=None,
        timeout_seconds: float = 5,
        now=time.time,
    ) -> None:
        self.jwks_url = issuer_url.rstrip("/") + "/jwks.json"
        self.static_keys = list(static_keys)
        # Looked up at call time when None so tests can replace the module
        # function and production never captures a stale reference.
        self._fetch = fetch
        self._timeout = timeout_seconds
        self._now = now
        self._remote_keys: list[str] = []
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None

    def public_keys(self) -> list[str]:
        if (
            self._fetched_at is None
            or self._now() - self._fetched_at > JWKS_CACHE_SECONDS
        ):
            self.refresh()
        seen: set[str] = set()
        out: list[str] = []
        for key in self.static_keys + self._remote_keys:
            if key not in seen:
                seen.add(key)
                out.append(key)
        return out

    def refresh(self, *, force: bool = False) -> bool:
        """Fetch the JWKS; returns True when the cache was updated.

        Rate-limited so a flood of tokens with unknown kids cannot turn this
        into a request amplifier against Auth.
        """
        now = self._now()
        if (
            not force
            and self._last_attempt is not None
            and now - self._last_attempt < JWKS_MIN_REFRESH_SECONDS
        ):
            return False
        self._last_attempt = now
        fetcher = self._fetch if self._fetch is not None else _fetch_jwks
        try:
            raw = fetcher(self.jwks_url, self._timeout)
            document = json.loads(raw)
        except (
            CentralAuthError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
        ):
            return False
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            return False
        parsed: list[str] = []
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("kty") != "OKP"
                or entry.get("crv") != "Ed25519"
                or not isinstance(entry.get("x"), str)
            ):
                continue
            try:
                raw_key = base64.urlsafe_b64decode(
                    entry["x"] + "=" * (-len(entry["x"]) % 4)
                )
            except (ValueError, binascii.Error):
                continue
            if len(raw_key) != 32:
                continue
            parsed.append(base64.b64encode(raw_key).decode("ascii"))
        self._remote_keys = parsed
        self._fetched_at = now
        return True

    def keys_for_token(self, raw_token: str) -> list[str]:
        """Keys to try for one token: refresh once if its kid is unknown."""
        keys = self.public_keys()
        kid = _token_kid(raw_token)
        if kid is not None and not any(_kid_for_key(key) == kid for key in keys):
            if self.refresh():
                keys = self.public_keys()
        return keys


def _token_kid(raw_token: str) -> str | None:
    parts = raw_token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_decode_b64url(parts[0]))
    except (CentralAuthError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    return kid if isinstance(kid, str) else None


def _kid_for_key(encoded_key: str) -> str | None:
    try:
        raw_key = base64.b64decode(encoded_key.strip(), validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(raw_key) != 32:
        return None
    return (
        base64.urlsafe_b64encode(hashlib.sha256(raw_key).digest()[:16])
        .rstrip(b"=")
        .decode()
    )


def require_auth_signing_public_keys() -> list[str]:
    """Fail at startup, not at the first logout event, when no usable key is set.

    Central mode needs the auth service's Ed25519 public key to verify
    back-channel logout tokens. Without it every revocation would be answered
    400 and retried forever while sessions stayed alive.
    """
    keys = auth_signing_public_keys()
    if not keys:
        raise RuntimeError(
            "AUTH_SIGNING_PUBKEY is required in central mode: run `auth pubkey` on the auth host. "
            "Rotation keys are fetched from Auth's /jwks.json at runtime, but one static key "
            "is needed so verification works even when Auth is unreachable at startup."
        )
    for encoded in keys:
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError("AUTH_SIGNING_PUBKEY is not valid base64") from exc
        if len(raw) != 32:
            raise RuntimeError(
                "AUTH_SIGNING_PUBKEY must decode to a 32-byte Ed25519 key"
            )
    return keys


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def normalize_email(email: str) -> str:
    normalized = unicodedata.normalize("NFC", email).strip().casefold()
    if not normalized or len(normalized) > 254 or normalized.count("@") != 1:
        raise ValueError("A valid email address is required.")
    local, domain = normalized.split("@", 1)
    if not local or not domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("A valid email address is required.")
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        raise ValueError("Email contains unsupported control characters.")
    return normalized


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def csrf_token_for_session(token: str) -> str:
    return hmac.new(
        token.encode("ascii"), b"explorer-central-csrf-v1", hashlib.sha256
    ).hexdigest()


def verify_csrf_token(token: str, submitted: str) -> bool:
    if not token or not submitted:
        return False
    return hmac.compare_digest(csrf_token_for_session(token), submitted)


def _origin(name: str, raw: str, *, allow_http: bool = False) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        requirement = "an HTTPS origin" if not allow_http else "an HTTP(S) origin"
        raise RuntimeError(f"{name} must be {requirement} without a path or query")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


class CentralAuthClient:
    """Backchannel client for the auth service's authorization-code API."""

    def __init__(
        self,
        *,
        issuer_url: str,
        public_url: str,
        client_id: str,
        client_secret: str,
        timeout_seconds: float = 10,
        allow_insecure_http: bool = False,
    ) -> None:
        self.issuer_url = _origin(
            "AUTH_ISSUER_URL", issuer_url, allow_http=allow_insecure_http
        )
        self.public_url = _origin(
            "EXPLORER_PUBLIC_URL", public_url, allow_http=allow_insecure_http
        )
        self.client_id = client_id.strip()
        self.client_secret = client_secret
        self.timeout_seconds = timeout_seconds
        if not self.client_id or ":" in self.client_id or len(self.client_id) > 128:
            raise RuntimeError("AUTH_CLIENT_ID must be 1-128 characters without ':'")
        if len(self.client_secret.encode("utf-8")) < 32:
            raise RuntimeError("AUTH_CLIENT_SECRET must contain at least 32 bytes")
        if len(self.client_secret) > 256 or ":" in self.client_secret:
            raise RuntimeError(
                "AUTH_CLIENT_SECRET must be at most 256 characters without ':'"
            )
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise RuntimeError("AUTH_HTTP_TIMEOUT_SECONDS must be between 0 and 60")

    @classmethod
    def from_env(cls) -> CentralAuthClient:
        return cls(
            issuer_url=os.getenv("AUTH_ISSUER_URL", ""),
            public_url=os.getenv("EXPLORER_PUBLIC_URL", ""),
            client_id=os.getenv("AUTH_CLIENT_ID", "explorer"),
            client_secret=os.getenv("AUTH_CLIENT_SECRET", ""),
            timeout_seconds=float(os.getenv("AUTH_HTTP_TIMEOUT_SECONDS", "10")),
            allow_insecure_http=_env_bool("AUTH_ALLOW_INSECURE_HTTP", False),
        )

    @property
    def callback_url(self) -> str:
        return f"{self.public_url}/auth/callback"

    def authorization_url(self, *, state: str, code_challenge: str, nonce: str) -> str:
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "scope": "email",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "nonce": nonce,
            }
        )
        return f"{self.issuer_url}/authorize?{query}"

    def exchange(
        self, *, code: str, code_verifier: str, expected_nonce: str
    ) -> AuthenticatedPrincipal:
        body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.callback_url,
                "client_id": self.client_id,
                "code_verifier": code_verifier,
            }
        ).encode("ascii")
        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode("ascii")
        request = urllib.request.Request(
            f"{self.issuer_url}/token",
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {credentials}",
                "Cache-Control": "no-store",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with _open_token_request(request, self.timeout_seconds) as response:
                raw = response.read(MAX_TOKEN_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            # 400 is the auth service's invalid_grant: the code was consumed,
            # expired, or superseded by a newer /authorize for this browser.
            # Anything else (401 invalid_client, 5xx) is a deployment or
            # availability problem.
            if exc.code == 400:
                raise CodeExchangeRejectedError(
                    "The authentication service rejected the sign-in code"
                ) from exc
            raise CentralAuthError(
                "The authentication service rejected the code exchange"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CentralAuthError(
                "The authentication service rejected the code exchange"
            ) from exc
        if len(raw) > MAX_TOKEN_RESPONSE_BYTES:
            raise CentralAuthError("The authentication response was too large")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CentralAuthError("The authentication response was invalid") from exc
        if not isinstance(payload, dict):
            raise CentralAuthError("The authentication response was invalid")

        subject = payload.get("sub")
        email = payload.get("email")
        nonce = payload.get("nonce")
        issuer = payload.get("iss")
        audience = payload.get("aud")
        expires_at = payload.get("exp")
        now = int(time.time())
        # The response arrives over an authenticated TLS backchannel, so these
        # checks defend against misconfiguration rather than an attacker: a
        # response minted by a different issuer, for a different client, or
        # replayed after its assertion window must not create a session.
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 255
            or not isinstance(email, str)
            or not isinstance(nonce, str)
            or not _constant_time_equal(expected_nonce, nonce)
            or not isinstance(issuer, str)
            or issuer.rstrip("/") != self.issuer_url
            or not isinstance(audience, str)
            or audience != self.client_id
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or expires_at + CLOCK_SKEW_SECONDS <= now
        ):
            raise CentralAuthError("The authentication response was invalid")
        try:
            normalized_email = normalize_email(email)
        except ValueError as exc:
            raise CentralAuthError("The authentication response was invalid") from exc
        return AuthenticatedPrincipal(
            subject=subject, email=normalized_email, nonce=nonce
        )


class CentralAuthStore:
    """SQLite-backed service allowlist and revocable Explorer sessions."""

    def __init__(
        self,
        path: str | Path,
        *,
        idle_seconds: int = DEFAULT_IDLE_SECONDS,
        absolute_seconds: int = DEFAULT_ABSOLUTE_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        if idle_seconds <= 0 or absolute_seconds <= 0:
            raise ValueError("Session timeouts must be positive")
        if idle_seconds > absolute_seconds:
            raise ValueError("Idle timeout may not exceed absolute timeout")
        self._initialize()

    @classmethod
    def from_env(cls) -> CentralAuthStore:
        return cls(
            os.getenv("EXPLORER_ACCESS_DB", "/var/lib/explorer/access.db"),
            idle_seconds=int(
                os.getenv("EXPLORER_SESSION_IDLE_SECONDS", str(DEFAULT_IDLE_SECONDS))
            ),
            absolute_seconds=int(
                os.getenv(
                    "EXPLORER_SESSION_ABSOLUTE_SECONDS",
                    str(DEFAULT_ABSOLUTE_SECONDS),
                )
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_entries (
                    email TEXT PRIMARY KEY COLLATE NOCASE,
                    enabled INTEGER NOT NULL DEFAULT 1
                        CHECK (enabled IN (0, 1)),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    email TEXT NOT NULL REFERENCES access_entries(email),
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    idle_expires_at INTEGER NOT NULL,
                    absolute_expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS sessions_email_idx ON sessions(email);
                CREATE INDEX IF NOT EXISTS sessions_expiry_idx
                    ON sessions(absolute_expires_at, idle_expires_at);

                CREATE TABLE IF NOT EXISTS revocation_events (
                    event_id TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    received_at INTEGER NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or int(row["value"]) > SCHEMA_VERSION:
                raise RuntimeError(
                    "Unsupported Explorer access database schema version"
                )
            connection.execute(
                "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                (str(SCHEMA_VERSION),),
            )
        os.chmod(self.path, 0o600)

    def grant_access(self, email: str, *, now: int | None = None) -> AccessEntry:
        normalized = normalize_email(email)
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO access_entries(email, enabled, created_at, updated_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(email) DO UPDATE SET enabled = 1, updated_at = excluded.updated_at
                """,
                (normalized, timestamp, timestamp),
            )
        return self.get_access(normalized)

    def get_access(self, email: str) -> AccessEntry:
        normalized = normalize_email(email)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT email, enabled, created_at, updated_at FROM access_entries WHERE email = ?",
                (normalized,),
            ).fetchone()
        if row is None:
            raise AccessDeniedError("Email is not on this Explorer access list")
        return AccessEntry(
            email=str(row["email"]),
            enabled=bool(row["enabled"]),
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
        )

    def list_access(self, *, include_disabled: bool = False) -> list[AccessEntry]:
        where = "" if include_disabled else "WHERE enabled = 1"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT email, enabled, created_at, updated_at FROM access_entries {where} ORDER BY email"
            ).fetchall()
        return [
            AccessEntry(
                email=str(row["email"]),
                enabled=bool(row["enabled"]),
                created_at=int(row["created_at"]),
                updated_at=int(row["updated_at"]),
            )
            for row in rows
        ]

    def is_allowed(self, email: str) -> bool:
        try:
            normalized = normalize_email(email)
        except ValueError:
            return False
        with self._connect() as connection:
            row = connection.execute(
                "SELECT enabled FROM access_entries WHERE email = ?", (normalized,)
            ).fetchone()
        return row is not None and bool(row["enabled"])

    def revoke_access(self, email: str, *, now: int | None = None) -> bool:
        normalized = normalize_email(email)
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE access_entries SET enabled = 0, updated_at = ? WHERE email = ? AND enabled = 1",
                (timestamp, normalized),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE email = ? AND revoked_at IS NULL",
                (timestamp, normalized),
            )
        return cursor.rowcount > 0

    def create_session(
        self, subject: str, email: str, *, now: int | None = None
    ) -> IssuedSession:
        normalized = normalize_email(email)
        if (
            not subject
            or len(subject) > 255
            or any(unicodedata.category(char).startswith("C") for char in subject)
        ):
            raise CentralAuthError("The authenticated account identifier is invalid")
        timestamp = int(time.time() if now is None else now)
        absolute_expires = timestamp + self.absolute_seconds
        idle_expires = min(timestamp + self.idle_seconds, absolute_expires)
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM sessions WHERE revoked_at IS NOT NULL OR absolute_expires_at <= ?",
                (timestamp,),
            )
            allowed = connection.execute(
                "SELECT 1 FROM access_entries WHERE email = ? AND enabled = 1",
                (normalized,),
            ).fetchone()
            if allowed is None:
                raise AccessDeniedError("Email is not on this Explorer access list")
            connection.execute(
                """
                INSERT INTO sessions(
                    token_hash, subject, email, created_at, last_seen_at,
                    idle_expires_at, absolute_expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    token_hash,
                    subject,
                    normalized,
                    timestamp,
                    timestamp,
                    idle_expires,
                    absolute_expires,
                ),
            )
        return IssuedSession(token=token, token_hash=token_hash)

    def get_identity(
        self, token: str | None, *, now: int | None = None
    ) -> CentralIdentity | None:
        if not token:
            return None
        try:
            token_hash = _token_hash(token)
        except (UnicodeEncodeError, ValueError):
            return None
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            # Plain read first: most requests fall inside the touch interval
            # and must not take the write lock.
            row = connection.execute(
                """
                SELECT s.subject, s.email, s.last_seen_at, s.idle_expires_at,
                       s.absolute_expires_at, a.enabled
                FROM sessions AS s
                JOIN access_entries AS a ON a.email = s.email
                WHERE s.token_hash = ? AND s.revoked_at IS NULL
                """,
                (token_hash,),
            ).fetchone()
            if (
                row is None
                or not bool(row["enabled"])
                or timestamp >= int(row["idle_expires_at"])
                or timestamp >= int(row["absolute_expires_at"])
            ):
                if row is not None:
                    connection.execute(
                        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                        (timestamp, token_hash),
                    )
                return None
            if timestamp - int(row["last_seen_at"]) >= SESSION_TOUCH_SECONDS:
                next_idle = min(
                    timestamp + self.idle_seconds, int(row["absolute_expires_at"])
                )
                connection.execute(
                    """
                    UPDATE sessions SET last_seen_at = ?, idle_expires_at = ?
                    WHERE token_hash = ? AND revoked_at IS NULL
                    """,
                    (timestamp, next_idle, token_hash),
                )
        return CentralIdentity(subject=str(row["subject"]), email=str(row["email"]))

    def revoke_session(self, token: str | None, *, now: int | None = None) -> bool:
        if not token:
            return False
        try:
            token_hash = _token_hash(token)
        except (UnicodeEncodeError, ValueError):
            return False
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (timestamp, token_hash),
            )
        return cursor.rowcount > 0

    def consume_logout_event(
        self,
        event_id: str,
        issuer: str,
        subject: str,
        issued_at: int,
        *,
        now: int | None = None,
    ) -> bool:
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Replay protection only needs to outlive a token's acceptance
            # window (exp plus skew, minutes). Keep a week for forensics.
            connection.execute(
                "DELETE FROM revocation_events WHERE received_at < ?",
                (timestamp - REVOCATION_EVENT_RETENTION_SECONDS,),
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO revocation_events(
                    event_id, issuer, subject, issued_at, received_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, issuer, subject, issued_at, timestamp),
            )
            if cursor.rowcount:
                connection.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE subject = ? AND revoked_at IS NULL",
                    (timestamp, subject),
                )
        return cursor.rowcount > 0

    @staticmethod
    def csrf_token(token: str) -> str:
        return csrf_token_for_session(token)
