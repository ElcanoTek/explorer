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

CENTRAL_AUTH_COOKIE_NAME = "__Host-explorer_session"
DEFAULT_IDLE_SECONDS = 60 * 60
DEFAULT_ABSOLUTE_SECONDS = 12 * 60 * 60
LOGIN_TRANSACTION_SECONDS = 10 * 60
SCHEMA_VERSION = 1
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024


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
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
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
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 255
            or not isinstance(email, str)
            or not isinstance(nonce, str)
            or not hmac.compare_digest(nonce, expected_nonce)
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
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or int(row["value"]) != SCHEMA_VERSION:
                raise RuntimeError(
                    "Unsupported Explorer access database schema version"
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
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT s.subject, s.email, s.idle_expires_at,
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
            next_idle = min(
                timestamp + self.idle_seconds, int(row["absolute_expires_at"])
            )
            connection.execute(
                "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE token_hash = ?",
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

    @staticmethod
    def csrf_token(token: str) -> str:
        return csrf_token_for_session(token)
