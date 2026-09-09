# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Local password authentication and opaque server-side sessions.

This module deliberately owns no HTTP behavior.  It provides the durable
credential/session boundary used by Explorer's local auth provider and by the
operator CLI.  Passwords use Argon2id; browser session tokens are random and
only their SHA-256 fingerprints are stored in SQLite.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

LOCAL_AUTH_COOKIE_NAME = "__Host-explorer_session"
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
DEFAULT_IDLE_SECONDS = 60 * 60
DEFAULT_ABSOLUTE_SECONDS = 12 * 60 * 60
SCHEMA_VERSION = 1

# This is intentionally a small offline floor, not a claim to be a complete
# breach corpus.  It catches well-known choices and app-specific variants;
# deployments can grow it without changing stored hashes.
COMMON_PASSWORDS = {
    "correcthorsebatterystaple",
    "letmeinletmeinletmein",
    "passwordpassword",
    "password123456789",
    "qwertyqwertyqwerty",
    "explorerexplorer",
}


class LocalAuthError(Exception):
    """Base class for safe, expected local-auth errors."""


class PasswordPolicyError(LocalAuthError):
    """The proposed password does not satisfy Explorer's password policy."""


class UserExistsError(LocalAuthError):
    """The normalized username already exists."""


class UserNotFoundError(LocalAuthError):
    """The requested local user does not exist."""


class InvalidCurrentPasswordError(LocalAuthError):
    """A password-change request did not prove the current password."""


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    password_hash: str
    disabled: bool
    must_change_password: bool


@dataclass(frozen=True)
class LocalIdentity:
    user_id: int
    username: str
    must_change_password: bool
    provider: str = "local"

    @property
    def email(self) -> str:
        # Local usernames are currently email-shaped identifiers.  Keeping the
        # alias lets the Explorer UI treat both providers uniformly.
        return self.username


@dataclass(frozen=True)
class IssuedSession:
    token: str
    token_hash: str


def normalize_username(username: str) -> str:
    normalized = unicodedata.normalize("NFC", username).strip().casefold()
    if not normalized or len(normalized) > 254:
        raise ValueError("Username is required and must be at most 254 characters.")
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        raise ValueError("Username contains unsupported control characters.")
    return normalized


def normalize_password(password: str) -> str:
    return unicodedata.normalize("NFC", password)


def validate_password(password: str, *, username: str = "") -> str:
    normalized = normalize_password(password)
    if len(normalized) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(normalized) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        raise PasswordPolicyError("Password contains unsupported control characters.")

    folded = normalized.casefold()
    contextual = {"explorer"}
    if username:
        normalized_username = normalize_username(username)
        contextual.update(
            {
                normalized_username,
                normalized_username.split("@", 1)[0],
            }
        )
    if folded in COMMON_PASSWORDS or folded in contextual:
        raise PasswordPolicyError("Choose a password that is not commonly guessed.")
    return normalized


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def csrf_token_for_session(token: str) -> str:
    """Derive a form token from the raw session secret without DB storage."""
    return hmac.new(
        token.encode("ascii"), b"explorer-csrf-v1", hashlib.sha256
    ).hexdigest()


def verify_csrf_token(token: str, submitted: str) -> bool:
    if not token or not submitted:
        return False
    return hmac.compare_digest(csrf_token_for_session(token), submitted)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def build_password_hasher_from_env() -> PasswordHasher:
    memory_cost = int(os.getenv("EXPLORER_ARGON2_MEMORY_COST", "19456"))
    time_cost = int(os.getenv("EXPLORER_ARGON2_TIME_COST", "2"))
    parallelism = int(os.getenv("EXPLORER_ARGON2_PARALLELISM", "1"))
    weak_test_override = _env_bool("EXPLORER_AUTH_ALLOW_WEAK_HASH_FOR_TESTS", False)
    if (memory_cost < 19_456 or time_cost < 2) and not weak_test_override:
        raise RuntimeError(
            "Argon2id production settings require at least 19456 KiB and 2 iterations"
        )
    if time_cost < 1 or parallelism < 1:
        raise RuntimeError("Argon2 time cost and parallelism must be positive")
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


class LocalAuthStore:
    """SQLite-backed local users, rate limits, and revocable sessions."""

    def __init__(
        self,
        path: str | Path,
        *,
        password_hasher: PasswordHasher | None = None,
        idle_seconds: int = DEFAULT_IDLE_SECONDS,
        absolute_seconds: int = DEFAULT_ABSOLUTE_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.password_hasher = password_hasher or build_password_hasher_from_env()
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        if self.idle_seconds <= 0 or self.absolute_seconds <= 0:
            raise ValueError("Session timeouts must be positive")
        if self.idle_seconds > self.absolute_seconds:
            raise ValueError("Idle timeout may not exceed absolute timeout")
        self._dummy_hash = self.password_hasher.hash(
            "Explorer dummy verification value 7Yq9vP"
        )
        self._initialize()

    @classmethod
    def from_env(cls) -> LocalAuthStore:
        return cls(
            os.getenv("EXPLORER_AUTH_DB", "/var/lib/explorer/auth.db"),
            password_hasher=build_password_hasher_from_env(),
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
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, mode=0o700)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
                    must_change_password INTEGER NOT NULL DEFAULT 1
                        CHECK (must_change_password IN (0, 1)),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    password_changed_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

                CREATE TABLE IF NOT EXISTS login_attempts (
                    rate_key TEXT PRIMARY KEY,
                    window_started_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    successful INTEGER NOT NULL CHECK (successful IN (0, 1))
                );
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_meta(key, value)
                VALUES('schema_version', ?)
                """,
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or int(row["value"]) != SCHEMA_VERSION:
                raise RuntimeError("Unsupported local-auth database schema version")
        os.chmod(self.path, 0o600)

    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> UserRecord:
        return UserRecord(
            id=int(row["id"]),
            username=str(row["username"]),
            password_hash=str(row["password_hash"]),
            disabled=bool(row["disabled"]),
            must_change_password=bool(row["must_change_password"]),
        )

    def _find_user(self, username: str) -> UserRecord | None:
        try:
            normalized = normalize_username(username)
        except ValueError:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, disabled, must_change_password
                FROM users WHERE username = ?
                """,
                (normalized,),
            ).fetchone()
        return self._user_from_row(row) if row else None

    def get_user(self, username: str) -> UserRecord:
        user = self._find_user(username)
        if user is None:
            raise UserNotFoundError("User not found")
        return user

    def create_user(
        self,
        username: str,
        password: str,
        *,
        must_change_password: bool = True,
        now: int | None = None,
    ) -> UserRecord:
        normalized_username = normalize_username(username)
        normalized_password = validate_password(password, username=normalized_username)
        password_hash = self.password_hasher.hash(normalized_password)
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users(
                        username, password_hash, disabled, must_change_password,
                        created_at, updated_at, password_changed_at
                    ) VALUES (?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        normalized_username,
                        password_hash,
                        int(must_change_password),
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
                user_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise UserExistsError(
                f"User already exists: {normalized_username}"
            ) from exc
        return UserRecord(
            id=user_id,
            username=normalized_username,
            password_hash=password_hash,
            disabled=False,
            must_change_password=must_change_password,
        )

    def list_users(self) -> list[UserRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, username, password_hash, disabled, must_change_password
                FROM users ORDER BY username
                """
            ).fetchall()
        return [self._user_from_row(row) for row in rows]

    def authenticate(self, username: str, password: str) -> UserRecord | None:
        user = self._find_user(username)
        encoded_hash = user.password_hash if user else self._dummy_hash
        try:
            valid = self.password_hasher.verify(
                encoded_hash, normalize_password(password)
            )
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if not user or not valid or user.disabled:
            return None

        if self.password_hasher.check_needs_rehash(user.password_hash):
            replacement = self.password_hasher.hash(normalize_password(password))
            with self._connect() as connection:
                connection.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                    (replacement, int(time.time()), user.id),
                )
            user = UserRecord(
                id=user.id,
                username=user.username,
                password_hash=replacement,
                disabled=user.disabled,
                must_change_password=user.must_change_password,
            )
        return user

    def create_session(self, user_id: int, *, now: int | None = None) -> IssuedSession:
        timestamp = int(time.time() if now is None else now)
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM sessions
                WHERE expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at <= ?)
                """,
                (timestamp, timestamp - 86_400),
            )
            connection.execute(
                """
                INSERT INTO sessions(
                    token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    token_hash,
                    user_id,
                    timestamp,
                    timestamp,
                    timestamp + self.absolute_seconds,
                ),
            )
        return IssuedSession(token=token, token_hash=token_hash)

    def get_identity(
        self, token: str | None, *, now: int | None = None
    ) -> LocalIdentity | None:
        if not token:
            return None
        try:
            token_hash = _token_hash(token)
        except (UnicodeEncodeError, AttributeError):
            return None
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    s.created_at, s.last_seen_at, s.expires_at, s.revoked_at,
                    u.id AS user_id, u.username, u.disabled, u.must_change_password
                FROM sessions AS s
                JOIN users AS u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            expired = (
                row["revoked_at"] is not None
                or bool(row["disabled"])
                or timestamp >= int(row["expires_at"])
                or timestamp - int(row["last_seen_at"]) >= self.idle_seconds
            )
            if expired:
                if row["revoked_at"] is None:
                    connection.execute(
                        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
                        (timestamp, token_hash),
                    )
                return None
            connection.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (timestamp, token_hash),
            )
        return LocalIdentity(
            user_id=int(row["user_id"]),
            username=str(row["username"]),
            must_change_password=bool(row["must_change_password"]),
        )

    def revoke_session(self, token: str | None, *, now: int | None = None) -> bool:
        if not token:
            return False
        try:
            token_hash = _token_hash(token)
        except (UnicodeEncodeError, AttributeError):
            return False
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (timestamp, token_hash),
            )
        return cursor.rowcount > 0

    def revoke_user_sessions(self, user_id: int, *, now: int | None = None) -> int:
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (timestamp, user_id),
            )
        return cursor.rowcount

    def revoke_sessions_for_username(
        self, username: str, *, now: int | None = None
    ) -> int:
        return self.revoke_user_sessions(self.get_user(username).id, now=now)

    def reset_password(
        self, username: str, password: str, *, now: int | None = None
    ) -> None:
        user = self._find_user(username)
        if user is None:
            raise UserNotFoundError("User not found")
        normalized_password = validate_password(password, username=user.username)
        password_hash = self.password_hasher.hash(normalized_password)
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, must_change_password = 1,
                    updated_at = ?, password_changed_at = ?
                WHERE id = ?
                """,
                (password_hash, timestamp, timestamp, user.id),
            )
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (timestamp, user.id),
            )

    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
        *,
        now: int | None = None,
    ) -> UserRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, disabled, must_change_password
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            raise UserNotFoundError("User not found")
        user = self._user_from_row(row)
        try:
            valid = self.password_hasher.verify(
                user.password_hash, normalize_password(current_password)
            )
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if not valid:
            raise InvalidCurrentPasswordError("Current password is incorrect.")

        normalized_password = validate_password(new_password, username=user.username)
        replacement = self.password_hasher.hash(normalized_password)
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, must_change_password = 0,
                    updated_at = ?, password_changed_at = ?
                WHERE id = ?
                """,
                (replacement, timestamp, timestamp, user.id),
            )
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (timestamp, user.id),
            )
        return UserRecord(
            id=user.id,
            username=user.username,
            password_hash=replacement,
            disabled=False,
            must_change_password=False,
        )

    def set_user_enabled(
        self, username: str, *, enabled: bool, now: int | None = None
    ) -> None:
        user = self._find_user(username)
        if user is None:
            raise UserNotFoundError("User not found")
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            connection.execute(
                "UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?",
                (int(not enabled), timestamp, user.id),
            )
            if not enabled:
                connection.execute(
                    """
                    UPDATE sessions SET revoked_at = ?
                    WHERE user_id = ? AND revoked_at IS NULL
                    """,
                    (timestamp, user.id),
                )

    @staticmethod
    def _rate_keys(username: str, remote_address: str) -> tuple[tuple[str, int], ...]:
        try:
            normalized = normalize_username(username)
        except ValueError:
            normalized = "<invalid>"
        return ((f"user:{normalized}", 10), (f"ip:{remote_address}", 50))

    def login_allowed(
        self, username: str, remote_address: str, *, now: int | None = None
    ) -> bool:
        timestamp = int(time.time() if now is None else now)
        with self._connect() as connection:
            for rate_key, _limit in self._rate_keys(username, remote_address):
                row = connection.execute(
                    "SELECT blocked_until FROM login_attempts WHERE rate_key = ?",
                    (rate_key,),
                ).fetchone()
                if row and timestamp < int(row["blocked_until"]):
                    return False
        return True

    def record_login_failure(
        self, username: str, remote_address: str, *, now: int | None = None
    ) -> None:
        timestamp = int(time.time() if now is None else now)
        window_seconds = 15 * 60
        block_seconds = 15 * 60
        with self._connect() as connection:
            for rate_key, limit in self._rate_keys(username, remote_address):
                row = connection.execute(
                    """
                    SELECT window_started_at, attempts
                    FROM login_attempts WHERE rate_key = ?
                    """,
                    (rate_key,),
                ).fetchone()
                if (
                    row is None
                    or timestamp - int(row["window_started_at"]) >= window_seconds
                ):
                    attempts = 1
                    window_started = timestamp
                else:
                    attempts = int(row["attempts"]) + 1
                    window_started = int(row["window_started_at"])
                blocked_until = timestamp + block_seconds if attempts >= limit else 0
                connection.execute(
                    """
                    INSERT INTO login_attempts(
                        rate_key, window_started_at, attempts, blocked_until
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(rate_key) DO UPDATE SET
                        window_started_at=excluded.window_started_at,
                        attempts=excluded.attempts,
                        blocked_until=excluded.blocked_until
                    """,
                    (rate_key, window_started, attempts, blocked_until),
                )
            connection.execute(
                """
                INSERT INTO auth_events(occurred_at, event_type, username, successful)
                VALUES (?, 'login', ?, 0)
                """,
                (timestamp, username[:254]),
            )

    def record_login_success(
        self, username: str, remote_address: str, *, now: int | None = None
    ) -> None:
        timestamp = int(time.time() if now is None else now)
        normalized = normalize_username(username)
        with self._connect() as connection:
            # A valid login resets that account's retry count, but not the
            # source-IP bucket: clearing the latter would let an attacker use
            # one known credential to erase evidence of an address-wide spray.
            connection.execute(
                "DELETE FROM login_attempts WHERE rate_key = ?",
                (f"user:{normalized}",),
            )
            connection.execute(
                """
                INSERT INTO auth_events(occurred_at, event_type, username, successful)
                VALUES (?, 'login', ?, 1)
                """,
                (timestamp, normalized),
            )
