# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Behavior tests for Explorer's local password and session store."""

from __future__ import annotations

import base64
import stat
import unicodedata
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from app.local_auth import LocalAuthStore, PasswordPolicyError


@pytest.fixture()
def store(tmp_path: Path) -> LocalAuthStore:
    # Production uses the OWASP floor. Tests keep the same algorithm with a
    # deliberately small cost so the suite remains fast.
    hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=16,
    )
    return LocalAuthStore(tmp_path / "auth.db", password_hasher=hasher)


def test_password_is_verified_but_never_stored_in_plaintext(
    store: LocalAuthStore,
) -> None:
    password = "harbor violet lantern quartz"
    user = store.create_user("Alice@example.com", password)

    assert user.username == "alice@example.com"
    assert user.password_hash.startswith("$argon2id$")
    assert store.authenticate("ALICE@example.com", password) is not None
    assert store.authenticate("alice@example.com", "wrong password entirely") is None
    assert password.encode() not in store.path.read_bytes()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_passwords_allow_spaces_and_unicode_with_nfc_normalization(
    store: LocalAuthStore,
) -> None:
    decomposed = "cafe\u0301 harbor violet lantern"
    composed = unicodedata.normalize("NFC", decomposed)
    assert decomposed != composed

    store.create_user("alice@example.com", decomposed)

    assert store.authenticate("alice@example.com", composed) is not None


def test_each_user_receives_a_unique_password_salt(store: LocalAuthStore) -> None:
    password = "harbor violet lantern quartz"
    first = store.create_user("alice@example.com", password)
    second = store.create_user("bob@example.com", password)

    assert first.password_hash != second.password_hash


@pytest.mark.parametrize(
    "password",
    [
        "too short",
        "passwordpassword",
        "correcthorsebatterystaple",
    ],
)
def test_password_policy_rejects_short_or_known_passwords(
    store: LocalAuthStore, password: str
) -> None:
    with pytest.raises(PasswordPolicyError):
        store.create_user("alice@example.com", password)


def test_session_token_is_hashed_at_rest_and_hash_cannot_be_replayed(
    store: LocalAuthStore,
) -> None:
    user = store.create_user(
        "alice@example.com", "harbor violet lantern quartz", must_change_password=False
    )
    issued = store.create_session(user.id, now=1_000)
    decoded_token = base64.urlsafe_b64decode(issued.token + "=")

    assert len(decoded_token) == 32
    assert issued.token.encode() not in store.path.read_bytes()
    assert store.get_identity(issued.token, now=1_001) is not None
    assert store.get_identity(issued.token_hash, now=1_001) is None


def test_session_expires_after_sixty_minutes_idle(store: LocalAuthStore) -> None:
    user = store.create_user(
        "alice@example.com", "harbor violet lantern quartz", must_change_password=False
    )
    issued = store.create_session(user.id, now=1_000)

    assert store.get_identity(issued.token, now=4_599) is not None

    untouched = store.create_session(user.id, now=10_000)
    assert store.get_identity(untouched.token, now=13_601) is None


def test_session_never_outlives_twelve_hour_absolute_limit(
    store: LocalAuthStore,
) -> None:
    user = store.create_user(
        "alice@example.com", "harbor violet lantern quartz", must_change_password=False
    )
    issued = store.create_session(user.id, now=1_000)

    # Activity keeps the idle clock alive but never moves the absolute clock.
    for now in range(4_000, 44_000, 3_000):
        assert store.get_identity(issued.token, now=now) is not None
    assert store.get_identity(issued.token, now=44_201) is None


def test_logout_revokes_the_server_side_session(store: LocalAuthStore) -> None:
    user = store.create_user(
        "alice@example.com", "harbor violet lantern quartz", must_change_password=False
    )
    issued = store.create_session(user.id, now=1_000)

    assert store.revoke_session(issued.token, now=1_001)
    assert store.get_identity(issued.token, now=1_002) is None


def test_admin_password_reset_requires_change_and_revokes_all_sessions(
    store: LocalAuthStore,
) -> None:
    original = "harbor violet lantern quartz"
    replacement = "meadow compass glacier copper"
    user = store.create_user("alice@example.com", original, must_change_password=False)
    issued = store.create_session(user.id, now=1_000)

    store.reset_password("alice@example.com", replacement, now=1_001)

    assert store.authenticate("alice@example.com", original) is None
    reset_user = store.authenticate("alice@example.com", replacement)
    assert reset_user is not None
    assert reset_user.must_change_password is True
    assert store.get_identity(issued.token, now=1_002) is None


def test_disabling_user_immediately_invalidates_existing_sessions(
    store: LocalAuthStore,
) -> None:
    password = "harbor violet lantern quartz"
    user = store.create_user("alice@example.com", password, must_change_password=False)
    issued = store.create_session(user.id, now=1_000)

    store.set_user_enabled("alice@example.com", enabled=False, now=1_001)

    assert store.authenticate("alice@example.com", password) is None
    assert store.get_identity(issued.token, now=1_002) is None


def test_login_rate_limit_uses_account_and_ip_buckets(store: LocalAuthStore) -> None:
    for _attempt in range(10):
        assert store.login_allowed("alice@example.com", "192.0.2.10", now=1_000)
        store.record_login_failure("alice@example.com", "192.0.2.10", now=1_000)

    assert not store.login_allowed("alice@example.com", "198.51.100.20", now=1_001)
    assert store.login_allowed("bob@example.com", "192.0.2.10", now=1_001)

    for attempt in range(50):
        store.record_login_failure(
            f"candidate-{attempt}@example.com", "203.0.113.30", now=1_000
        )
    assert not store.login_allowed("other@example.com", "203.0.113.30", now=1_001)
    assert store.login_allowed("alice@example.com", "198.51.100.20", now=1_901)


def test_successful_login_clears_rate_limit_counters(store: LocalAuthStore) -> None:
    for _attempt in range(9):
        store.record_login_failure("alice@example.com", "192.0.2.10", now=1_000)

    store.record_login_success("alice@example.com", "192.0.2.10", now=1_001)

    assert store.login_allowed("alice@example.com", "192.0.2.10", now=1_002)


def test_successful_login_does_not_clear_shared_ip_limit(store: LocalAuthStore) -> None:
    for attempt in range(49):
        store.record_login_failure(
            f"candidate-{attempt}@example.com", "203.0.113.30", now=1_000
        )
    store.record_login_success("known@example.com", "203.0.113.30", now=1_001)
    store.record_login_failure("last@example.com", "203.0.113.30", now=1_002)

    assert not store.login_allowed("other@example.com", "203.0.113.30", now=1_003)
