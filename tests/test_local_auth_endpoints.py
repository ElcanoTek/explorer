# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""End-to-end request behavior for local Explorer authentication."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from app import main
from app.local_auth import LOCAL_AUTH_COOKIE_NAME, LocalAuthStore

TEMP_PASSWORD = "harbor violet lantern quartz"
NEW_PASSWORD = "meadow compass glacier copper"


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


@pytest.fixture()
def local_client(tmp_path: Path, monkeypatch, asgi_client):
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "local")
    monkeypatch.setenv("EXPLORER_AUTH_DB", str(db_path))
    monkeypatch.setenv("EXPLORER_AUTH_COOKIE_SECURE", "1")
    monkeypatch.setenv("EXPLORER_ARGON2_MEMORY_COST", "1024")
    monkeypatch.setenv("EXPLORER_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("EXPLORER_AUTH_ALLOW_WEAK_HASH_FOR_TESTS", "1")
    monkeypatch.setattr(
        main, "settings", replace(main.settings, session_secret="test-session-secret")
    )

    store = LocalAuthStore.from_env()
    store.create_user("alice@example.com", TEMP_PASSWORD)

    with asgi_client(main.app, base_url="https://explorer.example") as client:
        yield client, store


def login(client):
    page = client.get("/login")
    return client.post(
        "/login",
        data={
            "username": "alice@example.com",
            "password": TEMP_PASSWORD,
            "csrf_token": csrf_from(page.text),
        },
        follow_redirects=False,
    )


def test_global_gate_redirects_anonymous_requests_including_unknown_routes(
    local_client,
) -> None:
    client, _store = local_client

    for path in ["/", "/email?s3_key=emails/x", "/future-route"]:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_login_and_health_are_public(local_client) -> None:
    client, _store = local_client

    assert client.get("/login").status_code == 200
    assert client.get("/health").status_code == 200


def test_local_mode_rejects_missing_session_secret(
    tmp_path: Path, monkeypatch, asgi_client
) -> None:
    monkeypatch.setenv("EXPLORER_AUTH_MODE", "local")
    monkeypatch.setenv("EXPLORER_AUTH_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("EXPLORER_AUTH_COOKIE_SECURE", "1")
    monkeypatch.setenv("EXPLORER_ARGON2_MEMORY_COST", "1024")
    monkeypatch.setenv("EXPLORER_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("EXPLORER_AUTH_ALLOW_WEAK_HASH_FOR_TESTS", "1")
    monkeypatch.setattr(main, "settings", replace(main.settings, session_secret=""))

    with pytest.raises(RuntimeError, match="generated EXPLORER_SESSION_SECRET"):
        with asgi_client(main.app, base_url="https://explorer.example") as client:
            client.get("/health")


def test_login_uses_generic_failure_and_requires_csrf(local_client) -> None:
    client, _store = local_client
    page = client.get("/login")
    csrf_token = csrf_from(page.text)

    bad_password = client.post(
        "/login",
        data={
            "username": "alice@example.com",
            "password": "wrong password entirely",
            "csrf_token": csrf_token,
            "next": "/",
        },
    )
    unknown_user = client.post(
        "/login",
        data={
            "username": "nobody@example.com",
            "password": "wrong password entirely",
            "csrf_token": csrf_from(client.get("/login").text),
            "next": "/",
        },
    )
    missing_csrf = client.post(
        "/login",
        data={
            "username": "alice@example.com",
            "password": TEMP_PASSWORD,
            "next": "/",
        },
    )

    assert bad_password.status_code == 401
    assert unknown_user.status_code == 401
    assert "Invalid username or password" in bad_password.text
    assert "Invalid username or password" in unknown_user.text
    assert "alice@example.com" not in bad_password.text
    assert missing_csrf.status_code == 403


def test_successful_login_sets_protected_host_only_cookie(local_client) -> None:
    client, _store = local_client

    response = login(client)

    assert response.status_code == 303
    assert response.headers["location"] == "/change-password"
    cookie = response.headers["set-cookie"]
    assert f"{LOCAL_AUTH_COOKIE_NAME}=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert "Domain=" not in cookie


def test_login_ignores_an_external_redirect_field(local_client) -> None:
    client, _store = local_client
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "alice@example.com",
            "password": TEMP_PASSWORD,
            "csrf_token": csrf_from(page.text),
            "next": "https://evil.example/steal",
        },
        follow_redirects=False,
    )

    assert response.headers["location"] == "/change-password"


def test_first_login_is_restricted_until_password_changes(local_client) -> None:
    client, store = local_client
    login(client)
    old_token = client.cookies.get(LOCAL_AUTH_COOKIE_NAME)

    assert (
        client.get("/", follow_redirects=False).headers["location"]
        == "/change-password"
    )
    change_page = client.get("/change-password")
    response = client.post(
        "/change-password",
        data={
            "current_password": TEMP_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
            "csrf_token": csrf_from(change_page.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert store.get_identity(old_token) is None
    assert client.cookies.get(LOCAL_AUTH_COOKIE_NAME) != old_token
    assert client.get("/").status_code == 200


def test_logout_requires_csrf_and_revokes_session(local_client) -> None:
    client, store = local_client
    login(client)
    change_page = client.get("/change-password")
    client.post(
        "/change-password",
        data={
            "current_password": TEMP_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
            "csrf_token": csrf_from(change_page.text),
        },
    )
    token = client.cookies.get(LOCAL_AUTH_COOKIE_NAME)

    assert client.post("/logout").status_code == 403
    inbox = client.get("/")
    response = client.post(
        "/logout",
        data={"csrf_token": csrf_from(inbox.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert store.get_identity(token) is None


def test_elcano_cookie_is_not_accepted_by_local_provider(local_client) -> None:
    client, _store = local_client
    client.cookies.set("elcano_auth", "some.other.signed-token")

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
