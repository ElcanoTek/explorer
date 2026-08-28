# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Endpoint tests for app.main using TestClient and a minted auth cookie."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import auth, main


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _mint(priv: Ed25519PrivateKey) -> str:
    payload = {
        "email": "alice@elcanotek.com",
        "tenant": "elcanotek.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    body = _b64url(json.dumps(payload).encode())
    return f"{body}.{_b64url(priv.sign(body.encode()))}"


@pytest.fixture()
def client(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", base64.b64encode(pub).decode())
    with TestClient(main.app) as test_client:
        test_client.cookies.set(auth.AUTH_COOKIE_NAME, _mint(priv))
        yield test_client


@pytest.fixture()
def anonymous_client(monkeypatch):
    monkeypatch.setenv("AUTH_SIGNING_PUBKEY", "")
    with TestClient(main.app) as test_client:
        yield test_client


def test_unauthenticated_inbox_redirects_to_auth(anonymous_client):
    response = anonymous_client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith(auth.AUTH_LOGIN_URL)
    assert "return_to=" in response.headers["location"]


def test_inbox_page_renders_for_authenticated_user(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Explorer" in response.text


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"


def test_view_mode_renders_rows(client, monkeypatch):
    rows = [
        {
            "s3_key": "emails/2026/06/01/msg1",
            "subject": "Northwind daily totals",
            "from": "Reports <reporting@ssp.example>",
            "to": "archive@example.com",
            "date": "Mon, 01 Jun 2026 12:00:00 +0000",
            "received_at": "2026-06-01T12:00:00+00:00",
            "size_bytes": 1234,
        }
    ]
    monkeypatch.setattr(
        main.inbox,
        "view_page_by_date_ranges",
        lambda **kwargs: (rows, None, 1),
    )
    response = client.get("/", params={"run_search": "1", "mode": "view"})
    assert response.status_code == 200
    assert "Northwind daily totals" in response.text


def test_email_detail_rejects_out_of_scope_key(client):
    response = client.get("/email", params={"s3_key": "secrets/backup.tar.gz"})
    assert response.status_code == 404


def test_attachment_rejects_out_of_scope_key(client):
    response = client.get(
        "/attachment",
        params={"s3_key": "secrets/backup.tar.gz", "filename": "x"},
    )
    assert response.status_code == 404


def test_email_detail_unknown_key_is_404(client, monkeypatch):
    def boom(s3_key):
        raise FileNotFoundError(f"no such key: {s3_key}")

    monkeypatch.setattr(main.inbox, "get_email", boom)
    response = client.get(
        "/email", params={"s3_key": f"{main.settings.email_s3_prefix}missing"}
    )
    assert response.status_code == 404


def test_unauthenticated_email_detail_redirects(anonymous_client):
    response = anonymous_client.get(
        "/email",
        params={"s3_key": f"{main.settings.email_s3_prefix}x"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith(auth.AUTH_LOGIN_URL)


def test_logout_redirects_to_auth_logout(client):
    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"{auth.AUTH_LOGIN_URL}/logout"


def test_invalid_day_shows_error_not_500(client):
    response = client.get("/", params={"run_search": "1", "day": "junk"})
    assert response.status_code == 200
    assert "Invalid date" in response.text
