# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Shared test helpers.

The execution environment uses Python 3.14, where AnyIO's blocking portal can
deadlock during Starlette TestClient startup.  This small synchronous facade
runs the same ASGI transport in the current thread and keeps cookies between
requests, preserving endpoint-level behavior without a live socket.
"""

from __future__ import annotations

import sys
from typing import Any, Self

import anyio
import fastapi.dependencies.utils
import fastapi.routing
import httpx2
import pytest
import starlette.routing

if sys.version_info < (3, 14):
    from fastapi.testclient import TestClient as _NativeTestClient
else:
    _NativeTestClient = None


async def _run_sync_directly(function, *args, **kwargs):
    """Test-only replacement for AnyIO's Python 3.14 worker-thread bridge."""
    return function(*args, **kwargs)


# Patch before application modules are imported during test collection. This
# environment's AnyIO blocking/thread portals deadlock under Python 3.14; route
# behavior remains identical for these deterministic tests without the hop.
if sys.version_info >= (3, 14):
    fastapi.routing.run_in_threadpool = _run_sync_directly
    fastapi.dependencies.utils.run_in_threadpool = _run_sync_directly
    starlette.routing.run_in_threadpool = _run_sync_directly


class ASGITestClient:
    def __init__(self, app, *, base_url: str = "https://testserver") -> None:
        self.app = app
        self.base_url = base_url
        self.cookies = httpx2.Cookies()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, path: str, **kwargs: Any):
        follow_redirects = kwargs.pop("follow_redirects", True)

        async def run_request():
            transport = httpx2.ASGITransport(app=self.app)
            async with (
                self.app.router.lifespan_context(self.app),
                httpx2.AsyncClient(
                    transport=transport,
                    base_url=self.base_url,
                    cookies=self.cookies,
                    follow_redirects=follow_redirects,
                ) as client,
            ):
                response = await client.request(method, path, **kwargs)
                self.cookies = client.cookies
                return response

        return anyio.run(run_request)

    def get(self, path: str, **kwargs: Any):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any):
        return self.request("POST", path, **kwargs)


@pytest.fixture()
def asgi_client():
    return ASGITestClient if sys.version_info >= (3, 14) else _NativeTestClient
