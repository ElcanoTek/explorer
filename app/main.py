# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

from __future__ import annotations

import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware

from app.auth import AUTH_LOGIN_URL, current_identity, login_redirect
from app.config import settings
from app.s3_email import S3EmailInbox, SearchCancelledError

# Anchor every filesystem path to the package so the app works regardless of
# the process working directory (systemd sets it, `uvicorn` from a shell may
# not).
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    prune_attachment_cache()
    yield


app = FastAPI(title="Explorer", version="0.1.0", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
templates.env.globals["static_version"] = str(int(time.time()))
inbox = S3EmailInbox(settings)
attachment_dir = ROOT_DIR / ".tmp" / "email_attachments"
ATTACHMENT_CACHE_TTL_SECONDS = 600
VIEW_CURSOR_TTL_SECONDS = 900
VIEW_CURSOR_CACHE: dict[str, dict[str, Any]] = {}
SEARCH_JOB_TTL_SECONDS = 900
SEARCH_JOB_CACHE: dict[str, dict[str, Any]] = {}
# Guards both caches: jobs are mutated from worker threads while request
# threads read/cancel them, and bare dict read-modify-write loses updates.
CACHE_LOCK = threading.Lock()

# Browsing is scoped to the configured inbox. /email and /attachment take a
# raw S3 key, so without this check any signed-in user could read arbitrary
# objects in the bucket.
ALLOWED_S3_KEY_ROOTS = tuple(
    {
        root
        for root in (
            settings.email_s3_prefix,
            settings.email_s3_date_prefix_format.split("%", 1)[0],
        )
        if root
    }
)


def is_allowed_s3_key(key: str) -> bool:
    if not key or len(key) > 1024 or any(ord(ch) < 32 for ch in key):
        return False
    if not ALLOWED_S3_KEY_ROOTS:
        return True
    return key.startswith(ALLOWED_S3_KEY_ROOTS)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    # Caddy sets these too; keeping them here covers the legacy nginx path
    # and direct loopback access.
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def parse_date_ranges(
    raw: str | None, fallback_day: date
) -> tuple[list[tuple[date, date]], str]:
    if not raw or not raw.strip():
        return [(fallback_day, fallback_day)], fallback_day.isoformat()

    chunks = [
        piece.strip() for piece in raw.replace("\n", ",").split(",") if piece.strip()
    ]
    if not chunks:
        return [(fallback_day, fallback_day)], fallback_day.isoformat()

    parsed_ranges: list[tuple[date, date]] = []
    for chunk in chunks:
        if ".." in chunk:
            start_raw, end_raw = [part.strip() for part in chunk.split("..", 1)]
        elif ":" in chunk:
            start_raw, end_raw = [part.strip() for part in chunk.split(":", 1)]
        elif " to " in chunk.lower():
            split_at = chunk.lower().find(" to ")
            start_raw = chunk[:split_at].strip()
            end_raw = chunk[split_at + 4 :].strip()
        else:
            start_raw = chunk
            end_raw = chunk

        if not start_raw or not end_raw:
            raise ValueError(
                "Invalid date ranges. Use YYYY-MM-DD or YYYY-MM-DD..YYYY-MM-DD, separated by commas."
            )

        start_day = date.fromisoformat(start_raw)
        end_day = date.fromisoformat(end_raw)
        if end_day < start_day:
            start_day, end_day = end_day, start_day
        parsed_ranges.append((start_day, end_day))

    return parsed_ranges, raw.strip()


def parse_date_windows(
    date_from_values: list[str] | None,
    date_to_values: list[str] | None,
    fallback_day: date,
    legacy_ranges: str | None,
) -> tuple[list[tuple[date, date]], list[dict[str, str]]]:
    from_values = [
        value.strip() for value in (date_from_values or []) if value and value.strip()
    ]
    to_values = [
        value.strip() for value in (date_to_values or []) if value and value.strip()
    ]

    if from_values or to_values:
        total = max(len(from_values), len(to_values))
        parsed_ranges: list[tuple[date, date]] = []
        ui_windows: list[dict[str, str]] = []
        for index in range(total):
            raw_from = from_values[index] if index < len(from_values) else ""
            raw_to = to_values[index] if index < len(to_values) else ""
            if not raw_from and raw_to:
                raw_from = raw_to
            if not raw_to and raw_from:
                raw_to = raw_from
            if not raw_from or not raw_to:
                raise ValueError("Each date range needs both a start and end date.")

            start_day = date.fromisoformat(raw_from)
            end_day = date.fromisoformat(raw_to)
            if end_day < start_day:
                start_day, end_day = end_day, start_day

            parsed_ranges.append((start_day, end_day))
            ui_windows.append(
                {"from": start_day.isoformat(), "to": end_day.isoformat()}
            )

        return parsed_ranges, ui_windows

    parsed_ranges, _ = parse_date_ranges(legacy_ranges, fallback_day)
    ui_windows = [
        {"from": start.isoformat(), "to": end.isoformat()}
        for start, end in parsed_ranges
    ]
    return parsed_ranges, ui_windows


def count_days_covered(date_ranges: list[tuple[date, date]]) -> int:
    if not date_ranges:
        return 0

    normalized = sorted(
        ((start, end) if start <= end else (end, start) for start, end in date_ranges),
        key=lambda pair: pair[0],
    )
    merged: list[tuple[date, date]] = []
    for start, end in normalized:
        if not merged:
            merged.append((start, end))
            continue

        last_start, last_end = merged[-1]
        if start.toordinal() <= last_end.toordinal() + 1:
            merged[-1] = (last_start, end if end > last_end else last_end)
            continue
        merged.append((start, end))

    return sum((end - start).days + 1 for start, end in merged)


def build_view_signature(date_windows: list[dict[str, str]], page_size: int) -> str:
    flattened = "|".join(f"{item['from']}..{item['to']}" for item in date_windows)
    return f"{flattened}::{page_size}"


def prune_view_cache() -> None:
    now = time.time()
    with CACHE_LOCK:
        expired_ids = [
            cache_id
            for cache_id, payload in VIEW_CURSOR_CACHE.items()
            if float(cast(float, payload["expires_at"])) <= now
        ]
        for cache_id in expired_ids:
            VIEW_CURSOR_CACHE.pop(cache_id, None)


def build_search_signature(
    *,
    mode: str,
    date_windows: list[dict[str, str]],
    max_results: int,
    sender: str | None,
    recipient: str | None,
    subject: str | None,
    keywords: str | None,
    match_all: bool,
    search_subject: bool,
    search_sender: bool,
    search_body: bool,
) -> str:
    serialized_windows = "|".join(
        f"{item['from']}..{item['to']}" for item in date_windows
    )
    payload = "::".join(
        [
            mode,
            serialized_windows,
            str(max_results),
            (sender or "").strip().lower(),
            (recipient or "").strip().lower(),
            (subject or "").strip().lower(),
            (keywords or "").strip().lower(),
            "1" if match_all else "0",
            "1" if search_subject else "0",
            "1" if search_sender else "0",
            "1" if search_body else "0",
        ]
    )
    return payload


def prune_search_job_cache() -> None:
    now = time.time()
    with CACHE_LOCK:
        expired_ids = [
            cache_id
            for cache_id, payload in SEARCH_JOB_CACHE.items()
            if float(cast(float, payload["expires_at"])) <= now
        ]
        for cache_id in expired_ids:
            SEARCH_JOB_CACHE.pop(cache_id, None)


def update_search_job(job_id: str, **fields: Any) -> dict[str, Any] | None:
    """Merge fields into a job atomically; returns the new payload or None.

    All job mutations go through here so a worker finishing and a user
    cancelling can't lose each other's writes.
    """
    with CACHE_LOCK:
        job = SEARCH_JOB_CACHE.get(job_id)
        if job is None:
            return None
        job = {
            **job,
            **fields,
            "expires_at": time.time() + SEARCH_JOB_TTL_SECONDS,
        }
        SEARCH_JOB_CACHE[job_id] = job
        return job


def read_search_job(job_id: str) -> dict[str, Any] | None:
    with CACHE_LOCK:
        job = SEARCH_JOB_CACHE.get(job_id)
        return dict(job) if job is not None else None


def get_or_create_search_owner_id(request: Request) -> str:
    existing = cast(str | None, request.session.get("search_owner_id"))
    if existing:
        return existing
    owner_id = uuid4().hex
    request.session["search_owner_id"] = owner_id
    return owner_id


def load_search_job(
    job_id: str | None, signature: str, owner_id: str
) -> dict[str, Any] | None:
    if not job_id:
        return None
    job = read_search_job(job_id)
    if not job:
        return None
    if float(cast(float, job["expires_at"])) <= time.time():
        with CACHE_LOCK:
            SEARCH_JOB_CACHE.pop(job_id, None)
        return None
    if cast(str, job["signature"]) != signature:
        return None
    if cast(str, job.get("owner_id") or "") != owner_id:
        return None
    return job


def create_search_job(
    *,
    signature: str,
    mode: str,
    date_ranges: list[tuple[date, date]],
    sender: str | None,
    recipient: str | None,
    subject: str | None,
    keywords: str | None,
    match_all: bool,
    search_subject: bool,
    search_sender: bool,
    search_body: bool,
    max_results: int,
    owner_id: str,
) -> str:
    job_id = uuid4().hex
    with CACHE_LOCK:
        SEARCH_JOB_CACHE[job_id] = {
            "signature": signature,
            "owner_id": owner_id,
            "status": "running",
            "cancel_requested": False,
            "cancel_reason": None,
            "rows": [],
            "scanned_objects": 0,
            "error": None,
            "started_at": time.time(),
            "max_runtime_seconds": settings.email_search_job_max_seconds,
            "expires_at": time.time() + SEARCH_JOB_TTL_SECONDS,
        }

    def _run() -> None:
        def _should_cancel() -> bool:
            payload = read_search_job(job_id) or {}
            if bool(payload.get("cancel_requested")):
                return True

            started_at = float(cast(float, payload.get("started_at") or time.time()))
            max_runtime_seconds = int(
                cast(
                    int,
                    payload.get("max_runtime_seconds")
                    or settings.email_search_job_max_seconds,
                )
            )
            if time.time() - started_at < max_runtime_seconds:
                return False

            update_search_job(
                job_id,
                status="cancelling",
                cancel_requested=True,
                cancel_reason="timeout",
            )
            return True

        try:
            job_inbox = S3EmailInbox(settings)
            if mode == "fuzzy":
                selected_fields: list[str] = []
                if search_subject:
                    selected_fields.append("subject")
                if search_sender:
                    selected_fields.append("sender")
                if search_body:
                    selected_fields.append("body")
                if not selected_fields:
                    raise ValueError("Choose at least one fuzzy search field.")
                if not (keywords or "").strip():
                    raise ValueError("Enter at least one fuzzy keyword.")

                rows, scanned_objects = job_inbox.search_fuzzy_by_date_ranges(
                    date_ranges=date_ranges,
                    keywords=[chunk.strip() for chunk in (keywords or "").split(",")],
                    search_fields=selected_fields,
                    match_all=match_all,
                    max_results=max_results,
                    should_cancel=_should_cancel,
                )
            else:
                rows, scanned_objects = job_inbox.search_by_date_ranges(
                    date_ranges=date_ranges,
                    sender_contains=sender,
                    recipient_contains=recipient,
                    subject_contains=subject,
                    max_results=max_results,
                    should_cancel=_should_cancel,
                )

            if _should_cancel():
                update_search_job(
                    job_id,
                    status="cancelled",
                    rows=[],
                    scanned_objects=0,
                    error=None,
                    completed_at=time.time(),
                )
                return

            update_search_job(
                job_id,
                status="done",
                rows=rows,
                scanned_objects=scanned_objects,
                error=None,
                completed_at=time.time(),
            )
        except SearchCancelledError:
            update_search_job(
                job_id,
                status="cancelled",
                rows=[],
                scanned_objects=0,
                error=None,
                completed_at=time.time(),
            )
        except Exception as exc:  # noqa: BLE001
            update_search_job(
                job_id,
                status="error",
                error=str(exc),
                completed_at=time.time(),
            )

    threading.Thread(target=_run, daemon=True).start()
    return job_id


def stash_view_cursor(state: dict[str, Any], signature: str, owner_id: str) -> str:
    cursor_id = uuid4().hex
    with CACHE_LOCK:
        VIEW_CURSOR_CACHE[cursor_id] = {
            "state": state,
            "signature": signature,
            "owner_id": owner_id,
            "expires_at": time.time() + VIEW_CURSOR_TTL_SECONDS,
        }
    return cursor_id


def load_view_cursor(
    cursor_id: str | None, signature: str, owner_id: str
) -> dict[str, Any] | None:
    if not cursor_id:
        return None
    with CACHE_LOCK:
        cached = VIEW_CURSOR_CACHE.get(cursor_id)
        if not cached:
            return None
        if float(cast(float, cached["expires_at"])) <= time.time():
            VIEW_CURSOR_CACHE.pop(cursor_id, None)
            return None
    if cast(str, cached["signature"]) != signature:
        return None
    if cast(str, cached.get("owner_id") or "") != owner_id:
        return None
    return cast(dict[str, Any], cached["state"])


def prune_attachment_cache() -> None:
    if not attachment_dir.exists():
        return

    now = time.time()
    for path in attachment_dir.iterdir():
        if not path.is_file():
            continue
        try:
            if now - path.stat().st_mtime > ATTACHMENT_CACHE_TTL_SECONDS:
                path.unlink()
        except OSError:
            continue


def remove_attachment_file(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def is_logged_in(request: Request) -> bool:
    # Login is the unified elcano_auth cookie, verified against the auth
    # service's Ed25519 public key (see app/auth.py). No local password.
    return current_identity(request) is not None


@app.post("/logout")
def logout(request: Request):
    # Logout is owned by the auth service — it clears the shared cookie. We
    # drop our own ephemeral session state and forward there; auth redirects
    # back to its own login afterward.
    request.session.clear()
    return RedirectResponse(url=f"{AUTH_LOGIN_URL}/logout", status_code=303)


@app.get("/")
def inbox_page(
    request: Request,
    day: str | None = Query(default=None),
    date_from: list[str] | None = Query(default=None),
    date_to: list[str] | None = Query(default=None),
    date_ranges: str | None = Query(default=None),
    mode: str | None = Query(default=None),
    sender: str | None = Query(default=None),
    recipient: str | None = Query(default=None),
    subject: str | None = Query(default=None),
    search_mode: str | None = Query(default=None),
    keywords: str | None = Query(default=None),
    max_results: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    cursor_stack: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    search_job: str | None = Query(default=None),
    cancel_search: str | None = Query(default=None),
):
    if not is_logged_in(request):
        return login_redirect(request)
    search_owner_id = get_or_create_search_owner_id(request)

    selected_mode = (mode or search_mode or "view").strip().lower()
    if selected_mode not in {"view", "exact", "fuzzy"}:
        selected_mode = "view"

    prune_view_cache()
    prune_search_job_cache()

    selected_day = date.today()
    selected_ranges: list[tuple[date, date]] = [(selected_day, selected_day)]
    date_windows = [{"from": selected_day.isoformat(), "to": selected_day.isoformat()}]
    scanned_objects = 0
    error: str | None = None

    has_search_params = any(
        key in request.query_params
        for key in [
            "search_subject",
            "search_sender",
            "search_body",
            "match_all",
            "keywords",
            "mode",
            "search_mode",
        ]
    )
    search_subject = (
        True if not has_search_params else "search_subject" in request.query_params
    )
    search_sender = (
        True if not has_search_params else "search_sender" in request.query_params
    )
    search_body = "search_body" in request.query_params
    match_all = "match_all" in request.query_params

    if day:
        try:
            selected_day = date.fromisoformat(day)
        except ValueError:
            error = "Invalid date. Use YYYY-MM-DD."

    if error is None:
        try:
            if selected_mode == "view":
                selected_ranges = [(selected_day, selected_day)]
                date_windows = [
                    {"from": selected_day.isoformat(), "to": selected_day.isoformat()}
                ]
            else:
                selected_ranges, date_windows = parse_date_windows(
                    date_from, date_to, selected_day, date_ranges
                )
                total_days = count_days_covered(selected_ranges)
                max_allowed_days = settings.email_s3_max_date_prefix_days
                if selected_mode == "fuzzy" and search_body:
                    max_allowed_days = min(
                        max_allowed_days, settings.email_s3_max_body_search_days
                    )

                if total_days > max_allowed_days:
                    if selected_mode == "fuzzy" and search_body:
                        error = (
                            f"Body fuzzy search spans {total_days} days. Keep it at or under "
                            f"{max_allowed_days} days per search, or uncheck Body."
                        )
                    else:
                        error = (
                            f"Date ranges cover {total_days} days. Keep it at or under "
                            f"{max_allowed_days} days per search."
                        )
        except ValueError:
            error = "Invalid date ranges. Use YYYY-MM-DD or YYYY-MM-DD..YYYY-MM-DD, separated by commas."

    rows = []
    searched = request.query_params.get("run_search") == "1"
    page_size = max_results
    current_page = page
    next_page_params: dict[str, object] | None = None
    prev_page_params: dict[str, object] | None = None
    cursor_expired = False
    search_in_progress = False
    search_status = "idle"
    search_cancelled = False
    search_cancel_reason = ""
    search_pending_seconds = 0
    search_completed_seconds = 0
    cancel_search_params: dict[str, object] | None = None
    if searched and error is None:
        try:
            if selected_mode == "view":
                signature = build_view_signature(date_windows, page_size)
                current_stack = [
                    item for item in (cursor_stack or "").split(",") if item
                ]
                cursor_state = load_view_cursor(cursor, signature, search_owner_id)
                if cursor and cursor_state is None:
                    cursor_expired = True
                    current_stack = []

                rows, next_state, scanned_objects = inbox.view_page_by_date_ranges(
                    date_ranges=selected_ranges,
                    page_size=page_size,
                    cursor_state=cursor_state,
                )

                common_params: dict[str, object] = {
                    "run_search": "1",
                    "mode": selected_mode,
                    "max_results": page_size,
                    "day": selected_day.isoformat(),
                }

                if next_state is not None:
                    next_cursor = stash_view_cursor(
                        next_state, signature, search_owner_id
                    )
                    next_stack = [*current_stack, cursor or "FIRST"]
                    next_params = {
                        **common_params,
                        "cursor": next_cursor,
                        "cursor_stack": ",".join(next_stack),
                        "page": current_page + 1,
                    }
                    next_page_params = next_params

                if current_stack:
                    previous_marker = current_stack[-1]
                    prev_params = {
                        **common_params,
                        "page": max(1, current_page - 1),
                    }
                    if previous_marker != "FIRST":
                        prev_params["cursor"] = previous_marker
                    remaining_stack = current_stack[:-1]
                    if remaining_stack:
                        prev_params["cursor_stack"] = ",".join(remaining_stack)
                    prev_page_params = prev_params
            else:
                search_signature = build_search_signature(
                    mode=selected_mode,
                    date_windows=date_windows,
                    max_results=max_results,
                    sender=sender,
                    recipient=recipient,
                    subject=subject,
                    keywords=keywords,
                    match_all=match_all,
                    search_subject=search_subject,
                    search_sender=search_sender,
                    search_body=search_body,
                )
                job = load_search_job(search_job, search_signature, search_owner_id)
                if cancel_search == "1":
                    if not search_job:
                        error = "No active search to cancel."
                    elif job is None:
                        error = "This search session expired. Run the search again."
                    else:
                        job_status = cast(str, job.get("status") or "running")
                        if job_status in {"running", "cancelling"}:
                            update_search_job(
                                search_job,
                                status="cancelling",
                                cancel_requested=True,
                                cancel_reason="user",
                            )
                        query_items = list(request.query_params.multi_items())
                        query_items = [
                            (k, v) for k, v in query_items if k != "cancel_search"
                        ]
                        return RedirectResponse(
                            url=f"/?{urlencode(query_items, doseq=True)}",
                            status_code=303,
                        )

                if search_job and job is None:
                    error = "This search session expired. Run the search again."
                elif job is None:
                    created_job_id = create_search_job(
                        signature=search_signature,
                        mode=selected_mode,
                        date_ranges=selected_ranges,
                        sender=sender,
                        recipient=recipient,
                        subject=subject,
                        keywords=keywords,
                        match_all=match_all,
                        search_subject=search_subject,
                        search_sender=search_sender,
                        search_body=search_body,
                        max_results=max_results,
                        owner_id=search_owner_id,
                    )
                    query_items = list(request.query_params.multi_items())
                    query_items = [(k, v) for k, v in query_items if k != "search_job"]
                    query_items.append(("search_job", created_job_id))
                    return RedirectResponse(
                        url=f"/?{urlencode(query_items, doseq=True)}", status_code=303
                    )
                else:
                    job_status = cast(str, job.get("status") or "running")
                    search_status = job_status
                    started_at = float(
                        cast(float, job.get("started_at") or time.time())
                    )
                    search_pending_seconds = max(0, int(time.time() - started_at))
                    if job_status == "done":
                        rows = cast(list[dict[str, Any]], job.get("rows") or [])
                        scanned_objects = int(
                            cast(int, job.get("scanned_objects") or 0)
                        )
                        completed_at = float(
                            cast(float, job.get("completed_at") or time.time())
                        )
                        search_completed_seconds = max(
                            0, int(completed_at - started_at)
                        )
                    elif job_status == "cancelled":
                        search_cancelled = True
                        search_cancel_reason = cast(str, job.get("cancel_reason") or "")
                        completed_at = float(
                            cast(float, job.get("completed_at") or time.time())
                        )
                        search_completed_seconds = max(
                            0, int(completed_at - started_at)
                        )
                    elif job_status == "error":
                        error = cast(str, job.get("error") or "Search failed.")
                    else:
                        search_in_progress = True
                        if search_job:
                            cancel_search_params = {
                                "run_search": "1",
                                "mode": selected_mode,
                                "max_results": max_results,
                                "search_job": search_job,
                                "cancel_search": "1",
                            }
                            if selected_mode == "exact":
                                cancel_search_params["sender"] = sender or ""
                                cancel_search_params["recipient"] = recipient or ""
                                cancel_search_params["subject"] = subject or ""
                            if selected_mode == "fuzzy":
                                cancel_search_params["keywords"] = keywords or ""
                                if match_all:
                                    cancel_search_params["match_all"] = "on"
                                if search_subject:
                                    cancel_search_params["search_subject"] = "on"
                                if search_sender:
                                    cancel_search_params["search_sender"] = "on"
                                if search_body:
                                    cancel_search_params["search_body"] = "on"
                            cancel_search_params["date_from"] = [
                                item["from"] for item in date_windows
                            ]
                            cancel_search_params["date_to"] = [
                                item["to"] for item in date_windows
                            ]
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

    return templates.TemplateResponse(
        request,
        "inbox.html",
        {
            "error": error,
            "rows": rows,
            "searched": searched,
            "date_windows": date_windows,
            "selected_day": selected_day.isoformat(),
            "searched_windows": len(selected_ranges),
            "scanned_objects": scanned_objects,
            "max_search_days": settings.email_s3_max_date_prefix_days,
            "max_body_search_days": min(
                settings.email_s3_max_date_prefix_days,
                settings.email_s3_max_body_search_days,
            ),
            "page": current_page,
            "next_page_params": next_page_params,
            "prev_page_params": prev_page_params,
            "is_paginated_view": selected_mode == "view",
            "cursor_expired": cursor_expired,
            "search_in_progress": search_in_progress,
            "search_status": search_status,
            "search_cancelled": search_cancelled,
            "search_cancel_reason": search_cancel_reason,
            "search_pending_seconds": search_pending_seconds,
            "search_completed_seconds": search_completed_seconds,
            "cancel_search_params": cancel_search_params,
            "sender": sender or "",
            "recipient": recipient or "",
            "subject": subject or "",
            "mode": selected_mode,
            "keywords": keywords or "",
            "match_all": match_all,
            "search_subject": search_subject,
            "search_sender": search_sender,
            "search_body": search_body,
            "max_results": max_results,
        },
    )


@app.get("/email")
def email_detail_page(request: Request, s3_key: str = Query(...)):
    if not is_logged_in(request):
        return login_redirect(request)
    if not is_allowed_s3_key(s3_key):
        raise HTTPException(status_code=404, detail="Unknown email key.")
    try:
        email_data = inbox.get_email(s3_key=s3_key)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return templates.TemplateResponse(
        request,
        "email_detail.html",
        {
            "email": email_data,
        },
    )


@app.get("/attachment")
def download_attachment(
    request: Request, s3_key: str = Query(...), filename: str = Query(...)
):
    if not is_logged_in(request):
        return login_redirect(request)
    if not is_allowed_s3_key(s3_key):
        raise HTTPException(status_code=404, detail="Unknown email key.")
    prune_attachment_cache()
    try:
        saved_path = inbox.download_attachment(
            s3_key=s3_key, filename=filename, out_dir=attachment_dir
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return FileResponse(
        path=saved_path,
        filename=saved_path.name,
        background=BackgroundTask(remove_attachment_file, saved_path),
    )
