# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

from __future__ import annotations

import email
import html
import mimetypes
import re
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from email.header import decode_header
from email.message import Message
from email.parser import BytesHeaderParser
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import bleach
import boto3
from botocore.exceptions import ClientError

from app.config import Settings

UTC = UTC


def decode_bytes(raw: bytes, charset: str | None) -> str:
    """Decode bytes with a possibly bogus charset label without raising.

    Emails in the wild carry charsets Python doesn't know ("utf-8//translit",
    "ansi_x3.110-1983", ...). Fall back to UTF-8 with replacement rather than
    failing the whole message view.
    """
    try:
        return raw.decode(charset or "utf-8", errors="replace")
    except (LookupError, ValueError):
        return raw.decode("utf-8", errors="replace")


def decode_email_header(value: str) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
    except Exception:
        return value
    decoded: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(decode_bytes(part, charset))
        else:
            decoded.append(part)
    return "".join(decoded)


def build_search_prefixes(
    s3_prefix: str,
    date_prefix_format: str,
    max_days: int,
    date_from_dt: datetime | None,
    date_to_dt: datetime | None,
) -> list[str]:
    if not date_prefix_format:
        return [s3_prefix]
    if date_from_dt is None or date_to_dt is None:
        return [s3_prefix]

    start_date = date_from_dt.date()
    end_date = date_to_dt.date()
    if end_date < start_date:
        start_date, end_date = end_date, start_date

    total_days = (end_date - start_date).days + 1
    if total_days <= 0 or total_days > max_days:
        return [s3_prefix]

    prefixes: list[str] = []
    current = end_date
    while current >= start_date:
        current_dt = datetime(current.year, current.month, current.day, tzinfo=UTC)
        prefixes.append(current_dt.strftime(date_prefix_format))
        current -= timedelta(days=1)
    return prefixes


class SearchCancelledError(Exception):
    pass


def _allow_anchor_attribute(tag: str, name: str, value: str) -> bool:
    """bleach attribute filter for <a>: data:/cid: are for inline images only.

    The global ``protocols`` list must include data:/cid: so inline images
    survive sanitization, but a link to a data: URL is a phishing/XSS vector
    with no legitimate use in email bodies.
    """
    if name in {"title", "target", "rel"}:
        return True
    if name != "href":
        return False
    scheme = value.strip().lower().split(":", 1)[0] if ":" in value else ""
    return scheme not in {"data", "cid"}


class S3EmailInbox:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.s3 = boto3.client(
            "s3",
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
        )

    def _fetch_headers(self, key: str) -> dict[str, str]:
        try:
            response = self.s3.get_object(
                Bucket=self.settings.email_s3_bucket,
                Key=key,
                Range=f"bytes=0-{self.settings.email_search_header_fetch_bytes - 1}",
            )
        except ClientError as exc:
            # S3 answers 416 InvalidRange for zero-byte objects (e.g. the
            # AMAZON_SES_SETUP_NOTIFICATION marker). Treat them as headerless
            # instead of failing the whole listing.
            if exc.response.get("Error", {}).get("Code") == "InvalidRange":
                return {"subject": "", "from": "", "to": "", "date": ""}
            raise
        chunk = response["Body"].read()
        parser = BytesHeaderParser()
        msg = parser.parsebytes(chunk)
        return {
            "subject": decode_email_header(msg.get("Subject", "")),
            "from": decode_email_header(msg.get("From", "")),
            "to": decode_email_header(msg.get("To", "")),
            "date": msg.get("Date", ""),
        }

    def _list_objects_for_ranges(
        self,
        date_ranges: list[tuple[date, date]],
        should_cancel: Callable[[], bool] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        if not date_ranges:
            return [], 0

        windows, deduped_prefixes = self._build_windows_and_prefixes(date_ranges)
        rows: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        scanned_objects = 0
        paginator = self.s3.get_paginator("list_objects_v2")
        for prefix in deduped_prefixes:
            if should_cancel and should_cancel():
                raise SearchCancelledError("Search cancelled by user.")
            for page in paginator.paginate(
                Bucket=self.settings.email_s3_bucket, Prefix=prefix
            ):
                if should_cancel and should_cancel():
                    raise SearchCancelledError("Search cancelled by user.")
                contents = page.get("Contents", [])
                for obj in contents:
                    if should_cancel and should_cancel():
                        raise SearchCancelledError("Search cancelled by user.")
                    key = obj["Key"]
                    if key == prefix or key in seen_keys:
                        continue

                    last_modified = obj["LastModified"].astimezone(UTC)
                    if not any(start <= last_modified <= end for start, end in windows):
                        continue

                    rows.append(obj)
                    seen_keys.add(key)
                    scanned_objects += 1
        return rows, scanned_objects

    def _build_windows_and_prefixes(
        self, date_ranges: list[tuple[date, date]]
    ) -> tuple[list[tuple[datetime, datetime]], list[str]]:
        windows: list[tuple[datetime, datetime]] = []
        prefixes: list[str] = []
        for start_date, end_date in date_ranges:
            if end_date < start_date:
                start_date, end_date = end_date, start_date

            start = datetime(
                start_date.year,
                start_date.month,
                start_date.day,
                0,
                0,
                0,
                0,
                tzinfo=UTC,
            )
            end = datetime(
                end_date.year,
                end_date.month,
                end_date.day,
                23,
                59,
                59,
                999999,
                tzinfo=UTC,
            )
            windows.append((start, end))
            prefixes.extend(
                build_search_prefixes(
                    self.settings.email_s3_prefix,
                    self.settings.email_s3_date_prefix_format,
                    self.settings.email_s3_max_date_prefix_days,
                    start,
                    end,
                )
            )

        deduped_prefixes = list(dict.fromkeys(prefixes))
        return windows, deduped_prefixes

    def view_page_by_date_ranges(
        self,
        date_ranges: list[tuple[date, date]],
        page_size: int,
        cursor_state: dict[str, Any] | None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None, int]:
        windows, prefixes = self._build_windows_and_prefixes(date_ranges)
        if not prefixes or page_size <= 0:
            return [], None, 0

        prefix_index = int((cursor_state or {}).get("prefix_index", 0))
        continuation_token = (cursor_state or {}).get("continuation_token")
        pending_objects = list((cursor_state or {}).get("pending_objects", []))

        if prefix_index < 0 or (prefix_index >= len(prefixes) and not pending_objects):
            return [], None, 0

        rows: list[dict[str, Any]] = []
        scanned_objects = 0

        while len(rows) < page_size and (
            pending_objects or prefix_index < len(prefixes)
        ):
            if not pending_objects:
                if prefix_index >= len(prefixes):
                    break
                kwargs: dict[str, Any] = {
                    "Bucket": self.settings.email_s3_bucket,
                    "Prefix": prefixes[prefix_index],
                    "MaxKeys": 250,
                }
                if continuation_token:
                    kwargs["ContinuationToken"] = continuation_token

                response = self.s3.list_objects_v2(**kwargs)
                continuation_token = response.get("NextContinuationToken")

                for obj in response.get("Contents", []):
                    if obj["Key"] == prefixes[prefix_index]:
                        continue

                    last_modified = obj["LastModified"].astimezone(UTC)
                    if not any(start <= last_modified <= end for start, end in windows):
                        continue

                    pending_objects.append(
                        {
                            "key": obj["Key"],
                            "last_modified": last_modified.isoformat(),
                            "size_bytes": obj.get("Size", 0),
                        }
                    )
                    scanned_objects += 1

                if not continuation_token:
                    prefix_index += 1

            while pending_objects and len(rows) < page_size:
                obj = pending_objects.pop(0)
                headers = self._fetch_headers(obj["key"])
                rows.append(
                    {
                        "s3_key": obj["key"],
                        "subject": headers["subject"],
                        "from": headers["from"],
                        "to": headers["to"],
                        "date": headers["date"],
                        "received_at": obj["last_modified"],
                        "size_bytes": obj["size_bytes"],
                    }
                )

        if prefix_index >= len(prefixes) and not pending_objects:
            return rows, None, scanned_objects

        next_state = {
            "prefix_index": prefix_index,
            "continuation_token": continuation_token,
            "pending_objects": pending_objects,
        }
        return rows, next_state, scanned_objects

    def _read_full_email(self, s3_key: str) -> Message:
        response = self.s3.get_object(Bucket=self.settings.email_s3_bucket, Key=s3_key)
        raw = response["Body"].read()
        return email.message_from_bytes(raw)

    @staticmethod
    def _extract_bodies(msg: Message) -> tuple[str, str]:
        body_plain = ""
        body_html = ""
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if "attachment" in (part.get("Content-Disposition", "") or ""):
                continue

            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                continue

            decoded = decode_bytes(payload, part.get_content_charset())
            content_type = part.get_content_type()
            if content_type == "text/plain" and not body_plain:
                body_plain = decoded
            elif content_type == "text/html" and not body_html:
                body_html = decoded
        return body_plain, body_html

    @staticmethod
    def _sanitize_html_preview(html_text: str, max_chars: int = 12000) -> str:
        cleaned_source = re.sub(
            r"(?is)<(script|style|head|title|meta|link)[^>]*>.*?</\1>",
            "",
            html_text,
        )
        cleaned_source = re.sub(r"(?is)<!--\[if.*?<!\[endif\]-->", "", cleaned_source)

        clean_html = bleach.clean(
            cleaned_source,
            tags=[
                "a",
                "b",
                "blockquote",
                "br",
                "code",
                "div",
                "em",
                "h1",
                "h2",
                "h3",
                "h4",
                "h5",
                "h6",
                "hr",
                "img",
                "li",
                "ol",
                "p",
                "pre",
                "span",
                "strong",
                "table",
                "tbody",
                "td",
                "th",
                "thead",
                "tr",
                "ul",
            ],
            attributes={
                "a": _allow_anchor_attribute,
                "img": ["src", "alt", "title", "width", "height"],
                "*": ["class"],
            },
            protocols=["http", "https", "mailto", "data", "cid"],
            strip=True,
        )
        return clean_html[:max_chars]

    @staticmethod
    def _normalize_cid(content_id: str | None) -> str:
        if not content_id:
            return ""
        return content_id.strip().strip("<>").strip().lower()

    @staticmethod
    def _inline_filename_for_cid(cid: str, content_type: str) -> str:
        safe_cid = re.sub(r"[^A-Za-z0-9._-]", "_", cid) or "inline"
        extension = mimetypes.guess_extension(content_type or "") or ".bin"
        return f"inline_{safe_cid}{extension}"

    @staticmethod
    def _strip_leading_css_noise(text: str) -> str:
        if not text:
            return ""

        cleaned = text.lstrip()
        css_rule = r"(?:\.[A-Za-z0-9_-]+|#[A-Za-z0-9_-]+|[A-Za-z][A-Za-z0-9_-]*)\s*\{[^{}]{1,800}\}\s*"
        leading_css = re.match(rf"^(?:{css_rule}){{1,50}}", cleaned)
        if leading_css and leading_css.end() > 0:
            cleaned = cleaned[leading_css.end() :].lstrip()

        return cleaned

    @staticmethod
    def _normalize_inline_ref(value: str | None) -> str:
        if not value:
            return ""
        return value.strip().strip("\"'").strip("<>").strip().lower()

    @staticmethod
    def _basename_inline_ref(value: str | None) -> str:
        normalized = S3EmailInbox._normalize_inline_ref(value)
        if not normalized:
            return ""
        split = urlsplit(normalized)
        path = unquote(split.path or normalized)
        return Path(path).name.lower()

    def search_by_date_ranges(
        self,
        date_ranges: list[tuple[date, date]],
        sender_contains: str | None,
        recipient_contains: str | None,
        subject_contains: str | None,
        max_results: int,
        should_cancel: Callable[[], bool] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        sender_needle = sender_contains.lower() if sender_contains else None
        recipient_needle = recipient_contains.lower() if recipient_contains else None
        subject_needle = subject_contains.lower() if subject_contains else None

        matches: list[dict[str, Any]] = []
        listed_objects, scanned_objects = self._list_objects_for_ranges(
            date_ranges, should_cancel=should_cancel
        )
        for obj in listed_objects:
            if should_cancel and should_cancel():
                raise SearchCancelledError("Search cancelled by user.")
            headers = self._fetch_headers(obj["Key"])
            if sender_needle and sender_needle not in headers["from"].lower():
                continue
            if recipient_needle and recipient_needle not in headers["to"].lower():
                continue
            if subject_needle and subject_needle not in headers["subject"].lower():
                continue

            matches.append(
                {
                    "s3_key": obj["Key"],
                    "subject": headers["subject"],
                    "from": headers["from"],
                    "to": headers["to"],
                    "date": headers["date"],
                    "received_at": obj["LastModified"].astimezone(UTC).isoformat(),
                    "size_bytes": obj.get("Size", 0),
                }
            )

            if len(matches) >= max_results:
                matches.sort(key=lambda row: row["received_at"], reverse=True)
                return matches, scanned_objects

        matches.sort(key=lambda row: row["received_at"], reverse=True)
        return matches, scanned_objects

    def search_fuzzy_by_date_ranges(
        self,
        date_ranges: list[tuple[date, date]],
        keywords: list[str],
        search_fields: list[str],
        match_all: bool,
        max_results: int,
        should_cancel: Callable[[], bool] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        terms = [term.strip().lower() for term in keywords if term.strip()]
        if not terms:
            return [], 0

        use_subject = "subject" in search_fields
        use_sender = "sender" in search_fields
        use_body = "body" in search_fields

        matches: list[dict[str, Any]] = []
        listed_objects, scanned_objects = self._list_objects_for_ranges(
            date_ranges, should_cancel=should_cancel
        )
        for obj in listed_objects:
            if should_cancel and should_cancel():
                raise SearchCancelledError("Search cancelled by user.")
            headers = self._fetch_headers(obj["Key"])
            subject_text = headers["subject"].lower() if use_subject else ""
            sender_text = headers["from"].lower() if use_sender else ""
            per_term_hits: list[bool] = []
            body_hits: list[bool] = [False] * len(terms)
            needs_body_scan = False

            for term in terms:
                in_subject = use_subject and term in subject_text
                in_sender = use_sender and term in sender_text
                per_term_hits.append(in_subject or in_sender)

            if use_body:
                if match_all:
                    needs_body_scan = not all(per_term_hits)
                else:
                    needs_body_scan = not any(per_term_hits)

                if needs_body_scan:
                    if should_cancel and should_cancel():
                        raise SearchCancelledError("Search cancelled by user.")
                    msg = self._read_full_email(obj["Key"])
                    body_plain, body_html = self._extract_bodies(msg)
                    body_text = (body_plain or body_html).lower()
                    body_hits = [term in body_text for term in terms]
                    per_term_hits = [
                        header_hit or body_hit
                        for header_hit, body_hit in zip(per_term_hits, body_hits)
                    ]

            score = 0
            for index, term in enumerate(terms):
                in_subject = use_subject and term in subject_text
                in_sender = use_sender and term in sender_text
                in_body = use_body and body_hits[index]

                if in_subject:
                    score += 3
                if in_sender:
                    score += 2
                if in_body:
                    score += 1

            matched = all(per_term_hits) if match_all else any(per_term_hits)
            if not matched:
                continue

            score += 1
            matches.append(
                {
                    "s3_key": obj["Key"],
                    "subject": headers["subject"],
                    "from": headers["from"],
                    "to": headers["to"],
                    "date": headers["date"],
                    "received_at": obj["LastModified"].astimezone(UTC).isoformat(),
                    "size_bytes": obj.get("Size", 0),
                    "fuzzy_score": score,
                    "matched_terms": sum(1 for hit in per_term_hits if hit),
                }
            )

        matches.sort(
            key=lambda row: (row["fuzzy_score"], row["received_at"]), reverse=True
        )
        return matches[:max_results], scanned_objects

    def get_email(self, s3_key: str) -> dict[str, Any]:
        msg = self._read_full_email(s3_key)

        attachments: list[dict[str, Any]] = []
        seen_attachment_names: set[str] = set()
        cid_map: dict[str, str] = {}
        inline_ref_map: dict[str, str] = {}
        inline_basename_map: dict[str, str] = {}
        body_plain, body_html = self._extract_bodies(msg)
        body_plain = self._strip_leading_css_noise(body_plain)

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = part.get("Content-Disposition", "")
            content_type = part.get_content_type()
            content_id = self._normalize_cid(part.get("Content-ID"))
            content_location = self._normalize_inline_ref(part.get("Content-Location"))
            payload = part.get_payload(decode=True) or b""
            filename = decode_email_header(part.get_filename() or "").strip()

            if content_id:
                if not filename:
                    filename = self._inline_filename_for_cid(content_id, content_type)
                cid_map[content_id] = filename

            should_expose = (
                "attachment" in disposition
                or bool(part.get_filename())
                or bool(content_id)
            )
            if should_expose:
                exposed_name = filename or "unknown"
                if exposed_name not in seen_attachment_names:
                    attachments.append(
                        {
                            "filename": exposed_name,
                            "content_type": content_type,
                            "size_bytes": len(payload),
                        }
                    )
                    seen_attachment_names.add(exposed_name)

                normalized_name = self._normalize_inline_ref(exposed_name)
                if normalized_name:
                    inline_ref_map[normalized_name] = exposed_name
                basename_name = self._basename_inline_ref(exposed_name)
                if basename_name:
                    inline_basename_map[basename_name] = exposed_name
                if content_location:
                    inline_ref_map[content_location] = exposed_name
                    content_location_basename = self._basename_inline_ref(
                        content_location
                    )
                    if content_location_basename:
                        inline_basename_map[content_location_basename] = exposed_name
                continue

        if body_html and cid_map:
            encoded_key = quote(s3_key, safe="")

            def replace_cid(match: re.Match[str]) -> str:
                cid_value = self._normalize_cid(match.group(1))
                filename = cid_map.get(cid_value)
                if not filename:
                    return match.group(0)
                encoded_filename = quote(filename, safe="")
                return f"/attachment?s3_key={encoded_key}&filename={encoded_filename}"

            body_html = re.sub(
                r"cid:\s*<?([^\s\"'>]+)>?", replace_cid, body_html, flags=re.IGNORECASE
            )

        if body_html and (inline_ref_map or inline_basename_map):
            encoded_key = quote(s3_key, safe="")

            def resolve_filename(raw_src: str) -> str | None:
                normalized_src = self._normalize_inline_ref(raw_src)
                if not normalized_src:
                    return None
                if normalized_src.startswith(
                    (
                        "http://",
                        "https://",
                        "data:",
                        "mailto:",
                        "/attachment?",
                        "#",
                        "cid:",
                    )
                ):
                    return None

                if normalized_src in inline_ref_map:
                    return inline_ref_map[normalized_src]

                source_basename = self._basename_inline_ref(normalized_src)
                if source_basename and source_basename in inline_basename_map:
                    return inline_basename_map[source_basename]

                return None

            def replace_inline_src(match: re.Match[str]) -> str:
                attr = match.group(1)
                src_value = match.group(2)
                filename = resolve_filename(src_value)
                if not filename:
                    return match.group(0)
                encoded_filename = quote(filename, safe="")
                return f'{attr}="/attachment?s3_key={encoded_key}&filename={encoded_filename}"'

            body_html = re.sub(
                r"(\bsrc)\s*=\s*[\"']([^\"']+)[\"']",
                replace_inline_src,
                body_html,
                flags=re.IGNORECASE,
            )

        safe_html = self._sanitize_html_preview(body_html) if body_html else ""
        safe_html = self._strip_leading_css_noise(safe_html)
        safe_html_linked = bleach.linkify(safe_html) if safe_html else ""
        has_renderable_html = bool(safe_html_linked.strip())
        preview_text = body_plain or body_html or ""
        plain_preview = preview_text[:6000]
        plain_preview_linked = (
            bleach.linkify(html.escape(plain_preview)) if plain_preview else ""
        )

        return {
            "s3_key": s3_key,
            "subject": decode_email_header(msg.get("Subject", "")),
            "from": decode_email_header(msg.get("From", "")),
            "to": decode_email_header(msg.get("To", "")),
            "cc": decode_email_header(msg.get("Cc", "")),
            "bcc": decode_email_header(msg.get("Bcc", "")),
            "reply_to": decode_email_header(msg.get("Reply-To", "")),
            "date": msg.get("Date", ""),
            "message_id": msg.get("Message-ID", ""),
            "attachment_count": len(attachments),
            "attachments": attachments,
            "body_preview": plain_preview,
            "body_preview_html": safe_html_linked if has_renderable_html else "",
            "body_preview_linked": plain_preview_linked,
            "body_preview_type": "html" if has_renderable_html else "plain",
        }

    def download_attachment(self, s3_key: str, filename: str, out_dir: Path) -> Path:
        msg = self._read_full_email(s3_key)
        requested_name = self._normalize_inline_ref(filename)

        out_dir.mkdir(parents=True, exist_ok=True)

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            part_filename = decode_email_header(part.get_filename() or "").strip()
            content_id = self._normalize_cid(part.get("Content-ID"))
            content_location = self._normalize_inline_ref(part.get("Content-Location"))
            inline_name = (
                self._inline_filename_for_cid(content_id, part.get_content_type())
                if content_id
                else ""
            )

            candidate_names = {
                name
                for name in (
                    part_filename,
                    inline_name,
                    content_location,
                    self._basename_inline_ref(content_location),
                    self._basename_inline_ref(part_filename),
                )
                if name
            }
            normalized_candidates = {
                self._normalize_inline_ref(name) for name in candidate_names
            }
            if requested_name not in normalized_candidates:
                continue

            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                break

            safe_name = Path(filename).name
            destination = out_dir / safe_name
            counter = 1
            while destination.exists():
                destination = (
                    out_dir
                    / f"{Path(safe_name).stem}_{counter}{Path(safe_name).suffix}"
                )
                counter += 1

            destination.write_bytes(payload)
            return destination

        raise FileNotFoundError(f"Attachment not found: {filename}")
