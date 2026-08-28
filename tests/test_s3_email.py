# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Tests for the S3 inbox layer (app/s3_email.py) using a fake S3 client."""

from __future__ import annotations

from datetime import UTC, date, datetime
from email.message import EmailMessage

import pytest
from botocore.exceptions import ClientError

from app.config import Settings
from app.s3_email import (
    S3EmailInbox,
    build_search_prefixes,
    decode_bytes,
    decode_email_header,
)

UTC = UTC
DAY = date(2026, 6, 1)
RECEIVED = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def make_settings(**overrides) -> Settings:
    values = dict(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_region="us-east-1",
        email_s3_bucket="test-bucket",
        email_s3_prefix="emails/",
        email_s3_date_prefix_format="emails/%Y/%m/%d/",
        email_s3_max_date_prefix_days=62,
        email_s3_max_body_search_days=14,
        email_search_header_fetch_bytes=65536,
        email_search_job_max_seconds=120,
        session_secret="test",
    )
    values.update(overrides)
    return Settings(**values)


class FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeS3:
    """Just enough of the boto3 S3 client for S3EmailInbox."""

    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects

    def get_object(self, Bucket, Key, Range=None):
        data = self.objects[Key]
        if Range is not None:
            if not data:
                raise ClientError(
                    {"Error": {"Code": "InvalidRange", "Message": "empty"}},
                    "GetObject",
                )
            end = int(Range.split("-", 1)[1])
            data = data[: end + 1]
        return {"Body": FakeBody(data)}

    def list_objects_v2(self, Bucket, Prefix, MaxKeys=1000, ContinuationToken=None):
        contents = [
            {"Key": key, "LastModified": RECEIVED, "Size": len(data)}
            for key, data in sorted(self.objects.items())
            if key.startswith(Prefix)
        ]
        return {"Contents": contents}

    def get_paginator(self, operation_name):
        fake = self

        class Paginator:
            def paginate(self, Bucket, Prefix):
                yield fake.list_objects_v2(Bucket=Bucket, Prefix=Prefix)

        return Paginator()


def make_inbox(objects: dict[str, bytes]) -> S3EmailInbox:
    inbox = S3EmailInbox(make_settings())
    inbox.s3 = FakeS3(objects)
    return inbox


def build_email(
    *,
    html: str | None = None,
    plain: str = "plain body",
    attachments: list[tuple[str, bytes]] | None = None,
    inline_png_cid: str | None = None,
    **headers: str,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = headers.get("from_", "Reports <reporting@ssp.example>")
    msg["To"] = headers.get("to", "archive@example.com")
    msg["Subject"] = headers.get("subject", "Daily report")
    if "cc" in headers:
        msg["Cc"] = headers["cc"]
    if "reply_to" in headers:
        msg["Reply-To"] = headers["reply_to"]
    msg["Date"] = "Mon, 01 Jun 2026 12:00:00 +0000"
    msg.set_content(plain)
    if html is not None:
        msg.add_alternative(html, subtype="html")
        if inline_png_cid:
            msg.get_payload()[1].add_related(
                b"\x89PNG-fake-bytes",
                maintype="image",
                subtype="png",
                cid=f"<{inline_png_cid}>",
            )
    for filename, payload in attachments or []:
        msg.add_attachment(
            payload,
            maintype="application",
            subtype="octet-stream",
            filename=filename,
        )
    return msg.as_bytes()


class TestDecoding:
    def test_decode_bytes_with_bogus_charset(self):
        assert decode_bytes(b"caf\xc3\xa9", "utf-8//translit") == "café"
        assert decode_bytes(b"hello", "ansi_x3.110-1983-bogus") == "hello"

    def test_decode_email_header_rfc2047(self):
        assert decode_email_header("=?utf-8?b?Y2Fmw6k=?=") == "café"

    def test_decode_email_header_unknown_charset_does_not_raise(self):
        # An unknown charset label must degrade, not 500 the page.
        result = decode_email_header("=?x-totally-bogus?q?hi?=")
        assert isinstance(result, str)


class TestBuildSearchPrefixes:
    def test_one_prefix_per_day_newest_first(self):
        start = datetime(2026, 6, 1, tzinfo=UTC)
        end = datetime(2026, 6, 3, tzinfo=UTC)
        prefixes = build_search_prefixes("emails/", "emails/%Y/%m/%d/", 62, start, end)
        assert prefixes == [
            "emails/2026/06/03/",
            "emails/2026/06/02/",
            "emails/2026/06/01/",
        ]

    def test_span_over_max_days_falls_back_to_root(self):
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 6, 1, tzinfo=UTC)
        assert build_search_prefixes("emails/", "emails/%Y/%m/%d/", 30, start, end) == [
            "emails/"
        ]

    def test_no_format_falls_back_to_root(self):
        start = datetime(2026, 6, 1, tzinfo=UTC)
        assert build_search_prefixes("emails/", "", 62, start, start) == ["emails/"]


class TestSanitizer:
    def test_script_and_event_handlers_stripped(self):
        dirty = '<p onclick="alert(1)">hi</p><script>alert(2)</script>'
        clean = S3EmailInbox._sanitize_html_preview(dirty)
        assert "<script" not in clean
        assert "onclick" not in clean
        assert "hi" in clean

    def test_data_href_dropped_but_https_kept(self):
        dirty = (
            '<a href="data:text/html;base64,PHNjcmlwdD4=">bad</a>'
            '<a href="https://example.com">ok</a>'
        )
        clean = S3EmailInbox._sanitize_html_preview(dirty)
        assert "data:text/html" not in clean
        assert 'href="https://example.com"' in clean

    def test_data_image_src_kept(self):
        dirty = '<img src="data:image/png;base64,iVBORw0KGgo=">'
        clean = S3EmailInbox._sanitize_html_preview(dirty)
        assert 'src="data:image/png;base64,iVBORw0KGgo="' in clean

    def test_style_block_removed(self):
        dirty = "<style>.x{color:red}</style><p>body</p>"
        clean = S3EmailInbox._sanitize_html_preview(dirty)
        assert "color:red" not in clean
        assert "body" in clean


class TestFetchHeaders:
    def test_zero_byte_object_returns_empty_headers(self):
        inbox = make_inbox({"emails/2026/06/01/empty": b""})
        headers = inbox._fetch_headers("emails/2026/06/01/empty")
        assert headers == {"subject": "", "from": "", "to": "", "date": ""}

    def test_normal_object_parses_headers(self):
        key = "emails/2026/06/01/msg1"
        inbox = make_inbox({key: build_email(subject="Hello world")})
        headers = inbox._fetch_headers(key)
        assert headers["subject"] == "Hello world"
        assert "reporting@ssp.example" in headers["from"]


class TestSearch:
    def test_exact_search_filters_by_sender(self):
        objects = {
            "emails/2026/06/01/a": build_email(
                from_="Alpha <alpha@one.example>", subject="A"
            ),
            "emails/2026/06/01/b": build_email(
                from_="Beta <beta@two.example>", subject="B"
            ),
        }
        inbox = make_inbox(objects)
        rows, scanned = inbox.search_by_date_ranges(
            date_ranges=[(DAY, DAY)],
            sender_contains="beta@two",
            recipient_contains=None,
            subject_contains=None,
            max_results=10,
        )
        assert scanned == 2
        assert [row["subject"] for row in rows] == ["B"]

    def test_fuzzy_search_matches_subject_keyword(self):
        objects = {
            "emails/2026/06/01/a": build_email(subject="Northwind daily report"),
            "emails/2026/06/01/b": build_email(subject="Unrelated"),
        }
        inbox = make_inbox(objects)
        rows, _ = inbox.search_fuzzy_by_date_ranges(
            date_ranges=[(DAY, DAY)],
            keywords=["northwind"],
            search_fields=["subject"],
            match_all=False,
            max_results=10,
        )
        assert [row["subject"] for row in rows] == ["Northwind daily report"]
        assert rows[0]["fuzzy_score"] >= 3

    def test_view_page_returns_rows_without_cursor(self):
        objects = {
            "emails/2026/06/01/a": build_email(subject="One"),
            "emails/2026/06/01/b": build_email(subject="Two"),
        }
        inbox = make_inbox(objects)
        rows, next_state, scanned = inbox.view_page_by_date_ranges(
            date_ranges=[(DAY, DAY)], page_size=10, cursor_state=None
        )
        assert scanned == 2
        assert {row["subject"] for row in rows} == {"One", "Two"}
        assert next_state is None


class TestGetEmail:
    def test_cc_reply_to_and_attachments_exposed(self):
        key = "emails/2026/06/01/msg1"
        raw = build_email(
            cc="copy@elcanotek.com",
            reply_to="replies@ssp.example",
            attachments=[("report.pdf", b"PDFDATA")],
        )
        inbox = make_inbox({key: raw})
        email_data = inbox.get_email(key)
        assert email_data["cc"] == "copy@elcanotek.com"
        assert email_data["reply_to"] == "replies@ssp.example"
        assert email_data["bcc"] == ""
        names = [att["filename"] for att in email_data["attachments"]]
        assert "report.pdf" in names

    def test_cid_image_rewritten_to_attachment_url(self):
        key = "emails/2026/06/01/msg2"
        raw = build_email(
            html='<p>Logo: <img src="cid:logo123"></p>',
            inline_png_cid="logo123",
        )
        inbox = make_inbox({key: raw})
        email_data = inbox.get_email(key)
        assert "/attachment?s3_key=" in email_data["body_preview_html"]
        assert "cid:logo123" not in email_data["body_preview_html"]

    def test_plain_preview_present(self):
        key = "emails/2026/06/01/msg3"
        inbox = make_inbox({key: build_email(plain="hello body")})
        email_data = inbox.get_email(key)
        assert "hello body" in email_data["body_preview"]


class TestDownloadAttachment:
    def test_round_trip(self, tmp_path):
        key = "emails/2026/06/01/msg1"
        raw = build_email(attachments=[("report.pdf", b"PDFDATA")])
        inbox = make_inbox({key: raw})
        saved = inbox.download_attachment(key, "report.pdf", tmp_path)
        assert saved.parent == tmp_path
        assert saved.read_bytes() == b"PDFDATA"

    def test_traversal_filename_confined_to_out_dir(self, tmp_path):
        key = "emails/2026/06/01/msg1"
        raw = build_email(attachments=[("../../evil.txt", b"X")])
        inbox = make_inbox({key: raw})
        saved = inbox.download_attachment(key, "../../evil.txt", tmp_path)
        assert saved.parent == tmp_path
        assert saved.name == "evil.txt"

    def test_missing_attachment_raises(self, tmp_path):
        key = "emails/2026/06/01/msg1"
        inbox = make_inbox({key: build_email()})
        with pytest.raises(FileNotFoundError):
            inbox.download_attachment(key, "nope.pdf", tmp_path)

    def test_duplicate_name_gets_counter_suffix(self, tmp_path):
        key = "emails/2026/06/01/msg1"
        raw = build_email(attachments=[("report.pdf", b"PDFDATA")])
        inbox = make_inbox({key: raw})
        first = inbox.download_attachment(key, "report.pdf", tmp_path)
        second = inbox.download_attachment(key, "report.pdf", tmp_path)
        assert first != second
        assert second.name == "report_1.pdf"
