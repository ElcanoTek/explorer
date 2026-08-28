# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Tests for the date-range parsing and view-state helpers in app.main."""

from __future__ import annotations

from datetime import date

import pytest

from app import main

FALLBACK = date(2026, 6, 1)


class TestParseDateRanges:
    def test_empty_falls_back_to_day(self):
        ranges, raw = main.parse_date_ranges(None, FALLBACK)
        assert ranges == [(FALLBACK, FALLBACK)]
        assert raw == "2026-06-01"

    def test_single_day(self):
        ranges, raw = main.parse_date_ranges("2026-05-02", FALLBACK)
        assert ranges == [(date(2026, 5, 2), date(2026, 5, 2))]
        assert raw == "2026-05-02"

    def test_dotdot_range(self):
        ranges, _ = main.parse_date_ranges("2026-05-01..2026-05-03", FALLBACK)
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 3))]

    def test_colon_and_to_separators(self):
        ranges, _ = main.parse_date_ranges(
            "2026-05-01:2026-05-02, 2026-05-04 to 2026-05-05", FALLBACK
        )
        assert ranges == [
            (date(2026, 5, 1), date(2026, 5, 2)),
            (date(2026, 5, 4), date(2026, 5, 5)),
        ]

    def test_reversed_bounds_are_swapped(self):
        ranges, _ = main.parse_date_ranges("2026-05-09..2026-05-01", FALLBACK)
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 9))]

    def test_invalid_date_raises(self):
        with pytest.raises(ValueError):
            main.parse_date_ranges("not-a-date", FALLBACK)


class TestParseDateWindows:
    def test_paired_lists(self):
        ranges, windows = main.parse_date_windows(
            ["2026-05-01"], ["2026-05-03"], FALLBACK, None
        )
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 3))]
        assert windows == [{"from": "2026-05-01", "to": "2026-05-03"}]

    def test_missing_to_copies_from(self):
        ranges, windows = main.parse_date_windows(["2026-05-01"], [], FALLBACK, None)
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 1))]
        assert windows == [{"from": "2026-05-01", "to": "2026-05-01"}]

    def test_reversed_bounds_normalized(self):
        ranges, windows = main.parse_date_windows(
            ["2026-05-09"], ["2026-05-01"], FALLBACK, None
        )
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 9))]
        assert windows == [{"from": "2026-05-01", "to": "2026-05-09"}]

    def test_falls_back_to_legacy_ranges(self):
        ranges, windows = main.parse_date_windows(
            None, None, FALLBACK, "2026-05-01..2026-05-02"
        )
        assert ranges == [(date(2026, 5, 1), date(2026, 5, 2))]
        assert windows == [{"from": "2026-05-01", "to": "2026-05-02"}]


class TestCountDaysCovered:
    def test_empty(self):
        assert main.count_days_covered([]) == 0

    def test_single_day(self):
        assert main.count_days_covered([(FALLBACK, FALLBACK)]) == 1

    def test_overlapping_ranges_merge(self):
        ranges = [
            (date(2026, 5, 1), date(2026, 5, 5)),
            (date(2026, 5, 3), date(2026, 5, 7)),
        ]
        assert main.count_days_covered(ranges) == 7

    def test_adjacent_ranges_merge(self):
        ranges = [
            (date(2026, 5, 1), date(2026, 5, 2)),
            (date(2026, 5, 3), date(2026, 5, 4)),
        ]
        assert main.count_days_covered(ranges) == 4

    def test_disjoint_ranges_sum(self):
        ranges = [
            (date(2026, 5, 1), date(2026, 5, 2)),
            (date(2026, 5, 10), date(2026, 5, 11)),
        ]
        assert main.count_days_covered(ranges) == 4

    def test_duplicate_windows_counted_once(self):
        ranges = [(FALLBACK, FALLBACK), (FALLBACK, FALLBACK)]
        assert main.count_days_covered(ranges) == 1


class TestS3KeyScoping:
    def test_inbox_prefix_allowed(self):
        prefix = main.settings.email_s3_prefix
        assert prefix, "test expects a configured inbox prefix"
        assert main.is_allowed_s3_key(f"{prefix}2026/06/01/abc123") is True

    def test_outside_prefix_rejected(self):
        assert main.is_allowed_s3_key("secrets/backup.tar.gz") is False

    def test_empty_and_garbage_rejected(self):
        assert main.is_allowed_s3_key("") is False
        assert main.is_allowed_s3_key("emails/\x00bad") is False
        assert main.is_allowed_s3_key("emails/" + "a" * 1100) is False


class TestViewCursorCache:
    def test_round_trip_requires_signature_and_owner(self):
        cursor_id = main.stash_view_cursor({"prefix_index": 1}, "sig-a", "owner-1")
        assert main.load_view_cursor(cursor_id, "sig-a", "owner-1") == {
            "prefix_index": 1
        }
        assert main.load_view_cursor(cursor_id, "sig-b", "owner-1") is None
        assert main.load_view_cursor(cursor_id, "sig-a", "owner-2") is None
        assert main.load_view_cursor("missing", "sig-a", "owner-1") is None
