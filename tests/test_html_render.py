# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Characterization tests for the email body render pipeline.

``tests/data/sanitizer_golden.json`` was recorded from the bleach-based
pipeline. Every case must stay neutralized (no script, handler or dangerous
URL can survive), and benign output must match the recording exactly unless
the case is listed in ``INTENTIONAL_DIFFERENCES`` with its reason.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.s3_email import S3EmailInbox

GOLDEN = json.loads(
    (Path(__file__).parent / "data" / "sanitizer_golden.json").read_text()
)

# name -> (expected output, why it differs from the bleach recording)
INTENTIONAL_DIFFERENCES: dict[str, tuple[str, str]] = {}

ALLOWED_TAGS = {
    "a", "b", "blockquote", "br", "code", "div", "em", "h1", "h2", "h3", "h4",
    "h5", "h6", "hr", "img", "li", "ol", "p", "pre", "span", "strong", "table",
    "tbody", "td", "th", "thead", "tr", "ul",
}  # fmt: skip

TAG_RE = re.compile(r'<(/?)([a-zA-Z0-9]+)((?:\s+[^\s=>]+(?:="[^"]*")?)*)\s*/?>')
ATTR_RE = re.compile(r'\s+([^\s=>]+)(?:="([^"]*)")?')
SAFE_URL = re.compile(r"^(?:https?:|mailto:|/|#|data:image/|cid:)", re.IGNORECASE)


def assert_neutralized(markup: str) -> None:
    """Structural XSS check: only allow-listed tags, attributes and URLs."""
    rest = TAG_RE.sub("", markup)
    assert "<" not in rest, f"unparsed markup survived: {markup!r}"
    for match in TAG_RE.finditer(markup):
        tag = match.group(2).lower()
        assert tag in ALLOWED_TAGS, f"tag {tag} survived: {markup!r}"
        for attr in ATTR_RE.finditer(match.group(3)):
            name = attr.group(1).lower()
            value = attr.group(2) or ""
            assert not name.startswith("on"), f"handler survived: {markup!r}"
            assert name in {
                "href", "title", "target", "rel", "src", "alt", "width",
                "height", "class",
            }, f"attribute {name} survived: {markup!r}"  # fmt: skip
            if name in {"href", "src"}:
                assert SAFE_URL.match(value) or not re.match(
                    r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value
                ), f"unsafe URL survived: {markup!r}"
            if name == "href":
                assert not value.lower().startswith(("data:", "cid:")), markup


def render(section: str, source: str) -> str:
    if section == "html":
        return S3EmailInbox._render_html_preview(source)
    return S3EmailInbox._render_plain_preview(source)


CASES = [
    (section, name, case)
    for section in ("html", "plain")
    for name, case in GOLDEN[section].items()
]


@pytest.mark.parametrize(
    ("section", "name", "case"), CASES, ids=[f"{s}-{n}" for s, n, _ in CASES]
)
def test_render_matches_recording(section, name, case):
    out = render(section, case["input"])
    assert_neutralized(out)
    expected = INTENTIONAL_DIFFERENCES.get(name, (case["bleach"], ""))[0]
    assert out == expected


def test_recording_itself_is_neutralized():
    for section in ("html", "plain"):
        for case in GOLDEN[section].values():
            assert_neutralized(case["bleach"])
