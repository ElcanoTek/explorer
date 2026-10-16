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
INTENTIONAL_DIFFERENCES: dict[str, tuple[str, str]] = {
    "entities_text": (
        "<p>Tom &amp; Jerry &lt;3 \"q\" 's' café &nbsp;x</p>",
        "nh3 decodes character references and re-escapes only what HTML "
        "needs; bleach echoed the sender's entities verbatim. Same rendering.",
    ),
    "xss_script_unclosed": (
        "<p>x</p>",
        "nh3 drops the content of <script> as well as the tag; bleach left "
        "an unclosed script's body behind as text.",
    ),
    "xss_svg_a": (
        "",
        "nh3 drops foreign (SVG) content wholesale; bleach kept an empty <a>.",
    ),
    "xss_math": (
        "",
        "nh3 drops foreign (MathML) content wholesale; bleach kept a <table>.",
    ),
    "xss_noscript": (
        '&lt;p title="<img src="x">"&gt;',
        "html5ever parses <noscript> as raw text (scripting on), as a browser "
        "does; the <img> after it is real and loses its handler either way.",
    ),
    "xss_template": (
        "",
        "nh3 drops <template> content; bleach hoisted the <img> out of it.",
    ),
    "xss_textarea": (
        "&lt;img src=x onerror=alert(1)&gt;",
        "<textarea> content is text in HTML; nh3 keeps it as escaped text "
        "where bleach re-parsed it into an <img>.",
    ),
    "plain_quote_url": (
        '<a href="https://example.com/" rel="nofollow">https://example.com/</a>'
        "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;",
        "Our linkify stops a URL at an escaped quote or angle bracket; bleach "
        "carried the escaped markup into the href.",
    ),
}

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


class TestLinkFilter:
    @pytest.mark.parametrize(
        "href",
        [
            "javascript:alert(1)",
            "da\tta:text/html,x",
            "\x01data:text/html,x",
            "c\nid:abc",
            "vbscript:x",
            "JAVASCRIPT:x",
        ],
    )
    def test_dangerous_link_schemes_dropped(self, href):
        out = S3EmailInbox._render_html_preview(f'<a href="{href}">x</a>')
        assert out == "<a>x</a>"

    @pytest.mark.parametrize(
        "href", ["https://example.com", "/attachment?x=1", "#top", "mailto:a@b.example"]
    )
    def test_safe_hrefs_kept(self, href):
        assert f'href="{href}"' in S3EmailInbox._render_html_preview(
            f'<a href="{href}">x</a>'
        )

    def test_data_and_cid_images_still_render(self):
        out = S3EmailInbox._render_html_preview(
            '<img src="data:image/gif;base64,R0lGOD=="><img src="cid:logo">'
        )
        assert out == '<img src="data:image/gif;base64,R0lGOD=="><img src="cid:logo">'


class TestTruncation:
    def test_cut_inside_a_tag_is_closed_or_dropped(self):
        source = "<p>" + "x" * 30 + '</p><a href="https://example.com/long">y</a>'
        for limit in range(30, len(source) + 5):
            out = S3EmailInbox._sanitize_html_preview(source, max_chars=limit)
            assert_neutralized(out)
            assert out.count("<a") == out.count("</a>")

    def test_css_strip_cannot_leave_half_a_tag(self):
        out = S3EmailInbox._render_html_preview("p{<b>x}</b><p>body</p>")
        assert_neutralized(out)
        assert "</b>" not in out or "<b>" in out


class TestLinkify:
    def render(self, text):
        return S3EmailInbox._render_html_preview(f"<p>{text}</p>")

    def test_explicit_scheme_links_any_tld(self):
        assert self.render("https://app.example.dev/x") == (
            '<p><a href="https://app.example.dev/x" rel="nofollow">'
            "https://app.example.dev/x</a></p>"
        )

    def test_bare_domain_needs_a_known_tld(self):
        assert self.render("config.yaml") == "<p>config.yaml</p>"

    def test_other_schemes_not_linked(self):
        assert "<a" not in self.render("ftp://files.example.com/a")

    def test_userinfo_not_linked(self):
        assert "<a" not in self.render("ada@example.com")

    def test_existing_rel_gets_nofollow_once(self):
        out = S3EmailInbox._render_html_preview(
            '<a href="https://example.com" rel="NoFollow noopener">x</a>'
        )
        assert out == '<a href="https://example.com" rel="NoFollow noopener">x</a>'

    def test_mailto_and_hrefless_anchor_untouched(self):
        out = S3EmailInbox._render_html_preview(
            '<a href="mailto:a@example.com">m</a><a title="t">n</a>'
        )
        assert out == '<a href="mailto:a@example.com">m</a><a title="t">n</a>'

    def test_url_inside_attribute_never_linked(self):
        out = S3EmailInbox._render_html_preview(
            '<img alt="see https://example.com/a>b" src="https://img.example/a.png">'
        )
        assert out.count("<a") == 0

    def test_url_never_leaves_the_href(self):
        for payload in (
            'https://example.com/a"onmouseover="x',
            "https://example.com/a'onmouseover='x",
            "https://example.com/a<img src=x>",
        ):
            for out in (
                self.render(payload.replace("<", "&lt;").replace(">", "&gt;")),
                S3EmailInbox._render_plain_preview(payload),
            ):
                assert_neutralized(out)
                for href in re.findall(r'href="([^"]*)"', out):
                    assert "onmouseover" not in href and "<" not in href


class TestLinkifyReviewCases:
    """Codex review on #38. bleach.linkify had all three gaps too."""

    def link(self, url):
        return f'<a href="{url}" rel="nofollow">{url}</a>'

    def test_fragment_only_suffix_stays_in_the_link(self):
        url = "https://example.com#token=abc"
        assert S3EmailInbox._render_plain_preview(url) == self.link(url)

    def test_only_unmatched_closing_parens_are_stripped(self):
        url = "https://en.wikipedia.org/wiki/Function_(mathematics)"
        out = S3EmailInbox._render_plain_preview(f"see ({url}).")
        assert out == f"see ({self.link(url)})."

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/status",
            "http://localhost:8000/",
            "https://xn--80ak6aa92e.xn--p1ai/path",
            "http://[::1]:8080/a",
            "https://intranet",
        ],
    )
    def test_explicit_scheme_links_any_host(self, url):
        assert S3EmailInbox._render_plain_preview(url) == self.link(url)

    def test_bare_punycode_tld_links(self):
        out = S3EmailInbox._render_plain_preview("xn--80ak6aa92e.xn--p1ai")
        assert 'href="http://xn--80ak6aa92e.xn--p1ai"' in out

    def test_bare_hosts_still_need_a_tld(self):
        for text in ("localhost:8000", "127.0.0.1", "config.yaml"):
            assert "<a" not in S3EmailInbox._render_plain_preview(text)

    def test_hostile_input_stays_linear(self):
        import time

        for text in (
            "http://" + "a." * 3000,
            "http://[" + ":" * 6000,
            "https://" + "a-" * 3000,
            "x" + ")" * 6000,
            "https://e.example/" + "(" * 3000 + ")" * 3000,
            ("xn--a." * 1000),
            "https://e.example/" + ")]}" * 2000,
            "https://e.example/" + "[" * 6000,
            "https://" + "a@" * 3000,
            "https://e.example/" + ".;&amp;" * 1000,
            "https://e.example/a https://e.example/b " * 300,
        ):
            start = time.perf_counter()
            S3EmailInbox._render_plain_preview(text)
            S3EmailInbox._render_html_preview(f"<p>{text}</p>")
            assert time.perf_counter() - start < 0.5, text[:20]


def _a(url: str, href: str | None = None) -> str:
    return f'<a href="{href or url}" rel="nofollow">{url}</a>'


# (plain text, expected rendering) — scan, trim, then urlsplit-validate.
LINKIFY_TABLE = [
    # Codex round 2: userinfo is never linked (phishing shape), wholly text.
    ("https://user@example.com/path", "https://user@example.com/path"),
    ("https://user:pass@example.com/path", "https://user:pass@example.com/path"),
    ("https://bank.example@evil.example/x", "https://bank.example@evil.example/x"),
    ("see https://user@example.com.", "see https://user@example.com."),
    # Codex round 2: brackets, braces and parens are balance-aware.
    ("[https://example.com/path]", f"[{_a('https://example.com/path')}]"),
    ("{https://example.com/path}", "{" + _a("https://example.com/path") + "}"),
    (
        "(https://example.com/a_(b))",
        f"({_a('https://example.com/a_(b)')})",
    ),
    ("[https://example.com/a[1]].", f"[{_a('https://example.com/a[1]')}]."),
    ("([https://example.com/x])", f"([{_a('https://example.com/x')}])"),
    ("https://example.com/{id}", _a("https://example.com/{id}")),
    # Trailing prose punctuation.
    ("https://example.com/a.", _a("https://example.com/a") + "."),
    ("https://example.com/a,", _a("https://example.com/a") + ","),
    ("https://example.com/a!?", _a("https://example.com/a") + "!?"),
    ("https://example.com/a;", _a("https://example.com/a") + ";"),
    ("https://example.com/a:", _a("https://example.com/a") + ":"),
    ("https://example.com/?a=1&b=2", _a("https://example.com/?a=1&amp;b=2")),
    # Round 1: fragment, unmatched parens, any explicit host.
    ("https://example.com#token=abc", _a("https://example.com#token=abc")),
    (
        "(https://en.wikipedia.org/wiki/Function_(mathematics)).",
        f"({_a('https://en.wikipedia.org/wiki/Function_(mathematics)')}).",
    ),
    ("http://127.0.0.1/status", _a("http://127.0.0.1/status")),
    ("http://localhost:8000/", _a("http://localhost:8000/")),
    ("http://[::1]:8080/a", _a("http://[::1]:8080/a")),
    ("https://xn--80ak6aa92e.xn--p1ai/", _a("https://xn--80ak6aa92e.xn--p1ai/")),
    # Rejected by validation: left as text.
    ("http://example.com:99999/", "http://example.com:99999/"),
    ("http://[not-ipv6]/", "http://[not-ipv6]/"),
    ("https://", "https://"),
    # Bare domains keep the TLD rule.
    ("example.com/a.", _a("example.com/a", "http://example.com/a") + "."),
    ("config.yaml", "config.yaml"),
]


@pytest.mark.parametrize(("text", "expected"), LINKIFY_TABLE)
def test_linkify_table(text, expected):
    out = S3EmailInbox._render_plain_preview(text)
    assert_neutralized(out)
    assert out == expected
