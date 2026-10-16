# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Turn bare URLs in already-sanitized markup into ``rel="nofollow"`` links.

Replaces ``bleach.linkify``. The input MUST be serialized, well-formed markup:
the output of ``nh3.clean`` or of ``html.escape``. Both escape ``<`` in text
and double-quote every attribute value (escaping ``"`` inside it), which is
what lets a single regex split tags from text reliably here.

The guarantees the caller relies on:

* Only text nodes are rewritten — never an attribute value, and never text
  that is already inside an ``<a>``.
* A generated link's href is the escaped text it was found in, and the match
  can contain no raw ``"``, ``'``, ``<``, ``>`` or whitespace and stops at an
  escaped quote or angle bracket, so it cannot leave its attribute. Its
  scheme is always http or https (``http://`` is prefixed to a bare domain),
  it has a valid host and port per ``urllib.parse.urlsplit``, and it carries
  no userinfo (such URLs are left as text).
* Every ``<a>`` with a non-``mailto:`` href gets ``nofollow`` added to its
  ``rel`` tokens, exactly as bleach's default ``nofollow`` callback did.
"""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlsplit

# One serialized tag: quoted attribute values may contain ">".
_TAG_RE = re.compile(r'<[^>"]*(?:"[^"]*"[^>"]*)*>')
_ATTR_RE = re.compile(r'\s([^\s="]+)(?:="([^"]*)")?')

# Bare domains (no scheme) only link for these TLDs — the generic set bleach
# shipped plus any two-letter country code or punycode TLD — so
# "report.final" or "config.yaml" in prose stay text. A URL with an explicit
# http(s):// scheme links for any host.
_BARE_TLDS = frozenset(
    "aero arpa asia biz cat com coop edu gov info int jobs mil mobi museum "
    "name net org post pro tel travel xxx".split()
)

# One character of a URL candidate in escaped text: anything but whitespace,
# a raw quote or angle bracket, or an escaped one (``&quot;`` and kin). So a
# candidate can never leave a double-quoted attribute.
_URL_CHAR = r"""(?:[^\s<>"'&]|&(?!(?:quot|lt|gt|nbsp|\#x27|\#39|\#34|\#x22);))"""

_URL_RE = re.compile(
    rf"""
    (?<![\w@.:/&#-])                   # not mid-word, an email, or another scheme
    (?:
        # Explicit http(s): the maximal candidate run; trimmed and validated
        # by _explicit_href, which accepts any host a browser does.
        (?P<explicit>https?://{_URL_CHAR}+)
      |
        # Bare domain: needs a TLD from the short list (checked in code).
        (?P<bare>
            (?:[\w-]+\.)+(?P<tld>[^\W\d_]{{2,63}}|xn--[a-z0-9-]{{1,59}})
            (?![\w-]|\.\w)
            (?::[0-9]{{1,5}})?
            (?:[/?\#]{_URL_CHAR}*)?
        )
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PAIRS = {")": "(", "]": "[", "}": "{"}
_TRAILING_PROSE = ".,;:!?*"
_ENTITY_AT_END = re.compile(r"&(?:[A-Za-z][A-Za-z0-9]*|\#[0-9]+|\#x[0-9A-Fa-f]+);$")
_HOSTNAME = re.compile(r"^[\w-]+(?:\.[\w-]+)*\.?$")


def _strip_trailing(url: str) -> tuple[str, str]:
    """Split off trailing prose punctuation and unmatched closing brackets.

    Repeats until nothing changes, so ``(see https://x/a_(b)).`` keeps the
    balanced ``(b)`` and drops ``).``. Counts are kept incrementally, so a
    long run of closers stays linear.
    """
    opens = {o: url.count(o) for o in _PAIRS.values()}
    closes = {c: url.count(c) for c in _PAIRS}
    cut = len(url)
    while cut:
        char = url[cut - 1]
        if char in _PAIRS and closes[char] > opens[_PAIRS[char]]:
            closes[char] -= 1
        elif char in _TRAILING_PROSE and not (
            char == ";" and _ENTITY_AT_END.search(url, 0, cut)
        ):
            pass
        else:
            break
        cut -= 1
    return url[:cut], url[cut:]


def _valid_href(href: str) -> bool:
    """urlsplit check on the unescaped URL: scheme, host, port, no userinfo.

    A URL with userinfo is never linked: in untrusted mail
    ``https://bank.example@evil.example`` is a phishing shape, and linking
    only part of it would point somewhere else again.
    """
    try:
        parts = urlsplit(html.unescape(href))
        parts.port  # raises ValueError on a bad port
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https") or "@" in parts.netloc:
        return False
    host = parts.hostname or ""
    if parts.netloc.startswith("["):
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    return bool(_HOSTNAME.match(host))


def _linkify_text(text: str) -> str:
    out: list[str] = []
    end = 0
    for match in _URL_RE.finditer(text):
        if match.group("bare"):
            tld = match.group("tld").lower()
            if not (len(tld) == 2 or tld in _BARE_TLDS or tld.startswith("xn--")):
                continue
        url, suffix = _strip_trailing(match.group(0))
        href = url if match.group("explicit") else f"http://{url}"
        if not _valid_href(href):
            continue
        out.append(text[end : match.start()])
        out.append(f'<a href="{href}" rel="nofollow">{url}</a>{suffix}')
        end = match.end()
    out.append(text[end:])
    return "".join(out)


def _nofollow(tag: str) -> str:
    """Add ``nofollow`` to an existing ``<a ...>`` start tag's rel."""
    attrs = [(m.group(1), m.group(2)) for m in _ATTR_RE.finditer(tag[2:-1])]
    href = next((v for k, v in attrs if k.lower() == "href"), None)
    if href is None or href.startswith("mailto:"):
        return tag
    rel_index = next((i for i, (k, _) in enumerate(attrs) if k.lower() == "rel"), None)
    if rel_index is None:
        attrs.append(("rel", "nofollow"))
    else:
        tokens = (attrs[rel_index][1] or "").split()
        if "nofollow" not in [t.lower() for t in tokens]:
            tokens.append("nofollow")
        attrs[rel_index] = ("rel", " ".join(tokens))
    rendered = "".join(f' {k}="{v}"' if v is not None else f" {k}" for k, v in attrs)
    return f"<a{rendered}>"


def linkify(markup: str) -> str:
    """Linkify URLs in the text nodes of serialized, sanitized markup."""
    out: list[str] = []
    in_anchor = False
    end = 0
    for match in _TAG_RE.finditer(markup):
        text = markup[end : match.start()]
        out.append(text if in_anchor else _linkify_text(text))
        tag = match.group(0)
        name = re.match(r"</?([A-Za-z0-9]*)", tag)
        tag_name = name.group(1).lower() if name else ""
        if tag_name == "a":
            if tag.startswith("</"):
                in_anchor = False
            else:
                in_anchor = True
                tag = _nofollow(tag)
        out.append(tag)
        end = match.end()
    tail = markup[end:]
    out.append(tail if in_anchor else _linkify_text(tail))
    return "".join(out)
