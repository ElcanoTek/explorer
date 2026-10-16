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
  can contain no raw ``"``, ``<``, ``>`` or whitespace and stops at an escaped
  quote or angle bracket, so it cannot leave its attribute. Its scheme is
  always http or https (``http://`` is prefixed to a bare domain).
* Every ``<a>`` with a non-``mailto:`` href gets ``nofollow`` added to its
  ``rel`` tokens, exactly as bleach's default ``nofollow`` callback did.
"""

from __future__ import annotations

import re

# One serialized tag: quoted attribute values may contain ">".
_TAG_RE = re.compile(r'<[^>"]*(?:"[^"]*"[^>"]*)*>')
_ATTR_RE = re.compile(r'\s([^\s="]+)(?:="([^"]*)")?')

# Bare domains (no scheme) only link for these TLDs — the generic set bleach
# shipped plus any two-letter country code — so "report.final" or
# "config.yaml" in prose stay text. A URL with an explicit http(s):// scheme
# links for any alphabetic TLD.
_BARE_TLDS = frozenset(
    "aero arpa asia biz cat com coop edu gov info int jobs mil mobi museum "
    "name net org post pro tel travel xxx".split()
)

# Characters a URL path may contain: no whitespace, none of RFC 3986's
# unsafe set, no raw quote or angle bracket, and no escaped one either.
_PATH_CHAR = (
    r"""(?:[^\s{}|\\^`<>"'&]|&(?!(?:quot|lt|gt|nbsp|\#x27|\#39|\#34|\#x22);))"""
)

_URL_RE = re.compile(
    rf"""
    (?<![\w@.:/&#-])                   # not mid-word, an email, or another scheme
    (?P<scheme>https?://)?
    (?:[\w-]+\.)+(?P<tld>[^\W\d_]{{2,63}})
    (?::[0-9]{{1,5}})?
    (?![\w-]|\.\w)
    (?:[/?]{_PATH_CHAR}*)?
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _strip_trailing(url: str) -> tuple[str, str]:
    """Drop the trailing ``.``, ``,`` and unbalanced ``)`` prose adds."""
    suffix = ""
    while url:
        if url.endswith(")") and "(" not in url or url.endswith((",", ".")):
            suffix = url[-1] + suffix
            url = url[:-1]
            continue
        break
    return url, suffix


def _linkify_text(text: str) -> str:
    out: list[str] = []
    end = 0
    for match in _URL_RE.finditer(text):
        if not match.group("scheme") and not (
            len(match.group("tld")) == 2 or match.group("tld").lower() in _BARE_TLDS
        ):
            continue
        url, suffix = _strip_trailing(match.group(0))
        href = url if match.group("scheme") else f"http://{url}"
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
