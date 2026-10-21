// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package htmlsafe turns hostile email HTML into markup that is safe to
// render inside Explorer's pages. It is THE security boundary for message
// bodies: the web layer emits its output unescaped.
//
// The sanitizer parses with the HTML5 tree builder (golang.org/x/net/html,
// the same algorithm a browser runs), walks the tree against an explicit
// allow-list and serializes the survivors itself, so the result is always
// well-formed: every attribute value is double-quoted with " escaped, and
// < > & are escaped in text. Linkify relies on exactly that shape.
//
// Widening the allow-list needs a very good reason (CONTRIBUTING.md).
package htmlsafe

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// MaxPreviewRunes bounds the sanitized markup kept for one message.
const MaxPreviewRunes = 12000

var allowedTags = map[string]bool{
	"a": true, "b": true, "blockquote": true, "br": true, "code": true,
	"div": true, "em": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "hr": true, "img": true, "li": true, "ol": true,
	"p": true, "pre": true, "span": true, "strong": true, "table": true,
	"tbody": true, "td": true, "th": true, "thead": true, "tr": true,
	"ul": true,
}

var allowedAttrs = map[string]map[string]bool{
	"a":   {"href": true, "title": true, "target": true, "rel": true},
	"img": {"src": true, "alt": true, "title": true, "width": true, "height": true},
}

// Elements removed together with everything inside them. script and style
// carry code; title is metadata; template content is inert in a browser
// but would come alive once unwrapped.
var dropWithContent = map[string]bool{
	"script": true, "style": true, "title": true, "template": true,
}

var voidTags = map[string]bool{"br": true, "hr": true, "img": true}

// Scheme lists. data:/cid: exist only so inline images survive; a link to
// a data: URL is a phishing/XSS vector with no legitimate use in mail.
var (
	linkSchemes  = map[string]bool{"http": true, "https": true, "mailto": true}
	imageSchemes = map[string]bool{"http": true, "https": true, "mailto": true, "data": true, "cid": true}
	schemeRE     = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)
)

// urlScheme reads a URL's scheme the way a browser does: ASCII control
// characters and spaces anywhere in the value are ignored first. "" means
// the URL is relative.
func urlScheme(value string) string {
	compact := strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if m := schemeRE.FindStringSubmatch(compact); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func attrAllowed(tag, name, value string) bool {
	if name == "class" {
		return true
	}
	if !allowedAttrs[tag][name] {
		return false
	}
	switch {
	case tag == "a" && name == "href":
		s := urlScheme(value)
		return s == "" || linkSchemes[s]
	case tag == "img" && name == "src":
		s := urlScheme(value)
		return s == "" || imageSchemes[s]
	}
	return true
}

var bodyContext = &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body}

// clean parses markup as a <body> fragment and serializes only what the
// allow-list keeps. Comments and foreign (SVG/MathML) content are dropped
// whole; other disallowed elements are unwrapped, keeping their children.
func clean(markup string) string {
	nodes, err := html.ParseFragment(strings.NewReader(markup), bodyContext)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, n := range nodes {
		writeNode(&b, n)
	}
	return b.String()
}

func writeNode(b *strings.Builder, n *html.Node) {
	switch n.Type {
	case html.TextNode:
		b.WriteString(escapeText(n.Data))
		return
	case html.ElementNode:
	default:
		// Comments, doctypes and the like never survive.
		return
	}
	if n.Namespace != "" || dropWithContent[n.Data] {
		return
	}
	keep := allowedTags[n.Data]
	if keep {
		b.WriteByte('<')
		b.WriteString(n.Data)
		for _, a := range n.Attr {
			if a.Namespace != "" || !attrAllowed(n.Data, a.Key, a.Val) {
				continue
			}
			b.WriteByte(' ')
			b.WriteString(a.Key)
			b.WriteString(`="`)
			b.WriteString(escapeAttr(a.Val))
			b.WriteByte('"')
		}
		b.WriteByte('>')
		if voidTags[n.Data] {
			return
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		writeNode(b, c)
	}
	if keep {
		b.WriteString("</")
		b.WriteString(n.Data)
		b.WriteByte('>')
	}
}

var (
	textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\u00a0", "&nbsp;")
	attrEscaper = strings.NewReplacer("&", "&amp;", `"`, "&quot;", "<", "&lt;", ">", "&gt;", "\u00a0", "&nbsp;")
	// EscapeText is Python's html.escape(s, quote=True), used for plain text.
	plainEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
)

func escapeText(s string) string { return textEscaper.Replace(s) }
func escapeAttr(s string) string { return attrEscaper.Replace(s) }

// EscapeText escapes plain text for HTML exactly like Python's
// html.escape: & < > " and ' are all replaced.
func EscapeText(s string) string { return plainEscaper.Replace(s) }

var (
	preStripNames = []string{"script", "style", "head", "title", "meta", "link"}
	conditionalRE = regexp.MustCompile(`(?is)<!--\[if.*?<!\[endif\]-->`)
)

// asciiLower lowercases ASCII letters only, so byte offsets are unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// stripBlocks removes <script|style|head|title|meta|link ...>…</same> blocks
// in one left-to-right pass, the way the Python regex
// (?is)<(script|…)[^>]*>.*?</\1> did. A start with no matching close is left
// for the tree sanitizer. The scan is linear: the next '>' is tracked
// incrementally, and a name known to have no close after some point is
// never searched again.
func stripBlocks(s string) string {
	lower := asciiLower(s)
	noClose := map[string]int{}
	var out strings.Builder
	pos, emitted, gt := 0, 0, -1
	for pos < len(s) {
		lt := strings.IndexByte(lower[pos:], '<')
		if lt < 0 {
			break
		}
		start := pos + lt
		name := ""
		for _, n := range preStripNames {
			if strings.HasPrefix(lower[start+1:], n) {
				name = n
				break
			}
		}
		if name == "" {
			pos = start + 1
			continue
		}
		nameEnd := start + 1 + len(name)
		if gt < nameEnd {
			i := strings.IndexByte(lower[nameEnd:], '>')
			if i < 0 {
				break // no tag can close any more
			}
			gt = nameEnd + i
		}
		openEnd := gt + 1
		if limit, known := noClose[name]; known && openEnd >= limit {
			pos = start + 1
			continue
		}
		closeAt := strings.Index(lower[openEnd:], "</"+name+">")
		if closeAt < 0 {
			noClose[name] = openEnd
			pos = start + 1
			continue
		}
		out.WriteString(s[emitted:start])
		pos = openEnd + closeAt + len(name) + 3
		emitted = pos
	}
	out.WriteString(s[emitted:])
	return out.String()
}

// Sanitize cleans untrusted HTML: the block pre-pass, the allow-list, then
// a cut to MaxPreviewRunes that is cleaned again so nothing is left
// half-open at the boundary.
func Sanitize(htmlText string) string {
	return sanitizeLimit(htmlText, MaxPreviewRunes)
}

func sanitizeLimit(htmlText string, maxRunes int) string {
	source := conditionalRE.ReplaceAllString(stripBlocks(htmlText), "")
	out := clean(source)
	if utf8.RuneCountInString(out) > maxRunes {
		out = clean(truncateRunes(out, maxRunes))
	}
	return out
}

func truncateRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}
