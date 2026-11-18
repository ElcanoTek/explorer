// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"crypto/sha256"
	"encoding/hex"
	stdhtml "html"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ElcanoTek/explorer/internal/htmlsafe"
	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// Download-link detection (the agent API's has_payload filter and the links
// get_email reports).
//
// Vendors split roughly evenly between attaching report files and putting a
// download link in the body, so "has a payload" means an attachment OR a
// link the classifier calls download-likely. This is the Go port of the
// link archiver's classify_url (ElcanoTek/production-support
// ses-s3/lambdas/ses_email_link_archiver.py).
//
// Hash contract: the archiver caches each download-likely link's payload at
// <EMAIL_S3_ARCHIVE_PREFIX>by-url/<sha256(url)>/<filename>, where url is the
// string exactly as it extracts it from the body (outer wrapper, after
// clean_url, &amp; NOT decoded). Extraction here mirrors it (all text/plain
// parts' URLs, then all text/html parts' anchors, then URLs written as text
// in the HTML outside tags and <style>/<script> blocks, not seen before as
// written or entity-decoded) so the url a caller is given hashes to the
// cached copy. testdata/html_text_urls.json is a copy of the archiver's
// shared cases (ses-s3/scripts/tests/data/html_text_urls.json).

var downloadExtensions = setOf(
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt",
	".csv", ".json", ".xml", ".yaml", ".yml",
	".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
	".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp",
	".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
	".py", ".js", ".ts", ".html", ".css", ".sql",
	".exe", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
)

// imageExtensions are banners, logos and tracking pixels, never a report.
var imageExtensions = setOf(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico")

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// clickTrackerPatterns are email-marketing click redirectors (host suffix,
// path substring): they hide the target's extension but are often the only
// path to the payload.
var clickTrackerPatterns = [][2]string{
	{"sendgrid.net", "/ls/click"}, {"sendgrid.net", "/wf/click"},
	{"list-manage.com", "/track/click"}, {"mailchimp.com", "/track/click"},
	{"hubspotlinks.com", ""}, {"hs-sites.com", "/e1t/c/"},
	{"iterable.com", "/api/email/click"}, {"links.iterable.com", ""},
	{"mkt.com", "/trk"}, {"eloqua.com", "/e/er"}, {"pardot.com", "/e/"},
	{"exct.net", ""}, {"exacttarget.com", ""}, {"pstmrk.it", ""},
	{"", "/ls/click"}, {"", "/wf/click"}, {"", "/track/click"},
}

var junkHostSuffixes = []string{
	"advertising.amazon.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
	"calendly.com", "calendar.google.com", "zoom.us", "youtube.com", "vimeo.com",
}

var (
	lineContRE    = regexp.MustCompile(`=[\r\n]+`)
	textURLRE     = regexp.MustCompile(`(?i)https?://[^\s<>"')\]}>]*(?:=[\r\n]+[^\s<>"')\]}>]*)*`)
	htmlLinkRE    = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref=["']([^"']+)["'][^>]*>(.*?)</a\s*>`)
	tagRE         = regexp.MustCompile(`<[^>]*>`)
	unsubscribeRE = regexp.MustCompile(`(?i)unsubscribe|opt[-_]?out|email[-_]?preferences|manage[-_]?preferences`)
	proofpointV3  = regexp.MustCompile(`/v3/__(.+?)__;`)
)

var downloadKeywords = []string{
	"download", "attachment", "file", "export", "get", "report", "generate", "csv", "xlsx", "pdf",
	"api/download", "api/export", "api/report",
}

var downloadParams = []string{
	"format=csv", "format=xlsx", "format=pdf", "type=csv", "fmt=csv", "fmt=xls", "fmt=xlsx", "fmt=pdf",
	"export=", "download=", "action=download", "action=export",
}

func cleanURL(u string) string {
	u = lineContRE.ReplaceAllString(u, "")
	u = strings.NewReplacer("\n", "", "\r", "").Replace(u)
	return strings.TrimRight(strings.TrimSpace(u), ".,;:!?")
}

func extractTextURLs(text string) []string {
	var out []string
	for _, u := range textURLRE.FindAllString(text, -1) {
		if u = cleanURL(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// asciiLower lowercases A-Z only, so byte offsets stay those of s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// indexFrom is strings.Index of sub in s at or after from (-1 if none).
func indexFrom(s, sub string, from int) int {
	if from > len(s) {
		return -1
	}
	if k := strings.Index(s[from:], sub); k >= 0 {
		return from + k
	}
	return -1
}

// maxScanRunes is the archiver's MAX_SCAN_CHARS, counted in characters
// (runes) as Python counts them, so both cut at the same place.
const maxScanRunes = 2_000_000

// truncateToRunes is s cut after n runes.
func truncateToRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// endsAtFirstGT reports whether the markup at html[j] ends at its first
// ">", quotes included: "<!" and "<?" (declarations, bogus comments) and
// "</" without a letter after it ("</3>", "</>"), which the tokenizer reads
// as a comment.
func endsAtFirstGT(html string, j int) bool {
	if strings.HasPrefix(html[j:], "<!") || strings.HasPrefix(html[j:], "<?") {
		return true
	}
	if !strings.HasPrefix(html[j:], "</") {
		return false
	}
	if j+2 >= len(html) {
		return true
	}
	c := html[j+2] | 0x20 // ASCII lower case
	return c < 'a' || c > 'z'
}

func isTagStart(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '/' || c == '!' || c == '?'
}

// tagEnd is where the tag starting at html[j] ("<") ends, read as the HTML
// tokenizer reads it: its first ">" outside a quoted attribute value, or -1
// (a quote left open, or no ">"): then, as in a browser, the rest of the
// document is inside the tag. A quote opens a value only after an attribute
// name and "=" (spaces allowed); in a tag name, an attribute name (which may
// begin with "=" or hold quotes, as in <div =">) or an unquoted value,
// quotes and "=" are ordinary characters. "<!" and "<?" (declarations, bogus
// comments) end at their first ">", as does "</" without a letter after it
// (endsAtFirstGT). Callers move past the end, so each byte
// is scanned once. The archiver's _tag_end.
func tagEnd(html string, j int) int {
	end, _ := tagScan(html, j)
	return end
}

// tagScan is tagEnd and whether the tag is self-closing: it ends "/>"
// outside a value ("<svg/>", not "<svg a=b/>"). The archiver's _tag_scan.
func tagScan(html string, j int) (int, bool) {
	const (
		inName = iota
		beforeAttr
		inAttr
		afterAttr
		beforeValue
		inUnquoted
		afterQuoted
	)
	n := len(html)
	if endsAtFirstGT(html, j) {
		return indexFrom(html, ">", j+1), false
	}
	k := j + 1
	if strings.HasPrefix(html[j:], "</") {
		k = j + 2
	}
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
	state := inName
	for ; k < n; k++ {
		c := html[k]
		if c == '>' {
			return k, state == beforeAttr && html[k-1] == '/'
		}
		switch state {
		case inName:
			if space(c) || c == '/' {
				state = beforeAttr
			}
		case beforeAttr:
			if !space(c) && c != '/' {
				state = inAttr // any other byte, "=" and quotes included, starts a name
			}
		case inAttr:
			switch {
			case space(c):
				state = afterAttr
			case c == '/':
				state = beforeAttr
			case c == '=':
				state = beforeValue
			}
		case afterAttr:
			switch {
			case c == '=':
				state = beforeValue
			case c == '/':
				state = beforeAttr
			case !space(c):
				state = inAttr
			}
		case beforeValue:
			switch {
			case c == '"' || c == '\'':
				q := indexFrom(html, string(c), k+1)
				if q < 0 {
					return -1, false
				}
				k, state = q, afterQuoted
			case !space(c):
				state = inUnquoted
			}
		case inUnquoted:
			if space(c) {
				state = beforeAttr
			}
		case afterQuoted:
			if space(c) || c == '/' {
				state = beforeAttr
			} else {
				state = inAttr
			}
		}
	}
	return -1, false
}

// blockTags end a block of text: they become "\n" in stripMarkup, the only
// "\n" there (the source's own line breaks and <br> are spaces); any other
// tag (links included), a comment and a <style> or <script> element join
// what is around them, as a reader sees the text. The archiver's
// _BLOCK_TAGS.
var blockTags = setOf("address", "article", "aside", "blockquote", "center", "dd", "div", "dl", "dt",
	"footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "nav", "ol",
	"p", "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul", "listing", "plaintext", "xmp")

// tagName is the lower-case name of the tag at lower[j] ("<" or "</", then a
// letter, then anything up to a space, "/" or ">"), or "".
func tagName(lower string, j int) string {
	k := j + 1
	if k < len(lower) && lower[k] == '/' {
		k++
	}
	start := k
	if k >= len(lower) || lower[k] < 'a' || lower[k] > 'z' {
		return ""
	}
	// The whole name, up to a space, "/" or ">": <p-x> is not <p>.
	for k < len(lower) && !strings.ContainsRune(" \t\r\n\f/>", rune(lower[k])) {
		k++
	}
	return lower[start:k]
}

// rawTextNames are elements whose content a reader never sees, dropped with
// it (as internal/htmlsafe drops them when rendering): style and script, the
// head and its title, inert template content, and SVG and MathML (foreign
// content). The first four end at their first closing tag (a <head> left
// open is only a tag, as the sanitizer keeps its text); the others nest
// (dropEnd). The archiver's _RAW_TEXT.
var rawTextNames = []string{"style", "script", "title", "head", "template", "svg", "math"}

// rawTextName is the dropped element's name when the tag at lower[j] opens
// one (its name ends there: "<styles" does not).
func rawTextName(lower string, j int) string {
	return openingName(lower, j, rawTextNames)
}

// literalNames are elements whose content is shown as written, markup
// included (internal/htmlsafe keeps their raw text, escaped): RCDATA and
// RAWTEXT elements a reader sees, and plaintext, which runs to the end. The
// archiver's _LITERAL.
var literalNames = []string{"textarea", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext"}

// literalText is the text of the literal element name whose start tag ends
// at html[end] (up to its own closing tag, or the rest for plaintext or one
// left open) and just past that closing tag, or -1 when the rest is its.
func literalText(html, lower, name string, end int) (string, int) {
	if name != "plaintext" {
		if k := closingTag(lower, name, end+1); k >= 0 {
			if e := tagEnd(html, k); e >= 0 {
				return html[end+1 : k], e + 1
			}
			return html[end+1 : k], -1
		}
	}
	return html[end+1:], -1
}

// openingName is the one of names whose start tag is at lower[j] (its name
// ends there: "<styles" does not), or "".
func openingName(lower string, j int, names []string) string {
	for _, name := range names {
		after := j + 1 + len(name)
		if strings.HasPrefix(lower[j+1:], name) && after < len(lower) && strings.ContainsRune(" \t\r\n\f/>", rune(lower[after])) {
			return name
		}
	}
	return ""
}

// breakoutTags end SVG or MathML content in a browser (the parser's
// "breakout" list; <font> only with certain attributes, taken here as
// always). What follows is hard to place, so dropEnd hides it. The
// archiver's _BREAKOUT.
var breakoutTags = map[string]bool{
	"b": true, "big": true, "blockquote": true, "body": true, "br": true, "center": true, "code": true,
	"dd": true, "div": true, "dl": true, "dt": true, "em": true, "embed": true, "font": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "head": true, "hr": true, "i": true,
	"img": true, "li": true, "listing": true, "menu": true, "meta": true, "nobr": true, "ol": true, "p": true,
	"pre": true, "ruby": true, "s": true, "small": true, "span": true, "strike": true, "strong": true,
	"sub": true, "sup": true, "table": true, "tt": true, "u": true, "ul": true, "var": true,
}

// integrationTags are SVG and MathML elements whose content a browser
// parses as HTML (integration points; annotation-xml only with certain
// encodings, taken here as always), and swallowTags the HTML elements
// that swallow a template's closing tag (dropEnd skips the raw text of
// style, script and title, and hides the rest at any other). The
// archiver's _INTEGRATION and _SWALLOW.
var (
	integrationTags = map[string]bool{
		"foreignobject": true, "desc": true, "title": true, "mi": true, "mo": true, "mn": true, "ms": true,
		"mtext": true, "annotation-xml": true,
	}
	swallowTags = map[string]bool{
		"template": true, "script": true, "style": true, "title": true, "textarea": true, "xmp": true,
		"iframe": true, "noembed": true, "noframes": true, "noscript": true, "plaintext": true,
	}
)

// commentEnd is just past the comment starting at html[j] ("<!--"), or -1
// when it is left open: it ends at its first "-->" or "--!>", or at once as
// "<!-->" or "<!--->", as the HTML tokenizer reads it. The archiver's
// _comment_end.
func commentEnd(html string, j int) int {
	for _, short := range []string{"<!-->", "<!--->"} {
		if strings.HasPrefix(html[j:], short) {
			return j + len(short)
		}
	}
	end, at := -1, -1
	for _, m := range []string{"-->", "--!>"} {
		if k := indexFrom(html, m, j+4); k >= 0 && (at < 0 || k < at) {
			at, end = k, k+len(m)
		}
	}
	return end
}

// dropEnd is where the dropped element name whose start tag ends at
// html[end] ends (just past its end tag), or -1 when it is left open (the
// rest is the element's). Raw text ends at its first own closing tag (whose
// name ends there, quote-aware). A template, <svg> or <math> ends at its
// matching closing tag: a nested element of the same name opens a level (a
// self-closing <svg/> or <math/> does not), and a comment is skipped, as are
// a template's own raw-text, SVG and MathML children and an SVG or MathML
// CDATA section.
//
// Where a browser could end the element elsewhere, the rest is hidden here
// instead (dropped, never invented): in SVG or MathML, an HTML tag such as
// <p> or <br> (breakoutTags), a closing tag with no open element of its name
// inside (it can close the SVG from outside), or any tag but <svg> or <math>
// opened inside an integration point (an SVG <title>, whose content is
// HTML); in a template, an element that swallows its closing tag
// (swallowTags) other than the raw text skipped. The archiver's _drop_end.
func dropEnd(html, lower, name string, end int) int {
	if name != "template" && name != "svg" && name != "math" {
		return rawTextEnd(html, lower, name, end)
	}
	d := &dropLevel{name: name, foreign: name != "template", depth: 1, opened: map[string]int{}}
	n, i := len(html), end+1
	for {
		j := indexFrom(html, "<", i)
		if j < 0 {
			return -1
		}
		if k, skipped := skipMarkup(html, j, d.foreign); skipped {
			if i = k; i < 0 {
				return -1
			}
			continue
		}
		if j+1 >= n || !isTagStart(html[j+1]) {
			i = j + 1
			continue
		}
		e, selfClosing := tagScan(html, j)
		if e < 0 {
			return -1
		}
		if inner := rawTextName(lower, j); !d.foreign && templateChild(inner, selfClosing) {
			if i = dropEnd(html, lower, inner, e); i < 0 {
				return -1
			}
			continue
		}
		ends, hide := d.at(tagName(lower, j), strings.HasPrefix(lower[j:], "</"), selfClosing)
		if hide {
			return -1
		}
		if ends {
			return e + 1
		}
		i = e + 1
	}
}

// templateChild reports whether a template skips the element named inner
// whole: raw text, or SVG or MathML (unless self-closing).
func templateChild(inner string, selfClosing bool) bool {
	switch inner {
	case "style", "script", "title":
		return true
	case "svg", "math":
		return !selfClosing
	}
	return false
}

// rawTextEnd is just past the closing tag of the raw-text element name
// whose start tag ends at html[end]: its first own closing tag (whose name
// ends there, quote-aware), or -1 when there is none.
func rawTextEnd(html, lower, name string, end int) int {
	k := closingTag(lower, name, end+1)
	if k < 0 {
		return -1
	}
	if e := tagEnd(html, k); e >= 0 {
		return e + 1
	}
	return -1
}

// closingTag is where the first closing tag of name at or after from starts
// (its name ends there: "</styles" does not), or -1.
func closingTag(lower, name string, from int) int {
	closing := "</" + name
	k := indexFrom(lower, closing, from)
	for k >= 0 && k+len(closing) < len(lower) && !strings.ContainsRune(" \t\r\n\f/>", rune(lower[k+len(closing)])) {
		k = indexFrom(lower, closing, k+len(closing))
	}
	return k
}

// skipMarkup is just past the comment (or, in SVG or MathML, the CDATA
// section) starting at html[j], or -1 when it is left open; skipped is
// false when neither starts there.
func skipMarkup(html string, j int, foreign bool) (next int, skipped bool) {
	if strings.HasPrefix(html[j:], "<!--") {
		return commentEnd(html, j), true
	}
	if foreign && strings.HasPrefix(html[j:], "<![CDATA[") {
		if k := indexFrom(html, "]]>", j+9); k >= 0 {
			return k + 3, true
		}
		return -1, true
	}
	return 0, false
}

// dropLevel is a template, <svg> or <math> element being dropped (dropEnd).
type dropLevel struct {
	name               string
	foreign            bool
	depth, integration int
	opened             map[string]int // elements open inside a foreign one, by name
}

// at reads a tag inside the element: whether the element ends with it, or
// whether the rest is hidden (see dropEnd).
func (d *dropLevel) at(tag string, closing, selfClosing bool) (ends, hide bool) {
	switch {
	case tag == d.name:
		if closing {
			d.depth--
			return d.depth == 0, false
		}
		if !d.foreign || !selfClosing {
			d.depth++
		}
	case d.foreign && tag != "" && closing:
		if tag == "p" || tag == "br" || d.opened[tag] == 0 {
			return false, true
		}
		d.opened[tag]--
		if integrationTags[tag] {
			d.integration--
		}
	case d.foreign && tag != "":
		if breakoutTags[tag] || (d.integration > 0 && tag != "svg" && tag != "math") {
			return false, true
		}
		if !selfClosing {
			d.opened[tag]++
			if integrationTags[tag] {
				d.integration++
			}
		}
	case !d.foreign && !closing && swallowTags[tag]:
		return false, true
	}
	return false, false
}

// stripMarkup returns html's text as a reader sees it, in one left-to-right
// pass, as the archiver's _strip_markup does: a block-level tag becomes
// "\n" (the only "\n": the source's own line breaks and <br> become
// spaces); any other tag (links included), a comment and a <style> or <script> element
// (its raw text included) are removed, joining what is around them. A tag
// starts
// at "<" followed by a letter, "/", "!" or "?" (else "<" is text) and ends at
// its first ">" outside a quoted attribute value (tagEnd). A comment ends at
// "-->" (commentEnd); a raw-text element at its own closing tag (whose name ends there,
// quote-aware). Anything left open (a tag, a quote, a comment, an element)
// hides the rest, as in a browser. Markers inside a comment or an element's
// raw text are never read as markup.
func stripMarkup(html string) string {
	lower := asciiLower(html)
	var out strings.Builder
	sourceBreaks := strings.NewReplacer("\r", " ", "\n", " ")
	emit := func(text string) { _, _ = sourceBreaks.WriteString(&out, text) }
	i, n := 0, len(html)
	for {
		j := indexFrom(html, "<", i)
		if j < 0 {
			emit(html[i:])
			break
		}
		if strings.HasPrefix(html[j:], "<!--") {
			k := commentEnd(html, j)
			emit(html[i:j])
			if k < 0 {
				break
			}
			i = k
			continue
		}
		if j+1 >= n || !isTagStart(html[j+1]) {
			emit(html[i : j+1])
			i = j + 1
			continue
		}
		end, selfClosing := tagScan(html, j)
		emit(html[i:j])
		if end < 0 { // the rest is inside the tag
			break
		}
		switch name := tagName(lower, j); {
		case blockTags[name]:
			out.WriteString("\n")
		case name == "br":
			out.WriteString(" ")
		}
		if lit := openingName(lower, j, literalNames); lit != "" {
			text, next := literalText(html, lower, lit, end)
			emit(text)
			if next < 0 { // the rest is its text
				break
			}
			if blockTags[lit] {
				out.WriteString("\n")
			}
			i = next
			continue
		}
		name := rawTextName(lower, j)
		if name == "" || (selfClosing && (name == "svg" || name == "math")) { // <svg/> is empty
			i = end + 1
			continue
		}
		if i = dropEnd(html, lower, name, end); i < 0 && name == "head" {
			i = end + 1
		} else if i < 0 { // left open: the rest is the element's
			break
		}
	}
	return out.String()
}

// htmlSpace is every rune Python's str.isspace() calls whitespace: once
// they are spaces, Go's \s and Python's agree on where a URL ends.
func htmlSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, ' ', 0x85, 0xa0, 0x1680,
		0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return 0x2000 <= r && r <= 0x200a
}

// urlStop is a rune the text-URL pattern stops at besides whitespace.
func urlStop(r rune) bool {
	return htmlSpace(r) || strings.ContainsRune("<>\"')]}", r)
}

// charRefRE: named references end in ";"; HTML also decodes a few legacy
// names without it (of those, only these spell a separator), and numeric
// references without it. Same pattern as the archiver's _CHAR_REF_RE.
var charRefRE = regexp.MustCompile(`&(?:([A-Za-z][A-Za-z0-9]{1,31});|#0*([0-9]{1,7});?|#[xX]0*([0-9a-fA-F]{1,6});?|(nbsp|quot|QUOT|lt|LT|gt|GT))`)

// separatorRef reports whether the character reference m starts with
// whitespace or a URL stop: named ones through the HTML5 table, numeric ones
// by their code point (0x80-0x9F decode to windows-1252 characters, none of
// them a stop), as the archiver's _separator_ref.
func separatorRef(m string) bool {
	g := charRefRE.FindStringSubmatch(m)
	if g[4] != "" { // a legacy name without ";" that spells a separator
		return true
	}
	if g[1] != "" {
		decoded := stdhtml.UnescapeString(m)
		if decoded == m || decoded == "" {
			return false
		}
		// The URL shown ends at the first decoded rune: &nvlt; is "<" plus an overlay.
		first, _ := utf8.DecodeRuneInString(decoded)
		return urlStop(first)
	}
	digits, base := g[2], 10
	if digits == "" {
		digits, base = g[3], 16
	}
	// At most 7 decimal or 6 hex digits: always fits in 32 bits.
	code, err := strconv.ParseInt(digits, base, 32)
	return err == nil && (code < 0x80 || code > 0x9f) && code < 0x110000 && urlStop(rune(code))
}

// spaceOut turns whitespace characters, and every character reference
// (named, decimal or hex) that spells only whitespace or the runes the URL
// pattern stops at (&nbsp;, &hairsp;, &quot;, &lt;, &#39; ...), into spaces,
// leaving everything else as written (the archiver's _space_out).
func spaceOut(text string) string {
	text = charRefRE.ReplaceAllStringFunc(text, func(m string) string {
		if g := charRefRE.FindStringSubmatch(m); g[1] != "" && stdhtml.UnescapeString(m) == m {
			// Not a name: HTML still reads a legacy name at its start ("&nbspNext;").
			for _, legacy := range []string{"nbsp", "quot", "QUOT", "lt", "LT", "gt", "GT"} {
				if strings.HasPrefix(g[1], legacy) {
					return " " + m[1+len(legacy):]
				}
			}
			return m
		}
		if separatorRef(m) {
			return " "
		}
		return m
	})
	return spaceRunes(text)
}

// spaceRunes turns every whitespace rune but CR and LF into a space, so the
// text-URL pattern ends a URL where Python's Unicode \s does (CR and LF stay
// for its quoted-printable soft break, and \s is CR/LF in both).
func spaceRunes(text string) string {
	return strings.Map(func(r rune) rune {
		if r != '\r' && r != '\n' && htmlSpace(r) {
			return ' '
		}
		return r
	}, text)
}

// extractHTMLTextURLs lists the URLs written as text in an HTML part,
// outside its tags, comments and attribute values (so not hrefs), with its
// <style>/<script> blocks left out and whitespace entities as separators;
// otherwise as written (&amp; kept, as in an href). The archiver's
// extract_urls_from_html_text.
func extractHTMLTextURLs(html string) []string {
	html = truncateToRunes(html, maxScanRunes)
	var out []string
	for _, raw := range textURLRE.FindAllString(spaceOut(stripMarkup(html)), -1) {
		if u := cleanBareURL(raw); u != "" {
			out = append(out, u)
		}
	}
	return out
}

var trailingRefRE = regexp.MustCompile(`&(?:([A-Za-z][A-Za-z0-9]{1,31});|#0*([0-9]{1,7});?|#[xX]0*([0-9a-fA-F]{1,6});?)$`)

// cleanBareURL is cleanURL for a URL written as text in HTML: literal
// trailing punctuation goes, and so does punctuation written as a real
// reference ("report.csv&period; Next" ends at ".csv"), checked before a
// trailing ";" is dropped so "...?mode=full&period" (no ";", not a
// reference) keeps its "&period". Named references decode through the
// HTML5 table, numeric ones by code point. The archiver's _clean_bare_url.
func cleanBareURL(raw string) string {
	u := strings.TrimSpace(strings.NewReplacer("\n", "", "\r", "").Replace(lineContRE.ReplaceAllString(raw, "")))
	for u != "" {
		if loc := trailingRefRE.FindStringSubmatchIndex(u); loc != nil {
			var char string
			if loc[2] >= 0 {
				char = stdhtml.UnescapeString("&" + u[loc[2]:loc[3]] + ";")
			} else {
				digits, base := "", 10
				if loc[4] >= 0 {
					digits = u[loc[4]:loc[5]]
				} else {
					digits, base = u[loc[6]:loc[7]], 16
				}
				// At most 7 decimal or 6 hex digits: always fits in 32 bits.
				if code, err := strconv.ParseInt(digits, base, 32); err == nil && code < 0x110000 && (code < 0x80 || code > 0x9f) {
					char = string(rune(code))
				}
			}
			if len(char) == 1 && strings.IndexByte(".,;:!?", char[0]) >= 0 {
				u = u[:loc[0]]
				continue
			}
		}
		if strings.IndexByte(".,;:!?", u[len(u)-1]) < 0 {
			break
		}
		u = u[:len(u)-1]
	}
	return u
}

// bodyLink is a link of a body; bare marks one found only as text in HTML.
type bodyLink struct {
	url, text string
	bare      bool
}

func extractHTMLLinks(html string) []bodyLink {
	var out []bodyLink
	for _, m := range htmlLinkRE.FindAllStringSubmatch(html, -1) {
		href := strings.TrimSpace(m[1])
		if lower := strings.ToLower(href); strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			text := strings.Join(strings.Fields(tagRE.ReplaceAllString(m[2], " ")), " ")
			out = append(out, bodyLink{url: cleanURL(href), text: text})
		}
	}
	return out
}

// allBodies joins every non-attachment text/plain part and every
// text/html part, as the archiver does.
func allBodies(msg *mailmsg.Part) (plain, html string) {
	var plains, htmls []string
	for _, part := range bodyParts(msg) {
		if part.MainType() == "multipart" {
			continue
		}
		payload, ok := part.Payload()
		if !ok {
			continue
		}
		switch part.ContentType() {
		case "text/plain":
			plains = append(plains, mailmsg.DecodeBytes(payload, part.Charset()))
		case "text/html":
			htmls = append(htmls, mailmsg.DecodeBytes(payload, part.Charset()))
		}
	}
	return strings.Join(plains, "\n"), strings.Join(htmls, "\n")
}

// bodyParts walks the message's own parts: it never descends into an
// attachment or an attached message, whose text is not this email's body.
func bodyParts(p *mailmsg.Part) []*mailmsg.Part {
	out := []*mailmsg.Part{p}
	for _, c := range p.Children {
		if strings.Contains(strings.ToLower(c.Header.Get("Content-Disposition")), "attachment") || c.ContentType() == "message/rfc822" {
			continue
		}
		out = append(out, bodyParts(c)...)
	}
	return out
}

func parsedURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func isClickTracker(raw string) bool {
	u := parsedURL(raw)
	host, p := strings.ToLower(u.Host), strings.ToLower(u.Path)
	for _, pat := range clickTrackerPatterns {
		hostOK := pat[0] == "" || host == pat[0] || strings.HasSuffix(host, "."+pat[0])
		pathOK := pat[1] == "" || strings.Contains(p, pat[1])
		if (pat[0] != "" || pat[1] != "") && hostOK && pathOK {
			return true
		}
	}
	return false
}

func hasHTTPScheme(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// unwrapOnce peels one known redirector/security wrapper (Proofpoint v2/v3,
// Amazon Ads CL0, awstrack L0), or returns "".
func unwrapOnce(raw string) string {
	u := parsedURL(raw)
	host := strings.ToLower(u.Host)
	if strings.Contains(host, "urldefense.proofpoint.com") && strings.Contains(u.Path, "/v2/url") {
		if enc := u.Query().Get("u"); enc != "" {
			return unquote(strings.ReplaceAll(strings.ReplaceAll(enc, "_", "/"), "-", "%"))
		}
	}
	if strings.Contains(host, "urldefense.com") || strings.Contains(host, "urldefense.proofpoint.com") {
		if m := proofpointV3.FindStringSubmatch(raw); m != nil {
			return m[1]
		}
	}
	marker := ""
	switch {
	case strings.HasSuffix(host, "r.ads.amazon.com"):
		marker = "/CL0/"
	case strings.HasSuffix(host, "awstrack.me"):
		marker = "/L0/"
	}
	if marker != "" {
		if i := strings.Index(raw, marker); i >= 0 {
			seg, _, _ := strings.Cut(raw[i+len(marker):], "/")
			if inner := unquote(seg); hasHTTPScheme(inner) {
				return inner
			}
		}
	}
	return ""
}

func unwrapURL(raw string) string {
	current := raw
	for range 3 {
		inner := unwrapOnce(current)
		if inner == "" || !hasHTTPScheme(inner) {
			return current
		}
		current = cleanURL(inner)
	}
	return current
}

// pageExtensions are web pages, never a file payload (the archiver's
// PAGE_EXTENSIONS).
var pageExtensions = setOf(".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp", ".cgi")

// hasFileEvidence reports whether raw names a file (a download extension,
// not a page or an image) or is presigned: the archiver's
// has_file_evidence, which a bare URL in HTML text needs to be listed, since
// such text is often a "paste this link" fallback for a sign-in or
// verification button.
func hasFileEvidence(raw string) bool {
	u := parsedURL(unwrapURL(cleanURL(raw)))
	if isPresigned(u) {
		return true
	}
	// Python's urlparse leaves ";params" of the last segment out of the path,
	// and Path(...).suffix ignores a trailing "/".
	p := u.EscapedPath()
	if k := strings.LastIndex(p, "/"); strings.Contains(p[k+1:], ";") {
		p = p[:k+1+strings.Index(p[k+1:], ";")]
	}
	ext := strings.ToLower(path.Ext(path.Base(unquote(p))))
	return downloadExtensions[ext] && !pageExtensions[ext] && !imageExtensions[ext]
}

func isPresigned(u *url.URL) bool {
	q := strings.ToLower(u.RawQuery)
	if strings.Contains(q, "x-amz-signature") || strings.Contains(q, "x-amz-credential") || strings.Contains(q, "x-goog-signature") {
		return true
	}
	return strings.Contains(strings.ToLower(u.Host), "blob.core.windows.net") && strings.Contains(q, "sig=") && strings.Contains(q, "sv=")
}

func isJunkHost(host string) bool {
	host = strings.ToLower(host)
	for _, s := range junkHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// DownloadLink is a body link classified as a likely payload. URL is the
// string exactly as extracted (the cache key); FetchURL is the same link
// with HTML entities (&amp;) decoded, the form a live request needs.
type DownloadLink struct {
	URL            string `json:"url"`
	FetchURL       string `json:"-"`
	Filename       string `json:"filename,omitempty"`
	LinkText       string `json:"link_text,omitempty"`
	IsClickTracker bool   `json:"is_click_tracker"`
}

// URLHash is the archiver's cache key for url: hex SHA-256 of the exact
// string.
func URLHash(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
}

// classifyURL reports whether raw is a likely download link and its
// cleaned form and filename.
func classifyURL(raw string) (cleaned, filename string, downloadLikely, clickTracker bool) {
	cleaned = cleanURL(raw)
	target := unwrapURL(cleaned)
	u := parsedURL(target)
	p := unquote(u.EscapedPath())
	if p != "" {
		if base := path.Base(p); base != "/" && base != "." {
			filename = base
		}
	}
	ext := strings.ToLower(path.Ext(filename))
	isImage := imageExtensions[ext]
	isDownloadExt := downloadExtensions[ext] && !isImage
	lowerTarget := strings.ToLower(target)
	hasKeyword := false
	for _, kw := range downloadKeywords {
		if strings.Contains(lowerTarget, kw) {
			hasKeyword = true
			break
		}
	}
	query := strings.ToLower(u.RawQuery)
	hasParam := false
	for _, prm := range downloadParams {
		if strings.Contains(query, prm) {
			hasParam = true
			break
		}
	}
	clickTracker = isClickTracker(cleaned) || isClickTracker(target)
	presigned := isPresigned(u)
	unsubscribe := (unsubscribeRE.MatchString(cleaned) || unsubscribeRE.MatchString(target)) && !isDownloadExt && !presigned
	downloadLikely = (isDownloadExt || hasKeyword || hasParam || clickTracker || presigned) &&
		!isImage && !isJunkHost(u.Host) && !unsubscribe
	return cleaned, filename, downloadLikely, clickTracker
}

var ampRefRE = regexp.MustCompile(`&(?:(?:amp|AMP);?|#0*38(;?)|#[xX]0*26(;?))`)

// dedupeKey: a bare HTML URL repeats an earlier link when they are equal
// with &amp; (any spelling) read as "&", the one difference between a
// multipart message's text and HTML spellings. Nothing else is decoded, so
// this agrees with the archiver's _dedupe_key whatever the entity decoders do.
func dedupeKey(u string) string {
	var out strings.Builder
	last := 0
	for _, m := range ampRefRE.FindAllStringSubmatchIndex(u, -1) {
		out.WriteString(u[last:m[0]])
		last = m[1]
		// A numeric reference without ";" ends at its last digit: "&#380" is
		// not "&#38" + "0" (the archiver's _amp_ref).
		next := byte(0)
		if m[1] < len(u) {
			next = u[m[1]]
		}
		decimal := m[2] >= 0 && m[2] == m[3] && '0' <= next && next <= '9'
		hexa := m[4] >= 0 && m[4] == m[5] && (('0' <= next && next <= '9') || ('a' <= next && next <= 'f') || ('A' <= next && next <= 'F'))
		if decimal || hexa {
			out.WriteString(u[m[0]:m[1]])
		} else {
			out.WriteString("&")
		}
	}
	out.WriteString(u[last:])
	return out.String()
}

// bodyURLs lists a body's distinct links in the archiver's order:
// plain-text URLs, then HTML anchors (whose text wins), then bare URLs in the
// HTML's text not seen before as written or entity-decoded.
func bodyURLs(plain, html string) []bodyLink {
	var out []bodyLink
	index := map[string]int{}
	add := func(l bodyLink) {
		if i, ok := index[l.url]; ok {
			if l.text != "" {
				out[i].text = l.text
			}
			return
		}
		index[l.url] = len(out)
		out = append(out, l)
	}
	// Cut as the archiver cuts (MAX_SCAN_CHARS), so the dedupe below sees the
	// same earlier links.
	plainURLs := extractTextURLs(spaceRunes(truncateToRunes(plain, maxScanRunes)))
	for _, u := range plainURLs {
		add(bodyLink{url: u})
	}
	html = truncateToRunes(html, maxScanRunes)
	for _, l := range extractHTMLLinks(html) {
		add(l)
	}
	// A bare URL repeats a text/plain URL when their dedupe keys match (a
	// multipart message's two spellings), and any earlier link when it is the
	// same string: anchors are compared as written only, so an anchor one
	// implementation reads and the other skips cannot change which spelling
	// is archived.
	seen := make(map[string]bool, len(plainURLs))
	for _, u := range plainURLs {
		seen[dedupeKey(u)] = true
	}
	// Bare URLs come from what the renderer shows: after its pre-strip pass
	// (blocks, then Outlook conditional regions; the archiver also reads
	// those regions, so it may archive more; a URL listed here is extracted
	// as it does). The pass runs on the cut body, so a long removed block
	// cannot bring text past the archiver's cut into the scan.
	for _, u := range extractHTMLTextURLs(htmlsafe.PreStrip(html)) {
		decoded := dedupeKey(u)
		if _, ok := index[u]; ok || seen[decoded] {
			continue
		}
		seen[decoded] = true
		add(bodyLink{url: u, bare: true})
	}
	return out
}

// downloadLinks lists the distinct likely-payload links of a body.
func downloadLinks(plain, html string) []DownloadLink {
	var out []DownloadLink
	for _, l := range bodyURLs(plain, html) {
		cleaned, filename, likely, tracker := classifyURL(l.url)
		if l.bare {
			// A URL found only as text in HTML is judged on the request it makes
			// (entities decoded), and needs file evidence, as in the archiver.
			decoded := stdhtml.UnescapeString(l.url)
			_, filename, likely, tracker = classifyURL(decoded)
			likely = likely && hasFileEvidence(decoded)
		}
		if likely {
			out = append(out, DownloadLink{URL: cleaned, FetchURL: stdhtml.UnescapeString(cleaned),
				Filename: filename, LinkText: truncateRunes(l.text, 200), IsClickTracker: tracker})
		}
	}
	return out
}
