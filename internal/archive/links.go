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
	"sort"
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
// Only a textarea (RCDATA) decodes character references; in the others
// (RAWTEXT, plaintext) "&lt;" is shown as written, so their "&" is returned
// escaped ("&amp;"), never read later as a reference or a separator.
func literalText(html, lower, name string, end int) (string, int) {
	text, next := html[end+1:], -1
	if name != "plaintext" {
		if k := closingTag(lower, name, end+1); k >= 0 {
			text = html[end+1 : k]
			if e := tagEnd(html, k); e >= 0 {
				next = e + 1
			}
		}
	}
	if name != "textarea" {
		text = strings.ReplaceAll(text, "&", "&amp;")
	}
	return text, next
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
// "breakout" list): dropEnd resumes at the tag, read as HTML. <font> breaks
// out only with a color, face or size attribute, so it hides the rest
// instead. The archiver's _BREAKOUT.
var breakoutTags = map[string]bool{
	"b": true, "big": true, "blockquote": true, "body": true, "br": true, "center": true, "code": true,
	"dd": true, "div": true, "dl": true, "dt": true, "em": true, "embed": true, "font": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "head": true, "hr": true, "i": true,
	"img": true, "li": true, "listing": true, "menu": true, "meta": true, "nobr": true, "ol": true, "p": true,
	"pre": true, "ruby": true, "s": true, "small": true, "span": true, "strike": true, "strong": true,
	"sub": true, "sup": true, "table": true, "tt": true, "u": true, "ul": true, "var": true,
}

// integrationTags are SVG and MathML elements whose content a browser
// parses as HTML (integration points), each only in its own namespace
// (annotation-xml only with certain encodings, taken here as always), and
// swallowTags the HTML elements that swallow a template's closing tag
// (dropEnd skips the raw text of style, script and title, and hides the
// rest at any other). The archiver's _INTEGRATION and _SWALLOW.
var (
	integrationTags = map[string]map[string]bool{
		"svg":  setOf("foreignobject", "desc", "title"),
		"math": setOf("mi", "mo", "mn", "ms", "mtext", "annotation-xml"),
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
// name ends there, quote-aware). A template ends at its matching closing
// tag: a nested template opens a level, and a comment is skipped, as are its
// own raw-text, SVG and MathML children; an element that swallows its
// closing tag (swallowTags) other than that raw text hides the rest. SVG and
// MathML: foreignEnd. The archiver's _drop_end.
func dropEnd(html, lower, name string, end int) int {
	if name != "template" && name != "svg" && name != "math" {
		return rawTextEnd(html, lower, name, end)
	}
	if name != "template" {
		return foreignEnd(html, lower, name, end)
	}
	depth, n, i := 1, len(html), end+1
	for {
		j := indexFrom(html, "<", i)
		if j < 0 {
			return -1
		}
		if strings.HasPrefix(html[j:], "<!--") {
			if i = commentEnd(html, j); i < 0 {
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
		if inner := rawTextName(lower, j); templateChild(inner, selfClosing) {
			if i = dropEnd(html, lower, inner, e); i < 0 {
				return -1
			}
			continue
		}
		tag, closing := tagName(lower, j), strings.HasPrefix(lower[j:], "</")
		switch {
		case tag == "template" && closing:
			if depth--; depth == 0 {
				return e + 1
			}
		case tag == "template":
			depth++
		case !closing && swallowTags[tag]:
			return -1
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

// openElement is one element on foreignEnd's stack: SVG/MathML (an
// integration point when its content is HTML) or HTML.
type openElement struct {
	tag, ns      string // ns: the namespace of a foreign element ("svg" or "math")
	html, intPnt bool
}

// elementKey names the open elements of one tag in one namespace.
type elementKey struct {
	tag  string
	html bool
}

// foreignScan is foreignEnd's stack of open elements, with indexes kept as
// it grows and shrinks (the positions of each tag, of HTML elements and of
// integration points), so every tag is read in constant time however deep
// the stack. The archiver's _ForeignStack.
type foreignScan struct {
	stack         []openElement
	byName        map[elementKey][]int
	htmls, points []int
	// HTML special elements (htmlSpecial) and scope walls (htmlWalls), and
	// the specials an li/dd/dt start does not close past
	specials, walls, listWalls []int
	// the form element pointer: set once an HTML form opens, until a form
	// end tag; form is its position while it is open, or -1
	formSet bool
	form    int
	// staleAt: for each formatting element (formattingTags) closed by
	// something other than its own end tag, the innermost marker element
	// (markerTags) open below it, or -1. The parser reopens such an element
	// at the next text or start tag in HTML content until that marker
	// closes; the scan does not model reopening and hides the rest there
	// instead. markers are the open marker elements' positions.
	staleAt, markers []int
}

func newForeignScan(root string) *foreignScan {
	f := &foreignScan{byName: map[elementKey][]int{}, form: -1}
	f.push(openElement{tag: root, ns: root})
	return f
}

func (f *foreignScan) push(el openElement) {
	k := len(f.stack)
	f.stack = append(f.stack, el)
	key := elementKey{el.tag, el.html}
	f.byName[key] = append(f.byName[key], k)
	if el.html {
		f.htmls = append(f.htmls, k)
		if htmlSpecial[el.tag] {
			f.specials = append(f.specials, k)
			if !listOpen[el.tag] {
				f.listWalls = append(f.listWalls, k)
			}
		}
		if htmlWalls[el.tag] {
			f.walls = append(f.walls, k)
		}
		if markerTags[el.tag] {
			f.markers = append(f.markers, k)
		}
	}
	if el.intPnt {
		f.points = append(f.points, k)
	}
}

// cut closes every element from position size up.
func (f *foreignScan) cut(size int) {
	if f.form >= size {
		f.form = -1
	}
	for len(f.stack) > size {
		p := len(f.stack) - 1
		el := f.stack[p]
		if el.html && formattingTags[el.tag] {
			f.staleAt = append(f.staleAt, lastAtOrBelow(f.markers, p))
		}
		if el.html && markerTags[el.tag] { // closing a marker clears what went stale inside it
			kept := f.staleAt[:0]
			for _, at := range f.staleAt {
				if at < p {
					kept = append(kept, at)
				}
			}
			f.staleAt = kept
			f.markers = f.markers[:len(f.markers)-1]
		}
		f.stack = f.stack[:p]
		key := elementKey{el.tag, el.html}
		f.byName[key] = f.byName[key][:len(f.byName[key])-1]
		if el.html {
			f.htmls = f.htmls[:len(f.htmls)-1]
			if htmlSpecial[el.tag] {
				f.specials = f.specials[:len(f.specials)-1]
				if !listOpen[el.tag] {
					f.listWalls = f.listWalls[:len(f.listWalls)-1]
				}
			}
			if htmlWalls[el.tag] {
				f.walls = f.walls[:len(f.walls)-1]
			}
		}
		if el.intPnt {
			f.points = f.points[:len(f.points)-1]
		}
	}
}

// remove takes the element at position m off the stack and leaves the ones
// above it open, as a form end tag does.
func (f *foreignScan) remove(m int) {
	above := append([]openElement(nil), f.stack[m+1:]...)
	stale := append([]int(nil), f.staleAt...)
	f.cut(m)
	f.staleAt = stale
	for _, el := range above {
		f.push(el)
	}
}

// closeFormatting closes the formatting element at position m and what is
// open above it, as its own end tag or a new <a> does: m itself is no
// longer active, but a formatting element above it stays active (stale).
func (f *foreignScan) closeFormatting(m int) {
	f.cut(m + 1)
	stale := append([]int(nil), f.staleAt...)
	f.cut(m)
	f.staleAt = stale
}

// formatting reads a start tag a or nobr, or a formatting element's end
// tag, as the adoption agency does in its simple case: an open element
// with no special element above it closes (ok, handled). One that is not
// open is left to the caller (ok, not handled); an open one out of scope
// or under a special element is not modeled (not ok: hide the rest).
func (f *foreignScan) formatting(t string, top int) (ok, handled bool) {
	m := f.htmlLast(t, top)
	if m <= 0 {
		return true, false
	}
	if m < max(lastAtOrBelow(f.points, top), lastAtOrBelow(f.walls, top)) || lastAtOrBelow(f.specials, top) > m {
		return false, true
	}
	f.closeFormatting(m)
	return true, true
}

// reconstructs reports whether text or a start tag here makes the parser
// reopen a stale formatting element: in HTML content (an HTML element or
// an integration point on top).
func (f *foreignScan) reconstructs() bool {
	top := f.stack[len(f.stack)-1]
	return len(f.staleAt) > 0 && (top.html || top.intPnt)
}

// lastAtOrBelow is the last of positions (ascending) at or below below, or
// -1.
func lastAtOrBelow(positions []int, below int) int {
	k := sort.SearchInts(positions, below+1) - 1
	if k < 0 {
		return -1
	}
	return positions[k]
}

// htmlSpecial are the HTML parser's special elements: an ordinary end tag
// ("any other end tag") does not close past one. A special end tag closes
// past them, but not past a scope wall (htmlWalls). The archiver's
// _HTML_SPECIAL and _HTML_WALLS.
var (
	htmlSpecial = setOf("address", "applet", "area", "article", "aside", "base", "basefont", "bgsound",
		"blockquote", "body", "br", "button", "caption", "center", "col", "colgroup", "dd", "details", "dir",
		"div", "dl", "dt", "embed", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset",
		"h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe", "img", "input",
		"keygen", "li", "link", "listing", "main", "marquee", "menu", "meta", "nav", "noembed", "noframes",
		"noscript", "object", "ol", "p", "param", "plaintext", "pre", "script", "search", "section", "select",
		"source", "style", "summary", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead",
		"title", "tr", "track", "ul", "wbr", "xmp")
	htmlWalls = setOf("applet", "caption", "html", "table", "td", "th", "marquee", "object", "template")
	// listOpen are the specials an li/dd/dt start closes past (or closes)
	listOpen = setOf("address", "div", "p", "li", "dd", "dt")
	// closesP are start tags that first close an open p (button scope). The
	// archiver's _CLOSES_P.
	closesP = setOf("address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div",
		"dl", "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "main", "menu", "nav", "ol",
		"p", "search", "section", "summary", "ul", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "listing",
		"form", "li", "dd", "dt", "table", "hr", "xmp")
	// impliedEnds close before a form end tag removes the form
	impliedEnds = setOf("dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt", "rtc")
	headingTags = setOf("h1", "h2", "h3", "h4", "h5", "h6")
	// tableOnly are the start tags the in-body rule ignores outside a table
	tableOnly = setOf("caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr")
	// markerTags put a marker in the list of active formatting elements:
	// what goes stale inside one is cleared when it closes
	markerTags = setOf("applet", "caption", "marquee", "object", "td", "th", "template")
	// formattingTags are the parser's formatting elements: closed by
	// something other than their own end tag, they stay active and reopen
	formattingTags = setOf("a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong",
		"tt", "u")
	mathTextPoints = setOf("mi", "mo", "mn", "ms", "mtext")
)

// skipToClose are elements read as HTML whose content is raw text or
// RCDATA: skipped to their own closing tag. (A template or plaintext inside
// an integration point still hides the rest.) The archiver's
// _SKIP_TO_CLOSE.
var skipToClose = setOf("script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript")

// htmlVoid are HTML void elements: never open, so never on a stack of open
// elements. The archiver's _HTML_VOID.
var htmlVoid = setOf("area", "base", "basefont", "bgsound", "br", "col", "embed", "hr", "img", "input",
	"keygen", "link", "meta", "param", "source", "track", "wbr")

// foreignEnd is where the SVG or MathML element name whose start tag ends
// at html[end] ends, or a position to resume at, or -1 to hide the rest, by
// a small stack of open elements (foreignScan), each foreign (an
// integration point when its content is HTML: integrationTags) or HTML
// (opened inside an integration point).
//
// Start tags: where the current element is HTML or an integration point, a
// tag is HTML (svg and math open foreign elements; raw text or RCDATA is
// skipped to its own closing tag, skipToClose; a template or plaintext
// hides the rest); elsewhere a
// breakout tag (breakoutTags) closes the foreign elements up to the nearest
// HTML element or integration point and is read there as HTML, and with
// none inside, ends name: the scan resumes at the tag (a <font>, a breakout
// only with certain attributes, hides the rest instead). End tags: from a
// foreign current element, the nearest open element of that name closes,
// and an HTML element on the way hands the tag to the HTML rule; from an
// HTML one, the nearest open HTML element of that name closes and an
// integration point on the way ignores the tag; </p> and </br> are
// breakouts like start tags, then read by the HTML rule. A walk past name
// (it could close something outside) hides the rest. Comments are skipped,
// and "<![CDATA[" too (skip). The content is the foreign element's either
// way, dropped. The archiver's _foreign_end.
func foreignEnd(html, lower, name string, end int) int {
	f := newForeignScan(name)
	n, i := len(html), end+1
	for {
		j := indexFrom(html, "<", i)
		if j < 0 {
			return -1
		}
		if j > i && f.reconstructs() { // text reopens a stale formatting element
			return -1
		}
		if next, skipped := f.skip(html, j); skipped {
			if i = next; i < 0 {
				return -1
			}
			continue
		}
		if j+1 >= n || !isTagStart(html[j+1]) {
			if f.reconstructs() { // a "<" that is text
				return -1
			}
			i = j + 1
			continue
		}
		e, selfClosing := tagScan(html, j)
		if e < 0 {
			return -1
		}
		i = e + 1
		t := tagName(lower, j)
		if t == "" { // "<!x>", "<?x>": a bogus comment
			continue
		}
		closing := strings.HasPrefix(lower[j:], "</")
		if top := f.stack[len(f.stack)-1]; (top.html || top.intPnt) && !closing && skipToClose[t] {
			// raw text or RCDATA read as HTML: its content runs to its own
			// closing tag (none: the rest); an xmp first closes an open p
			if len(f.staleAt) > 0 {
				return -1
			}
			f.impliedClose(t)
			k := closingTag(lower, t, i)
			if k < 0 {
				return -1
			}
			ke := tagEnd(html, k)
			if ke < 0 {
				return -1
			}
			i = ke + 1
			continue
		}
		if r := f.tag(html, t, closing, selfClosing, j, e); r != 0 {
			return r
		}
	}
}

// skip is just past the comment or "<![CDATA[" starting at html[j] (a CDATA
// section in a foreign element, a bogus comment under an HTML one), or -1
// when it is left open; skipped is false when neither starts there.
func (f *foreignScan) skip(html string, j int) (int, bool) {
	if strings.HasPrefix(html[j:], "<!--") {
		return commentEnd(html, j), true
	}
	if !strings.HasPrefix(html[j:], "<![CDATA[") {
		return 0, false
	}
	// in a foreign element (an integration point included) a CDATA section,
	// to "]]>"; under an HTML element a bogus comment, to the first ">"
	if f.stack[len(f.stack)-1].html {
		if k := indexFrom(html, ">", j+9); k >= 0 {
			return k + 1, true
		}
		return -1, true
	}
	if k := indexFrom(html, "]]>", j+9); k >= 0 {
		return k + 3, true
	}
	return -1, true
}

// inside is the nearest HTML element or integration point above the root,
// or 0 when there is none.
func (f *foreignScan) inside() int {
	k := 0
	if len(f.htmls) > 0 {
		k = f.htmls[len(f.htmls)-1]
	}
	if len(f.points) > 0 && f.points[len(f.points)-1] > k {
		k = f.points[len(f.points)-1]
	}
	return k
}

// tag reads tag t at html[j] (ending at html[e]): 0 to go on, e+1 when the
// element ends, j to resume there, or -1 to hide the rest.
func (f *foreignScan) tag(html, t string, closing, selfClosing bool, j, e int) int {
	top := f.stack[len(f.stack)-1]
	htmlMode := top.html || top.intPnt
	breakout := !htmlMode && ((closing && (t == "p" || t == "br")) || (!closing && breakoutTags[t]))
	if breakout && t == "font" && !closing {
		// a font breaks out only with a color, face or size attribute
		_, color := tagAttr(html, j, e, "color")
		_, face := tagAttr(html, j, e, "face")
		_, size := tagAttr(html, j, e, "size")
		breakout = color || face || size
	}
	if breakout {
		k := f.inside()
		if k == 0 {
			return j // name ends here, as in a browser
		}
		f.cut(k + 1) // back to the nearest HTML element or integration point, read there as HTML
		htmlMode = true
		top = f.stack[len(f.stack)-1]
	}
	if !closing {
		if top.intPnt && top.ns == "math" && mathTextPoints[top.tag] && (t == "mglyph" || t == "malignmark") {
			htmlMode = false // these stay MathML at a MathML text integration point
		}
		if htmlMode && len(f.staleAt) > 0 { // a start tag in HTML content reopens a stale formatting element
			return -1
		}
		if htmlMode && (t == "a" || t == "nobr") { // an open one closes first
			if ok, _ := f.formatting(t, len(f.stack)-1); !ok {
				return -1
			}
		}
		return f.startTag(html, t, htmlMode, selfClosing, j, e)
	}
	if top.html || breakout {
		if !f.htmlRule(t, len(f.stack)-1) {
			return -1
		}
		return 0
	}
	return f.foreignRule(t, e)
}

// startTag opens t (its tag html[j:e+1]), read as HTML when htmlMode: 0,
// or -1 to hide the rest.
func (f *foreignScan) startTag(html, t string, htmlMode, selfClosing bool, j, e int) int {
	if htmlMode && t == "form" && f.formSet {
		return 0 // a second form while the pointer is set is ignored
	}
	if htmlMode && (t == "html" || t == "head" || t == "body" || t == "frame") {
		return 0 // the in-body rule never opens these
	}
	if htmlMode && t == "input" { // an input closes an open select (in scope)
		top := len(f.stack) - 1
		if m := f.htmlLast("select", top); m > max(lastAtOrBelow(f.points, top), lastAtOrBelow(f.walls, top)) {
			f.cut(m)
		}
	}
	if htmlMode && tableOnly[t] {
		top := len(f.stack) - 1
		if f.htmlLast("table", top) <= lastAtOrBelow(f.points, top) {
			return 0 // nor a table part outside a table
		}
	}
	if htmlMode && t != "svg" && t != "math" {
		f.impliedClose(t)
	}
	switch {
	case !htmlMode:
		if !selfClosing {
			// a foreign element takes its parent's namespace (svg in a
			// MathML annotation-xml is SVG)
			top := f.stack[len(f.stack)-1]
			ns := top.ns
			if ns == "math" && top.tag == "annotation-xml" && t == "svg" {
				ns = "svg"
			}
			ip := integrationTags[ns][t]
			if ip && t == "annotation-xml" { // an HTML integration point only for an HTML encoding
				enc := strings.ToLower(strings.TrimSpace(stdhtml.UnescapeString(attrValue(html, j, e, "encoding"))))
				ip = enc == "text/html" || enc == "application/xhtml+xml"
			}
			f.push(openElement{tag: t, ns: ns, intPnt: ip})
		}
	case t == "svg" || t == "math":
		if !selfClosing {
			f.push(openElement{tag: t, ns: t})
		}
	case swallowTags[t]:
		return -1
	case !htmlVoid[t]:
		if t == "form" {
			f.formSet, f.form = true, len(f.stack)
		}
		f.push(openElement{tag: t, html: true})
	}
	return 0
}

// htmlRule reads end tag t by the HTML rule from stack[top] down: the
// nearest open HTML element of that name closes, unless a barrier comes
// first and the tag is ignored: an integration point, and for an ordinary
// tag any special element, for a special one a scope wall; a heading's end
// tag closes any open heading. False when neither (it walks past the root).
func (f *foreignScan) htmlRule(t string, top int) bool {
	if t == "form" {
		return f.formEnd(top)
	}
	if formattingTags[t] {
		if ok, handled := f.formatting(t, top); handled {
			return ok
		}
	}
	match := f.htmlLast(t, top)
	if headingTags[t] {
		for h := range headingTags {
			match = max(match, f.htmlLast(h, top))
		}
	}
	walls := f.specials
	if htmlSpecial[t] {
		walls = f.walls
	}
	barrier := max(lastAtOrBelow(f.points, top), lastAtOrBelow(walls, top))
	switch t {
	case "li": // list item scope also stops at a list
		barrier = max(barrier, f.htmlLast("ul", top), f.htmlLast("ol", top))
	case "p": // button scope also stops at a button
		barrier = max(barrier, f.htmlLast("button", top))
	}
	if match > 0 && match >= barrier { // a wall closes at its own end tag
		f.cut(match)
		return true
	}
	return barrier > 0
}

// formEnd reads a form end tag: the pointer clears, and the form it named,
// when open and in scope, comes off the stack after the implied end tags;
// the elements above it stay open. Otherwise the tag is ignored.
func (f *foreignScan) formEnd(top int) bool {
	m := f.form
	f.formSet, f.form = false, -1
	if m < 0 || m > top || m <= max(lastAtOrBelow(f.points, top), lastAtOrBelow(f.walls, top)) {
		return true
	}
	for last := len(f.stack) - 1; last > m && f.stack[last].html && impliedEnds[f.stack[last].tag]; last-- {
		f.cut(last)
	}
	f.remove(m)
	return true
}

func (f *foreignScan) htmlLast(t string, top int) int {
	return lastAtOrBelow(f.byName[elementKey{t, true}], top)
}

// impliedClose closes, before an HTML start tag t, what the parser closes
// first: an li the nearest open li, a dd or dt the nearest dd or dt
// (neither past a special element other than address, div and p, nor past
// an integration point), a heading the heading it is in, a block start
// an open p (button scope), and a button an open button. The archiver's
// _ForeignStack.implied_close.
func (f *foreignScan) impliedClose(t string) {
	top := len(f.stack) - 1
	points := lastAtOrBelow(f.points, top)
	match, barrier := -1, -1
	switch t {
	case "li":
		match = f.htmlLast("li", top)
		barrier = max(lastAtOrBelow(f.listWalls, top), f.htmlLast("dd", top), f.htmlLast("dt", top), points)
	case "dd", "dt":
		match = max(f.htmlLast("dd", top), f.htmlLast("dt", top))
		barrier = max(lastAtOrBelow(f.listWalls, top), f.htmlLast("li", top), points)
	case "button": // a button closes an open button (default scope)
		match = f.htmlLast("button", top)
		barrier = max(lastAtOrBelow(f.walls, top), points)
	}
	if match > 0 && match > barrier {
		f.cut(match)
	}
	if headingTags[t] {
		if last := f.stack[len(f.stack)-1]; last.html && headingTags[last.tag] {
			f.cut(len(f.stack) - 1)
		}
	}
	if closesP[t] {
		top = len(f.stack) - 1
		match = f.htmlLast("p", top)
		barrier = max(lastAtOrBelow(f.walls, top), f.htmlLast("button", top), lastAtOrBelow(f.points, top))
		if match > 0 && match > barrier {
			f.cut(match)
		}
	}
}

// attrValue is the value of attribute name of the start tag html[j:end+1],
// read as the tokenizer reads it (the first of a repeated name; "" when
// absent). The archiver's _tag_attrs.
func attrValue(html string, j, end int, name string) string {
	v, _ := tagAttr(html, j, end, name)
	return v
}

// tagAttr is attribute name of the start tag html[j:end+1] and whether it
// is there, read as attrValue reads it.
func tagAttr(html string, j, end int, name string) (string, bool) {
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
	k := j + 1
	for k < end && !space(html[k]) && html[k] != '/' { // the tag name
		k++
	}
	for k < end {
		if space(html[k]) || html[k] == '/' {
			k++
			continue
		}
		start := k
		k++
		for k < end && !space(html[k]) && html[k] != '/' && html[k] != '=' {
			k++
		}
		attr, value := asciiLower(html[start:k]), ""
		for k < end && space(html[k]) {
			k++
		}
		if k < end && html[k] == '=' {
			k++
			for k < end && space(html[k]) {
				k++
			}
			if k < end && (html[k] == '"' || html[k] == '\'') {
				q := indexFrom(html, string(html[k]), k+1)
				if q < 0 || q > end {
					return "", false
				}
				value, k = html[k+1:q], q+1
			} else {
				s := k
				for k < end && !space(html[k]) {
					k++
				}
				value = html[s:k]
			}
		}
		if attr == name {
			return value, true
		}
	}
	return "", false
}

// foreignRule reads end tag t (ending at html[e]) by the foreign rule from
// the top: e+1 when it closes the root, 0 when it closes an element or the
// HTML rule takes it, -1 when it walks past the root.
func (f *foreignScan) foreignRule(t string, e int) int {
	match := lastAtOrBelow(f.byName[elementKey{t, false}], len(f.stack)-1)
	html := -1
	if len(f.htmls) > 0 {
		html = f.htmls[len(f.htmls)-1]
	}
	switch {
	case match >= 0 && match > html:
		if match == 0 {
			return e + 1
		}
		f.cut(match)
		return 0
	case html > 0:
		if f.htmlRule(t, html) {
			return 0
		}
	}
	return -1
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

// allBodies joins every non-attachment text/plain part and lists every
// text/html part, as the archiver does.
func allBodies(msg *mailmsg.Part) (plain string, htmls []string) {
	var plains []string
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
	return strings.Join(plains, "\n"), htmls
}

// htmlPieces splits html, the scan's cut of htmls joined by "\n", back into
// its parts, so each is read as its own document: an unclosed <style> in
// one part does not hide the next. The archiver's _html_pieces.
func htmlPieces(html string, htmls []string) []string {
	var out []string
	start := 0
	for _, part := range htmls {
		if start >= len(html) {
			break
		}
		out = append(out, html[start:min(start+len(part), len(html))])
		start += len(part) + 1
	}
	return out
}

// bodyParts walks the message's own parts: it never descends into an
// attachment or an attached message, whose text is not this email's body.
// A root marked as an attachment is not body either, though a multipart
// one's children are read.
func bodyParts(p *mailmsg.Part) []*mailmsg.Part {
	var out []*mailmsg.Part
	if !strings.Contains(strings.ToLower(p.Header.Get("Content-Disposition")), "attachment") {
		out = append(out, p)
	}
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
func bodyURLs(plain string, htmls ...string) []bodyLink {
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
	html := truncateToRunes(strings.Join(htmls, "\n"), maxScanRunes)
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
	// cannot bring text past the archiver's cut into the scan, and on each
	// HTML part by itself, as each is its own document.
	for _, piece := range htmlPieces(html, htmls) {
		for _, u := range extractHTMLTextURLs(htmlsafe.PreStrip(piece)) {
			decoded := dedupeKey(u)
			if _, ok := index[u]; ok || seen[decoded] {
				continue
			}
			seen[decoded] = true
			add(bodyLink{url: u, bare: true})
		}
	}
	return out
}

// downloadLinks lists the distinct likely-payload links of a body.
func downloadLinks(plain string, htmls ...string) []DownloadLink {
	var out []DownloadLink
	for _, l := range bodyURLs(plain, htmls...) {
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
