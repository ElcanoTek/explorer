// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package htmlsafe

import (
	"html"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Linkify turns bare URLs in the text nodes of serialized, sanitized markup
// into rel="nofollow" links. The input MUST be the output of Sanitize or
// EscapeText: both escape < in text and double-quote every attribute value
// (escaping " inside it), which is what lets one regex split tags from text.
//
// Guarantees the callers rely on:
//
//   - Only text nodes are rewritten, never an attribute value and never text
//     already inside an <a>.
//   - A generated href is the escaped text it was found in; the match holds
//     no raw quote, angle bracket or whitespace and stops at an escaped
//     quote or angle bracket, so it cannot leave its attribute. Its scheme
//     is http or https (http:// is prefixed to a bare domain), it has a
//     valid host and port, and it carries no userinfo.
//   - Every <a> with a non-mailto: href gets nofollow added to its rel.
//
// This is a port of the Python app/linkify.py, which replaced
// bleach.linkify; the scanner is hand-written because RE2 has no
// look-around, and it emulates Python's Unicode \w and \s.
func Linkify(markup string) string {
	var out strings.Builder
	inAnchor := false
	end := 0
	for _, loc := range tagRE.FindAllStringIndex(markup, -1) {
		text := markup[end:loc[0]]
		if inAnchor {
			out.WriteString(text)
		} else {
			out.WriteString(linkifyText(text))
		}
		tag := markup[loc[0]:loc[1]]
		if m := tagNameRE.FindStringSubmatch(tag); m != nil && strings.EqualFold(m[1], "a") {
			if strings.HasPrefix(tag, "</") {
				inAnchor = false
			} else {
				inAnchor = true
				tag = nofollow(tag)
			}
		}
		out.WriteString(tag)
		end = loc[1]
	}
	tail := markup[end:]
	if inAnchor {
		out.WriteString(tail)
	} else {
		out.WriteString(linkifyText(tail))
	}
	return out.String()
}

var (
	// One serialized tag: quoted attribute values may contain ">".
	tagRE     = regexp.MustCompile(`<[^>"]*(?:"[^"]*"[^>"]*)*>`)
	tagNameRE = regexp.MustCompile(`^</?([A-Za-z0-9]*)`)
	attrRE    = regexp.MustCompile(`\s([^\s="]+)(?:="([^"]*)")?`)
)

// Bare domains (no scheme) only link for these TLDs, any two-letter country
// code, or a punycode TLD, so "report.final" or "config.yaml" stay text.
var bareTLDs = map[string]bool{
	"aero": true, "arpa": true, "asia": true, "biz": true, "cat": true,
	"com": true, "coop": true, "edu": true, "gov": true, "info": true,
	"int": true, "jobs": true, "mil": true, "mobi": true, "museum": true,
	"name": true, "net": true, "org": true, "post": true, "pro": true,
	"tel": true, "travel": true, "xxx": true,
}

// isWord is Python's Unicode \w: str.isalnum() or "_".
func isWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// isSpace is Python's Unicode \s (str.isspace()).
func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// isTLDLetter is [^\W\d_]: a word character that is not a decimal digit or
// the underscore.
func isTLDLetter(r rune) bool {
	return isWord(r) && r != '_' && !unicode.IsDigit(r)
}

func isLabelChar(r rune) bool { return r == '-' || isWord(r) }

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// Escaped characters a URL candidate must stop at (case-insensitive).
var stopEntities = []string{"&quot;", "&lt;", "&gt;", "&nbsp;", "&#x27;", "&#39;", "&#34;", "&#x22;"}

// urlCharLen returns the byte length of one URL candidate character at
// s[i:], or 0 when s[i] cannot be part of a URL: whitespace, a raw quote or
// angle bracket, or an escaped one.
func urlCharLen(s string, i int) int {
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case isSpace(r), r == '<', r == '>', r == '"', r == '\'':
		return 0
	case r == '&':
		rest := s[i:]
		for _, e := range stopEntities {
			if len(rest) >= len(e) && strings.EqualFold(rest[:len(e)], e) {
				return 0
			}
		}
	}
	return size
}

// urlRun returns the end of the maximal run of URL characters from i.
func urlRun(s string, i int) int {
	for i < len(s) {
		n := urlCharLen(s, i)
		if n == 0 {
			break
		}
		i += n
	}
	return i
}

func runeAt(s string, i int) (rune, int) {
	if i >= len(s) {
		return utf8.RuneError, 0
	}
	return utf8.DecodeRuneInString(s[i:])
}

// lookbehindOK is (?<![\w@.:/&#-]) at byte offset i.
func lookbehindOK(s string, i int) bool {
	if i == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return !isWord(r) && !strings.ContainsRune("@.:/&#-", r)
}

type urlMatch struct {
	start, end int
	explicit   bool
	tld        string
}

// matchExplicit matches https?://<url chars>+ at i (case-insensitive).
func matchExplicit(s string, i int) (int, bool) {
	rest := s[i:]
	var n int
	switch {
	case len(rest) >= 8 && strings.EqualFold(rest[:8], "https://"):
		n = 8
	case len(rest) >= 7 && strings.EqualFold(rest[:7], "http://"):
		n = 7
	default:
		return 0, false
	}
	end := urlRun(s, i+n)
	if end == i+n {
		return 0, false
	}
	return end, true
}

// tldAt tries the two TLD alternatives at p, each followed by the
// (?![\w-]|\.\w) look-ahead. Greedy backtracking can only ever succeed at
// the maximal run, so only that length is tried.
func tldAt(s string, p int) (int, bool) {
	lookahead := func(q int) bool {
		r, size := runeAt(s, q)
		if size == 0 {
			return true
		}
		if isLabelChar(r) {
			return false
		}
		if r == '.' {
			if r2, n2 := runeAt(s, q+size); n2 > 0 && isWord(r2) {
				return false
			}
		}
		return true
	}
	q, count := p, 0
	for {
		r, size := runeAt(s, q)
		if size == 0 || !isTLDLetter(r) {
			break
		}
		q += size
		count++
		if count > 63 {
			break
		}
	}
	if count >= 2 && count <= 63 && lookahead(q) {
		return q, true
	}
	if len(s)-p >= 4 && strings.EqualFold(s[p:p+4], "xn--") {
		q, count = p+4, 0
		for q < len(s) && count <= 59 {
			c := s[q]
			if !isASCIIAlnum(c) && c != '-' {
				break
			}
			q++
			count++
		}
		if count >= 1 && count <= 59 && lookahead(q) {
			return q, true
		}
	}
	return 0, false
}

// matchBare matches (?:[\w-]+\.)+TLD(?::\d{1,5})?(?:[/?#]<url chars>*)? at i.
func matchBare(s string, i int) (int, string, bool) {
	// Label ends: positions just after each "label." from i.
	var dots []int
	q := i
	for {
		start := q
		for {
			r, size := runeAt(s, q)
			if size == 0 || !isLabelChar(r) {
				break
			}
			q += size
		}
		if q == start || q >= len(s) || s[q] != '.' {
			break
		}
		q++
		dots = append(dots, q)
	}
	for k := len(dots) - 1; k >= 0; k-- {
		p := dots[k]
		tldEnd, ok := tldAt(s, p)
		if !ok {
			continue
		}
		end := tldEnd
		if end < len(s) && s[end] == ':' {
			d := end + 1
			for d < len(s) && d-end-1 < 5 && s[d] >= '0' && s[d] <= '9' {
				d++
			}
			if d > end+1 {
				end = d
			}
		}
		if end < len(s) && strings.IndexByte("/?#", s[end]) >= 0 {
			end = urlRun(s, end+1)
		}
		return end, s[p:tldEnd], true
	}
	return 0, "", false
}

func nextMatch(s string, from int) (urlMatch, bool) {
	for i := from; i < len(s); {
		if lookbehindOK(s, i) {
			if end, ok := matchExplicit(s, i); ok {
				return urlMatch{start: i, end: end, explicit: true}, true
			}
			if end, tld, ok := matchBare(s, i); ok {
				return urlMatch{start: i, end: end, tld: tld}, true
			}
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return urlMatch{}, false
}

func linkifyText(text string) string {
	var out strings.Builder
	end := 0
	for pos := 0; ; {
		m, ok := nextMatch(text, pos)
		if !ok {
			break
		}
		pos = m.end
		if !m.explicit {
			tld := strings.ToLower(m.tld)
			if utf8.RuneCountInString(tld) != 2 && !bareTLDs[tld] && !strings.HasPrefix(tld, "xn--") {
				continue
			}
		}
		url, suffix := stripTrailing(text[m.start:m.end])
		href := url
		if !m.explicit {
			href = "http://" + url
		}
		if !validHref(href) {
			continue
		}
		out.WriteString(text[end:m.start])
		out.WriteString(`<a href="` + href + `" rel="nofollow">` + url + `</a>` + suffix)
		end = m.end
	}
	out.WriteString(text[end:])
	return out.String()
}

var closerPair = map[byte]byte{')': '(', ']': '[', '}': '{'}

// stripTrailing splits off trailing prose punctuation and unmatched closing
// brackets, repeating until nothing changes: "(see https://x/a_(b))." keeps
// the balanced "(b)" and drops ")." Counts are kept incrementally.
func stripTrailing(url string) (string, string) {
	opens := map[byte]int{}
	closes := map[byte]int{}
	for i := 0; i < len(url); i++ {
		switch url[i] {
		case '(', '[', '{':
			opens[url[i]]++
		case ')', ']', '}':
			closes[url[i]]++
		}
	}
	cut := len(url)
	for cut > 0 {
		c := url[cut-1]
		open, isCloser := closerPair[c]
		switch {
		case isCloser && closes[c] > opens[open]:
			closes[c]--
		case strings.IndexByte(".,;:!?*", c) >= 0 && (c != ';' || !entityAtEnd(url[:cut])):
			// trailing prose punctuation
		default:
			return url[:cut], url[cut:]
		}
		cut--
	}
	return url[:cut], url[cut:]
}

// entityAtEnd is &(?:[A-Za-z][A-Za-z0-9]*|#[0-9]+|#x[0-9A-Fa-f]+);$.
func entityAtEnd(s string) bool {
	if !strings.HasSuffix(s, ";") {
		return false
	}
	body := s[:len(s)-1]
	amp := strings.LastIndexByte(body, '&')
	if amp < 0 {
		return false
	}
	name := body[amp+1:]
	isHex := func(c byte) bool { return c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c >= '0' && c <= '9' }
	all := func(t string, f func(byte) bool) bool {
		for i := 0; i < len(t); i++ {
			if !f(t[i]) {
				return false
			}
		}
		return t != ""
	}
	switch {
	case strings.HasPrefix(name, "#x"):
		return all(name[2:], isHex)
	case strings.HasPrefix(name, "#"):
		return all(name[1:], func(c byte) bool { return c >= '0' && c <= '9' })
	case name != "" && (name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z'):
		return all(name, isASCIIAlnum)
	}
	return false
}

// validHref applies Python's urlsplit rules to the unescaped URL: an http or
// https scheme, a valid host and port, and no userinfo. A URL with userinfo
// is never linked: https://bank.example@evil.example is a phishing shape.
func validHref(href string) bool {
	u := html.UnescapeString(href)
	u = strings.TrimLeftFunc(u, func(r rune) bool { return r <= 0x20 })
	u = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, u)
	colon := strings.IndexByte(u, ':')
	if colon <= 0 {
		return false
	}
	scheme := strings.ToLower(u[:colon])
	if scheme != "http" && scheme != "https" {
		return false
	}
	rest := u[colon+1:]
	if !strings.HasPrefix(rest, "//") {
		return false
	}
	rest = rest[2:]
	netloc := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		netloc = rest[:i]
	}
	if !netlocValid(netloc) || strings.Contains(netloc, "@") {
		return false
	}
	host, port, bracketed := splitHostPort(netloc)
	if port != "" {
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return false
			}
		}
		if n, err := strconv.Atoi(port); err != nil || n > 65535 {
			return false
		}
	}
	if strings.HasPrefix(netloc, "[") {
		return bracketed
	}
	return hostnameValid(strings.ToLower(host))
}

// netlocValid mirrors urlsplit's ValueError cases: unbalanced brackets, a
// bracketed host that is not IPv6, and NFKC-normalizing look-alikes of the
// URL delimiters.
func netlocValid(netloc string) bool {
	openB, closeB := strings.Contains(netloc, "["), strings.Contains(netloc, "]")
	if openB != closeB {
		return false
	}
	if openB && !bracketedNetlocValid(netloc) {
		return false
	}
	for i := 0; i < len(netloc); i++ {
		if netloc[i] >= 0x80 {
			n := strings.NewReplacer("@", "", ":", "", "#", "", "?", "").Replace(netloc)
			if n2 := norm.NFKC.String(n); n2 != n && strings.ContainsAny(n2, "/?#@:") {
				return false
			}
			break
		}
	}
	return true
}

// bracketedNetlocValid is Python 3.13's _check_bracketed_netloc: nothing
// before the bracket, nothing but ":port" after it, and an IPv6 address
// inside (an IPvFuture literal can never be linked, so it is refused here).
func bracketedNetlocValid(netloc string) bool {
	hostAndPort := netloc
	if i := strings.LastIndexByte(hostAndPort, '@'); i >= 0 {
		hostAndPort = hostAndPort[i+1:]
	}
	i := strings.IndexByte(hostAndPort, '[')
	if i != 0 {
		return false
	}
	bracketed := hostAndPort[1:]
	host, port := bracketed, ""
	if j := strings.IndexByte(bracketed, ']'); j >= 0 {
		host, port = bracketed[:j], bracketed[j+1:]
	}
	if port != "" && !strings.HasPrefix(port, ":") {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is6()
}

// splitHostPort is urlsplit's _hostinfo; bracketed reports a valid
// bracketed IPv6 host.
func splitHostPort(netloc string) (host, port string, bracketed bool) {
	hostinfo := netloc
	if i := strings.LastIndexByte(hostinfo, '@'); i >= 0 {
		hostinfo = hostinfo[i+1:]
	}
	if i := strings.IndexByte(hostinfo, '['); i >= 0 {
		b := hostinfo[i+1:]
		j := strings.IndexByte(b, ']')
		if j < 0 {
			return b, "", false
		}
		host = b[:j]
		after := b[j+1:]
		if k := strings.IndexByte(after, ':'); k >= 0 {
			port = after[k+1:]
		}
		addr, err := netip.ParseAddr(host)
		return host, port, err == nil && addr.Is6()
	}
	if i := strings.IndexByte(hostinfo, ':'); i >= 0 {
		return hostinfo[:i], hostinfo[i+1:], false
	}
	return hostinfo, "", false
}

// hostnameValid is ^[\w-]+(?:\.[\w-]+)*\.?$ with Python's Unicode \w.
func hostnameValid(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !isLabelChar(r) {
				return false
			}
		}
	}
	return true
}

// nofollow adds nofollow to an existing <a ...> start tag's rel tokens,
// exactly as bleach's default callback did. mailto: and hrefless anchors
// are left alone.
func nofollow(tag string) string {
	type attr struct {
		key, val string
		hasVal   bool
	}
	var attrs []attr
	for _, m := range attrRE.FindAllStringSubmatchIndex(tag[2:len(tag)-1], -1) {
		body := tag[2 : len(tag)-1]
		a := attr{key: body[m[2]:m[3]]}
		if m[4] >= 0 {
			a.val, a.hasVal = body[m[4]:m[5]], true
		}
		attrs = append(attrs, a)
	}
	href, hasHref, seenHref := "", false, false
	relIdx := -1
	for i, a := range attrs {
		switch strings.ToLower(a.key) {
		case "href":
			if !seenHref {
				seenHref = true
				href, hasHref = a.val, a.hasVal
			}
		case "rel":
			if relIdx < 0 {
				relIdx = i
			}
		}
	}
	if !hasHref || strings.HasPrefix(href, "mailto:") {
		return tag
	}
	if relIdx < 0 {
		attrs = append(attrs, attr{key: "rel", val: "nofollow", hasVal: true})
	} else {
		tokens := strings.Fields(attrs[relIdx].val)
		found := false
		for _, t := range tokens {
			if strings.EqualFold(t, "nofollow") {
				found = true
			}
		}
		if !found {
			tokens = append(tokens, "nofollow")
		}
		attrs[relIdx] = attr{key: "rel", val: strings.Join(tokens, " "), hasVal: true}
	}
	var b strings.Builder
	b.WriteString("<a")
	for _, a := range attrs {
		b.WriteString(" " + a.key)
		if a.hasVal {
			b.WriteString(`="` + a.val + `"`)
		}
	}
	b.WriteString(">")
	return b.String()
}
