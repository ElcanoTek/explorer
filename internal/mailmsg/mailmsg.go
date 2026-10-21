// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package mailmsg is a lenient MIME parser for archived mail. It replaces
// the parts of Python's email package Explorer used, and keeps its
// tolerance: archived messages are whatever senders produced, so nothing
// here returns an error. A malformed header ends the header block, a
// multipart body without its closing boundary still yields its parts,
// broken base64 is decoded as far as it goes, and an unknown charset falls
// back to UTF-8 with replacement characters.
package mailmsg

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"
)

// Field is one header as it appeared: the name as written and the value
// unfolded (line breaks removed), not yet RFC 2047 decoded.
type Field struct {
	Name  string
	Value string
}

// Header is a message's header fields in order.
type Header []Field

// Get returns the first field named name (case-insensitive), or "".
func (h Header) Get(name string) string {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// Has reports whether a field named name is present.
func (h Header) Has(name string) bool {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// Python's feedparser headerRE: a header line, a continuation, or a unix
// "From " line. Anything else ends the header block.
var headerLineRE = regexp.MustCompile(`^(From |[\x21-\x39\x3b-\x7e]*:|[\t ])`)

// splitLines splits data into lines that keep their line ending (\r\n, \r
// or \n), like Python's splitlines(keepends=True) for those three.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			lines = append(lines, data[start:i+1])
			start = i + 1
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				i++
			}
			lines = append(lines, data[start:i+1])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func trimEOL(line []byte) []byte {
	return bytes.TrimRight(line, "\r\n")
}

// headerText turns raw header bytes into text: UTF-8 when valid (RFC 6532
// mail), otherwise Windows-1252, so 8-bit legacy headers stay readable.
func headerText(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	out, err := charmap.Windows1252.NewDecoder().Bytes(raw)
	if err != nil {
		return strings.ToValidUTF8(string(raw), "\uFFFD")
	}
	return string(out)
}

// parseHeaderBlock reads header fields from the start of lines and returns
// them with the index of the first body line. A blank line is consumed; a
// non-header line is left as the first body line.
func parseHeaderBlock(lines [][]byte) (Header, int) {
	var h Header
	var name string
	var value []byte
	have := false
	flush := func() {
		if have {
			h = append(h, Field{Name: name, Value: headerText(bytes.TrimRight(value, " \t"))})
		}
		have = false
	}
	i := 0
	for ; i < len(lines); i++ {
		line := lines[i]
		content := trimEOL(line)
		if len(content) == 0 {
			flush()
			return h, i + 1
		}
		if !headerLineRE.Match(content) {
			break
		}
		if content[0] == ' ' || content[0] == '\t' {
			if have {
				value = append(value, content...)
			}
			continue
		}
		if bytes.HasPrefix(content, []byte("From ")) {
			continue // unix From line, or a misplaced one
		}
		colon := bytes.IndexByte(content, ':')
		if colon <= 0 {
			continue
		}
		flush()
		name = string(content[:colon])
		value = append([]byte(nil), bytes.TrimLeft(content[colon+1:], " \t")...)
		have = true
	}
	flush()
	return h, i
}

// ParseHeaders parses only the header block of data, which may be a
// truncated prefix of a message (a ranged read).
func ParseHeaders(data []byte) Header {
	h, _ := parseHeaderBlock(splitLines(data))
	return h
}

// Part is one node of a parsed message: the message itself, a multipart
// container, an attached message/rfc822, or a leaf.
type Part struct {
	Header Header
	// Children holds the parts of a multipart container, or the single
	// enclosed message of a message/rfc822 part.
	Children []*Part
	body     []byte
	defType  string
}

// Parse parses a complete message.
func Parse(raw []byte) *Part {
	return parsePart(raw, "text/plain", 0)
}

// maxDepth bounds nesting so a hostile message cannot recurse without end.
const maxDepth = 50

func parsePart(raw []byte, defType string, depth int) *Part {
	lines := splitLines(raw)
	h, bodyStart := parseHeaderBlock(lines)
	p := &Part{Header: h, defType: defType}
	body := bytes.Join(lines[bodyStart:], nil)
	p.body = body
	if depth >= maxDepth {
		return p
	}
	ctype := p.ContentType()
	switch {
	case strings.HasPrefix(ctype, "multipart/"):
		boundary, _ := p.Param("Content-Type", "boundary")
		boundary = strings.TrimRight(boundary, " \t\r\n")
		if boundary == "" {
			return p
		}
		childDefault := "text/plain"
		if ctype == "multipart/digest" {
			childDefault = "message/rfc822"
		}
		if parts, ok := splitMultipart(lines[bodyStart:], boundary); ok {
			for _, raw := range parts {
				p.Children = append(p.Children, parsePart(raw, childDefault, depth+1))
			}
		}
	case ctype == "message/rfc822" || ctype == "message/global":
		p.Children = []*Part{parsePart(body, "text/plain", depth+1)}
	}
	return p
}

// splitMultipart cuts body lines at "--boundary" lines (trailing blanks
// allowed) the way Python's feedparser does. The line ending before a
// boundary belongs to the boundary. A missing close boundary ends the last
// part at the end of input. ok is false when no boundary line exists.
func splitMultipart(lines [][]byte, boundary string) ([][]byte, bool) {
	sep := []byte("--" + boundary)
	var parts [][]byte
	var cur []byte
	inPart, found := false, false
	for _, line := range lines {
		content := trimEOL(line)
		if bytes.HasPrefix(content, sep) {
			rest := content[len(sep):]
			closing := bytes.HasPrefix(rest, []byte("--"))
			if closing {
				rest = rest[2:]
			}
			if len(bytes.Trim(rest, " \t")) == 0 {
				if inPart {
					parts = append(parts, dropLastEOL(cur))
				}
				found = true
				cur = nil
				if closing {
					return parts, true
				}
				inPart = true
				continue
			}
		}
		if inPart {
			cur = append(cur, line...)
		}
	}
	if inPart {
		parts = append(parts, cur)
	}
	return parts, found
}

func dropLastEOL(b []byte) []byte {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return b[:len(b)-2]
	case bytes.HasSuffix(b, []byte("\n")), bytes.HasSuffix(b, []byte("\r")):
		return b[:len(b)-1]
	}
	return b
}

// Walk returns p and every descendant, depth first, in document order
// (Python's Message.walk()).
func (p *Part) Walk() []*Part {
	out := []*Part{p}
	for _, c := range p.Children {
		out = append(out, c.Walk()...)
	}
	return out
}

// ContentType is the lowercased "type/subtype", defaulting like Python's
// get_content_type (text/plain, or message/rfc822 inside a digest; an
// unparseable value is text/plain).
func (p *Part) ContentType() string {
	if !p.Header.Has("Content-Type") {
		return p.defType
	}
	value := p.Header.Get("Content-Type")
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	ctype := strings.ToLower(strings.TrimSpace(value))
	if strings.Count(ctype, "/") != 1 {
		return "text/plain"
	}
	return ctype
}

// MainType is the part of ContentType before the slash.
func (p *Part) MainType() string {
	ct := p.ContentType()
	return ct[:strings.IndexByte(ct, '/')]
}

// IsContainer reports a multipart or enclosed-message part, which has no
// decodable payload of its own.
func (p *Part) IsContainer() bool { return len(p.Children) > 0 }

// Param returns a parameter of a structured header such as Content-Type or
// Content-Disposition, with RFC 2231 continuations and charsets decoded.
func (p *Part) Param(header, name string) (string, bool) {
	raw := p.Header.Get(header)
	if raw == "" {
		return "", false
	}
	v, ok := parseParams(raw)[strings.ToLower(name)]
	return v, ok
}

// Charset is the lowercased charset parameter of Content-Type, or "".
func (p *Part) Charset() string {
	v, _ := p.Param("Content-Type", "charset")
	return strings.ToLower(strings.TrimSpace(v))
}

// Filename is Content-Disposition's filename, else Content-Type's name,
// stripped. It may still hold RFC 2047 encoded words.
func (p *Part) Filename() string {
	if v, ok := p.Param("Content-Disposition", "filename"); ok {
		return strings.TrimSpace(v)
	}
	v, _ := p.Param("Content-Type", "name")
	return strings.TrimSpace(v)
}

// Payload returns the transfer-decoded body. ok is false for a container
// part, which has none (Python's get_payload(decode=True) returning None).
func (p *Part) Payload() ([]byte, bool) {
	if p.IsContainer() {
		return nil, false
	}
	switch strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return decodeBase64(p.body), true
	case "quoted-printable":
		return decodeQP(p.body), true
	}
	return p.body, true
}

// decodeBase64 decodes leniently: characters outside the alphabet are
// skipped and missing padding is tolerated.
func decodeBase64(b []byte) []byte {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			clean = append(clean, c)
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
	n, _ := base64.RawStdEncoding.Decode(out, clean)
	return out[:n]
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeQP decodes quoted-printable leniently: =XX escapes and soft line
// breaks are decoded, anything else (a stray "=") is kept as written.
func decodeQP(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '=' {
			out = append(out, c)
			continue
		}
		rest := b[i+1:]
		switch {
		case bytes.HasPrefix(rest, []byte("\r\n")):
			i += 2
		case len(rest) > 0 && (rest[0] == '\n' || rest[0] == '\r'):
			i++
		case len(rest) >= 2:
			hi, ok1 := unhex(rest[0])
			lo, ok2 := unhex(rest[1])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
			} else {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
	}
	return out
}

// lookupCharset finds a decoder for a charset label, trying the WHATWG
// names browsers use, then the IANA registry. nil means unknown.
func lookupCharset(label string) encoding.Encoding {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return nil
	}
	for _, l := range []string{label, strings.ReplaceAll(label, "_", "-")} {
		if e, err := htmlindex.Get(l); err == nil && e != nil {
			return e
		}
		for _, idx := range []*ianaindex.Index{ianaindex.MIME, ianaindex.IANA} {
			if e, err := idx.Encoding(l); err == nil && e != nil {
				return e
			}
		}
	}
	return nil
}

// DecodeBytes decodes raw in charset without failing: an unknown or bogus
// label ("utf-8//translit") falls back to UTF-8, and undecodable bytes
// become U+FFFD.
func DecodeBytes(raw []byte, charset string) string {
	if e := lookupCharset(charset); e != nil {
		if out, err := e.NewDecoder().Bytes(raw); err == nil {
			return toValidUTF8(out)
		}
	}
	return toValidUTF8(raw)
}

// toValidUTF8 replaces each invalid byte with U+FFFD, as Python's
// errors="replace" does.
func toValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var s strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			s.WriteRune(utf8.RuneError)
		} else {
			s.Write(b[:size])
		}
		b = b[size:]
	}
	return s.String()
}

var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		if e := lookupCharset(charset); e != nil {
			return transform.NewReader(input, e.NewDecoder()), nil
		}
		return input, nil
	},
}

// DecodeHeader decodes RFC 2047 encoded words. It never fails: a value that
// cannot be decoded is returned as written.
func DecodeHeader(value string) string {
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "=?") {
		return value
	}
	out, err := wordDecoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return toValidUTF8([]byte(out))
}
