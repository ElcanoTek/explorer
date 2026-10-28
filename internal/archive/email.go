// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ElcanoTek/explorer/internal/htmlsafe"
	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// maxPlainPreviewRunes bounds the plain-text preview of one message.
const maxPlainPreviewRunes = 6000

// AttachmentInfo describes one downloadable part.
type AttachmentInfo struct {
	Filename    string
	ContentType string
	SizeBytes   int
}

// Email is one rendered message.
type Email struct {
	S3Key       string
	Subject     string
	From        string
	To          string
	Cc          string
	Bcc         string
	ReplyTo     string
	Date        string
	MessageID   string
	Attachments []AttachmentInfo
	// BodyPreview is the plain-text body (or the raw HTML when there is no
	// plain part), cut to 6000 characters. Text, not markup.
	BodyPreview string
	// BodyPreviewHTML is sanitized, linkified markup safe to emit
	// unescaped, or "" when the message has no renderable HTML.
	BodyPreviewHTML string
	// BodyPreviewLinked is BodyPreview escaped and linkified (markup).
	BodyPreviewLinked string
	// BodyPreviewType is "html" or "plain".
	BodyPreviewType string
}

// Attachment is one downloaded part.
type Attachment struct {
	// Name is a safe download name: the last path element of the
	// requested filename, never empty, "." or "..".
	Name        string
	ContentType string
	Data        []byte
}

func normalizeCID(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(v), "<>")))
}

func normalizeInlineRef(v string) string {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	return strings.ToLower(v)
}

// pathName is Python's PurePosixPath(p).name.
func pathName(p string) string {
	var last string
	for _, seg := range strings.Split(p, "/") {
		if seg != "" && seg != "." {
			last = seg
		}
	}
	return last
}

// unquote is Python's urllib.parse.unquote: %XX is decoded, anything
// malformed is kept, and the bytes are read as UTF-8 with replacement.
func unquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := fromHex(s[i+1]); ok {
				if lo, ok := fromHex(s[i+2]); ok {
					out = append(out, hi<<4|lo)
					i += 2
					continue
				}
			}
		}
		out = append(out, s[i])
	}
	return strings.ToValidUTF8(string(out), "\uFFFD")
}

func fromHex(c byte) (byte, bool) {
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

var schemePrefixRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// urlPath is the path component urlsplit would return.
func urlPath(s string) string {
	if m := schemePrefixRE.FindString(s); m != "" {
		s = s[len(m):]
	}
	if strings.HasPrefix(s, "//") {
		rest := s[2:]
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			s = rest[i:]
		} else {
			s = ""
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func basenameInlineRef(v string) string {
	n := normalizeInlineRef(v)
	if n == "" {
		return ""
	}
	p := urlPath(n)
	if p == "" {
		p = n
	}
	return strings.ToLower(pathName(unquote(p)))
}

// Extensions for inline parts named after their Content-ID, matching what
// Python's mimetypes.guess_extension returned, so links stay stable.
var extensionFor = map[string]string{
	"image/jpeg": ".jpg", "image/pjpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
	"image/webp": ".webp", "image/svg+xml": ".svg", "image/bmp": ".bmp", "image/tiff": ".tiff",
	"image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico", "image/heic": ".heic",
	"image/avif": ".avif", "application/pdf": ".pdf", "text/plain": ".txt", "text/html": ".html",
	"text/css": ".css", "text/csv": ".csv", "application/json": ".json", "application/zip": ".zip",
	"application/octet-stream": ".bin", "audio/mpeg": ".mp3", "video/mp4": ".mp4",
	"application/msword": ".doc", "application/xml": ".xsl", "text/xml": ".xml",
}

func inlineFilenameForCID(cid, contentType string) string {
	var b strings.Builder
	for _, r := range cid {
		if r < utf8.RuneSelf && (r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	safe := b.String()
	if safe == "" {
		safe = "inline"
	}
	ext, ok := extensionFor[contentType]
	if !ok {
		ext = ".bin"
	}
	return "inline_" + safe + ext
}

// Quote percent-encodes s like Python's quote(s, safe=""): every byte but
// A-Z a-z 0-9 _ . - ~ becomes %XX.
func Quote(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

var (
	cidRefRE     = regexp.MustCompile(`(?i)cid:\s*<?([^\s"'>]+)>?`)
	inlineSrcRE  = regexp.MustCompile(`(?i)(\bsrc)\s*=\s*["']([^"']+)["']`)
	externalRefs = []string{"http://", "https://", "data:", "mailto:", "/attachment?", "#", "cid:"}
)

func attachmentURL(key, filename string) string {
	return "/attachment?s3_key=" + Quote(key) + "&filename=" + Quote(filename)
}

// GetEmail downloads and renders one message.
func (in *Inbox) GetEmail(ctx context.Context, key string) (*Email, error) {
	msg, err := in.readFull(ctx, key)
	if err != nil {
		return nil, err
	}
	var attachments []AttachmentInfo
	seenNames := map[string]bool{}
	cidMap := map[string]string{}
	refMap := map[string]string{}
	baseMap := map[string]string{}
	plain, bodyHTML := extractBodies(msg)
	plain = htmlsafe.StripLeadingCSSNoise(plain)

	for _, part := range msg.Walk() {
		if part.MainType() == "multipart" {
			continue
		}
		disposition := part.Header.Get("Content-Disposition")
		contentType := part.ContentType()
		contentID := normalizeCID(part.Header.Get("Content-ID"))
		location := normalizeInlineRef(part.Header.Get("Content-Location"))
		payload, _ := part.Payload()
		rawName := part.Filename()
		filename := strings.TrimSpace(mailmsg.DecodeHeader(rawName))
		if contentID != "" {
			if filename == "" {
				filename = inlineFilenameForCID(contentID, contentType)
			}
			cidMap[contentID] = filename
		}
		if !strings.Contains(disposition, "attachment") && rawName == "" && contentID == "" {
			continue
		}
		exposed := filename
		if exposed == "" {
			exposed = "unknown"
		}
		if !seenNames[exposed] {
			seenNames[exposed] = true
			attachments = append(attachments, AttachmentInfo{Filename: exposed, ContentType: contentType, SizeBytes: len(payload)})
		}
		if n := normalizeInlineRef(exposed); n != "" {
			refMap[n] = exposed
		}
		if b := basenameInlineRef(exposed); b != "" {
			baseMap[b] = exposed
		}
		if location != "" {
			refMap[location] = exposed
			if b := basenameInlineRef(location); b != "" {
				baseMap[b] = exposed
			}
		}
	}

	if bodyHTML != "" && len(cidMap) > 0 {
		bodyHTML = cidRefRE.ReplaceAllStringFunc(bodyHTML, func(m string) string {
			name, ok := cidMap[normalizeCID(cidRefRE.FindStringSubmatch(m)[1])]
			if !ok {
				return m
			}
			return attachmentURL(key, name)
		})
	}
	if bodyHTML != "" && (len(refMap) > 0 || len(baseMap) > 0) {
		resolve := func(src string) string {
			n := normalizeInlineRef(src)
			if n == "" {
				return ""
			}
			for _, p := range externalRefs {
				if strings.HasPrefix(n, p) {
					return ""
				}
			}
			if name, ok := refMap[n]; ok {
				return name
			}
			if b := basenameInlineRef(n); b != "" {
				return baseMap[b]
			}
			return ""
		}
		bodyHTML = inlineSrcRE.ReplaceAllStringFunc(bodyHTML, func(m string) string {
			sub := inlineSrcRE.FindStringSubmatch(m)
			name := resolve(sub[2])
			if name == "" {
				return m
			}
			return sub[1] + `="` + attachmentURL(key, name) + `"`
		})
	}

	safeHTML := htmlsafe.RenderHTMLPreview(bodyHTML)
	renderable := strings.TrimSpace(safeHTML) != ""
	preview := plain
	if preview == "" {
		preview = bodyHTML
	}
	preview = truncateRunes(preview, maxPlainPreviewRunes)
	e := &Email{
		S3Key:             key,
		Subject:           mailmsg.DecodeHeader(msg.Header.Get("Subject")),
		From:              mailmsg.DecodeHeader(msg.Header.Get("From")),
		To:                mailmsg.DecodeHeader(msg.Header.Get("To")),
		Cc:                mailmsg.DecodeHeader(msg.Header.Get("Cc")),
		Bcc:               mailmsg.DecodeHeader(msg.Header.Get("Bcc")),
		ReplyTo:           mailmsg.DecodeHeader(msg.Header.Get("Reply-To")),
		Date:              msg.Header.Get("Date"),
		MessageID:         msg.Header.Get("Message-ID"),
		Attachments:       attachments,
		BodyPreview:       preview,
		BodyPreviewLinked: htmlsafe.RenderPlainPreview(preview),
		BodyPreviewType:   "plain",
	}
	if renderable {
		e.BodyPreviewHTML = safeHTML
		e.BodyPreviewType = "html"
	}
	return e, nil
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

// Attachment returns the part of message key that filename names: its
// decoded filename, its Content-ID-derived inline name, its
// Content-Location, or the basename of either (all compared normalized).
func (in *Inbox) Attachment(ctx context.Context, key, filename string) (*Attachment, error) {
	requested := normalizeInlineRef(filename)
	if requested == "" {
		return nil, ErrNotFound
	}
	msg, err := in.readFull(ctx, key)
	if err != nil {
		return nil, err
	}
	for _, part := range msg.Walk() {
		if part.MainType() == "multipart" {
			continue
		}
		partName := strings.TrimSpace(mailmsg.DecodeHeader(part.Filename()))
		contentID := normalizeCID(part.Header.Get("Content-ID"))
		location := normalizeInlineRef(part.Header.Get("Content-Location"))
		inlineName := ""
		if contentID != "" {
			inlineName = inlineFilenameForCID(contentID, part.ContentType())
		}
		match := false
		for _, c := range []string{partName, inlineName, location, basenameInlineRef(location), basenameInlineRef(partName)} {
			if c != "" && normalizeInlineRef(c) == requested {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		payload, ok := part.Payload()
		if !ok {
			break
		}
		name := pathName(filename)
		if name == "" || name == ".." {
			name = "attachment"
		}
		return &Attachment{Name: name, ContentType: part.ContentType(), Data: payload}, nil
	}
	// The agent API's names (search results, get_email) are attachmentParts'.
	if part, ok := reportedAttachment(msg, strings.TrimSpace(filename)); ok {
		if payload, ok := part.Payload(); ok {
			name := pathName(filename)
			if name == "" || name == ".." {
				name = "attachment"
			}
			return &Attachment{Name: name, ContentType: part.ContentType(), Data: payload}, nil
		}
	}
	return nil, ErrNotFound
}
