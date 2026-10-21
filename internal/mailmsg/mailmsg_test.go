// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package mailmsg

import (
	"strings"
	"testing"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestParseHeadersUnfoldsAndStopsAtBody(t *testing.T) {
	h := ParseHeaders(crlf("From reporter@example.com Mon Jun  1 12:00:00 2026\n" +
		"Subject: Daily\n  report\nFrom: Ada <ada@example.com>\nTo: archive@example.com\n\nbody: not a header\n"))
	if got := h.Get("subject"); got != "Daily  report" {
		t.Fatalf("subject = %q", got)
	}
	if h.Get("FROM") != "Ada <ada@example.com>" || h.Get("to") != "archive@example.com" {
		t.Fatalf("headers = %+v", h)
	}
	if h.Has("body") {
		t.Fatal("body line parsed as a header")
	}
}

func TestParseHeadersToleratesGarbage(t *testing.T) {
	h := ParseHeaders([]byte(" continuation first\nSubject: ok\nthis is not a header\nTo: later@example.com\n"))
	if h.Get("Subject") != "ok" || h.Has("To") {
		t.Fatalf("headers = %+v", h)
	}
	// A truncated ranged read mid-header still yields what it holds.
	h = ParseHeaders([]byte("Subject: cut\r\nFrom: Ada <ada@exa"))
	if h.Get("From") != "Ada <ada@exa" {
		t.Fatalf("headers = %+v", h)
	}
	if len(ParseHeaders(nil)) != 0 {
		t.Fatal("empty input produced headers")
	}
}

func TestEightBitHeaders(t *testing.T) {
	if got := ParseHeaders([]byte("Subject: caf\xc3\xa9\n\n")).Get("Subject"); got != "café" {
		t.Fatalf("utf-8 header = %q", got)
	}
	if got := ParseHeaders([]byte("Subject: caf\xe9\n\n")).Get("Subject"); got != "café" {
		t.Fatalf("latin-1 header = %q", got)
	}
}

func TestDecodeHeader(t *testing.T) {
	cases := map[string]string{
		"=?utf-8?b?Y2Fmw6k=?=":                          "café",
		"=?iso-8859-1?q?caf=E9?= au lait":               "café au lait",
		"=?UTF-8?Q?a_b?= =?UTF-8?Q?c?=":                 "a bc",
		"plain text":                                    "plain text",
		"=?windows-1252?q?=93quoted=94?=":               "“quoted”",
		"=?x-totally-bogus?q?hi?=":                      "hi",
		"=?utf-8?b?not base64?=":                        "=?utf-8?b?not base64?=",
		"Reports =?utf-8?q?=E2=9C=93?= <r@example.com>": "Reports ✓ <r@example.com>",
	}
	for in, want := range cases {
		if got := DecodeHeader(in); got != want {
			t.Errorf("DecodeHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeBytes(t *testing.T) {
	if got := DecodeBytes([]byte("caf\xc3\xa9"), "utf-8//translit"); got != "café" {
		t.Fatalf("bogus label: %q", got)
	}
	if got := DecodeBytes([]byte("hello"), "ansi_x3.110-1983-bogus"); got != "hello" {
		t.Fatalf("unknown label: %q", got)
	}
	if got := DecodeBytes([]byte("caf\xe9"), "ISO-8859-1"); got != "café" {
		t.Fatalf("latin-1: %q", got)
	}
	if got := DecodeBytes([]byte("\x82\xa0"), "shift_jis"); got != "あ" {
		t.Fatalf("shift_jis: %q", got)
	}
	if got := DecodeBytes([]byte("a\xffb"), ""); got != "a\uFFFDb" {
		t.Fatalf("invalid utf-8: %q", got)
	}
	if got := DecodeBytes([]byte("\xc4\xe3\xba\xc3"), "gb2312"); got != "你好" {
		t.Fatalf("gb2312: %q", got)
	}
}

const nested = `From: Reports <reporting@ssp.example>
To: archive@example.com
Subject: Daily report
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble
--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

caf=E9 soft=
break
--inner
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PHA+aGk8L3A+
--inner--
--outer
Content-Type: application/pdf; name="fallback.pdf"
Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf
Content-Transfer-Encoding: base64

UERG
REFU!!QQ
--outer
Content-Type: message/rfc822

Subject: inner message
Content-Type: text/plain

inner body
--outer--
epilogue
`

func TestNestedMultipartWalk(t *testing.T) {
	msg := Parse(crlf(nested))
	types := make([]string, 0, len(msg.Walk()))
	for _, p := range msg.Walk() {
		types = append(types, p.ContentType())
	}
	want := "multipart/mixed multipart/alternative text/plain text/html application/pdf message/rfc822 text/plain"
	if got := strings.Join(types, " "); got != want {
		t.Fatalf("walk = %s\nwant %s", got, want)
	}
	parts := msg.Walk()
	plain, _ := parts[2].Payload()
	if got := DecodeBytes(plain, parts[2].Charset()); got != "café softbreak" {
		t.Fatalf("qp body = %q", got)
	}
	html, _ := parts[3].Payload()
	if string(html) != "<p>hi</p>" {
		t.Fatalf("base64 body = %q", html)
	}
	pdf, _ := parts[4].Payload()
	if string(pdf) != "PDFDATA" {
		t.Fatalf("lenient base64 = %q", pdf)
	}
	if parts[4].Filename() != "résumé.pdf" {
		t.Fatalf("rfc2231 filename = %q", parts[4].Filename())
	}
	if _, ok := parts[5].Payload(); ok {
		t.Fatal("message/rfc822 container returned a payload")
	}
	inner, _ := parts[6].Payload()
	if string(inner) != "inner body" || parts[6].Header.Get("Subject") != "inner message" {
		t.Fatalf("inner = %q %+v", inner, parts[6].Header)
	}
	if _, ok := msg.Payload(); ok {
		t.Fatal("multipart container returned a payload")
	}
}

func TestMissingCloseBoundaryAndNoBoundary(t *testing.T) {
	msg := Parse([]byte("Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nfirst\n--b\n\nsecond line\n"))
	parts := msg.Walk()
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	if body, _ := parts[2].Payload(); string(body) != "second line\n" {
		t.Fatalf("last part = %q", body)
	}
	if parts[2].ContentType() != "text/plain" {
		t.Fatalf("default type = %q", parts[2].ContentType())
	}
	// A multipart that never shows its boundary is a leaf with its raw body.
	msg = Parse([]byte("Content-Type: multipart/mixed; boundary=zz\n\nno parts here\n"))
	if len(msg.Walk()) != 1 {
		t.Fatal("phantom parts")
	}
	if body, ok := msg.Payload(); !ok || string(body) != "no parts here\n" {
		t.Fatalf("payload = %q %v", body, ok)
	}
}

func TestContentTypeDefaultsAndParams(t *testing.T) {
	p := Parse([]byte("Content-Type: TEXT/HTML; Charset=\"UTF-8\"; name=\"a;b.html\"\n\nx"))
	if p.ContentType() != "text/html" || p.Charset() != "utf-8" || p.Filename() != "a;b.html" {
		t.Fatalf("%q %q %q", p.ContentType(), p.Charset(), p.Filename())
	}
	if got := Parse([]byte("Content-Type: bogus\n\nx")).ContentType(); got != "text/plain" {
		t.Fatalf("bogus type = %q", got)
	}
	if got := Parse([]byte("Subject: x\n\nx")).MainType(); got != "text" {
		t.Fatalf("default main type = %q", got)
	}
	p = Parse([]byte("Content-Disposition: attachment; filename*0=\"long\"; filename*1=\"name.txt\"\n\nx"))
	if p.Filename() != "longname.txt" {
		t.Fatalf("continuation = %q", p.Filename())
	}
	digest := Parse([]byte("Content-Type: multipart/digest; boundary=d\n\n--d\n\nSubject: s\n\nb\n--d--\n"))
	if got := digest.Walk()[1].ContentType(); got != "message/rfc822" {
		t.Fatalf("digest child type = %q", got)
	}
}

func TestDeepNestingIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("Content-Type: message/rfc822\n\n")
	}
	b.WriteString("Subject: bottom\n\nend")
	if n := len(Parse([]byte(b.String())).Walk()); n > maxDepth+1 {
		t.Fatalf("walked %d levels", n)
	}
}

func TestZeroByteMessage(t *testing.T) {
	msg := Parse(nil)
	if len(msg.Header) != 0 || msg.ContentType() != "text/plain" {
		t.Fatalf("%+v", msg)
	}
	if body, ok := msg.Payload(); !ok || len(body) != 0 {
		t.Fatalf("payload = %q %v", body, ok)
	}
}
