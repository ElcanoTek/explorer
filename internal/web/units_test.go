// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
)

func d(s string) day {
	t, err := time.Parse(isoDate, s)
	if err != nil {
		panic(err)
	}
	return t
}

var fallback = d("2026-06-01")

func TestParseDateRanges(t *testing.T) {
	cases := []struct {
		raw  string
		want []dayRange
	}{
		{"", []dayRange{{fallback, fallback}}},
		{"2026-05-02", []dayRange{{d("2026-05-02"), d("2026-05-02")}}},
		{"2026-05-01..2026-05-03", []dayRange{{d("2026-05-01"), d("2026-05-03")}}},
		{"2026-05-01:2026-05-02, 2026-05-04 to 2026-05-05", []dayRange{{d("2026-05-01"), d("2026-05-02")}, {d("2026-05-04"), d("2026-05-05")}}},
		{"2026-05-09..2026-05-01", []dayRange{{d("2026-05-01"), d("2026-05-09")}}},
	}
	for _, tc := range cases {
		got, err := parseDateRanges(tc.raw, fallback)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q = %v, %v", tc.raw, got, err)
		}
	}
	if _, err := parseDateRanges("not-a-date", fallback); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParseDateWindows(t *testing.T) {
	cases := []struct {
		from, to []string
		legacy   string
		ranges   []dayRange
		windows  []dateWindow
	}{
		{[]string{"2026-05-01"}, []string{"2026-05-03"}, "", []dayRange{{d("2026-05-01"), d("2026-05-03")}}, []dateWindow{{"2026-05-01", "2026-05-03"}}},
		{[]string{"2026-05-01"}, nil, "", []dayRange{{d("2026-05-01"), d("2026-05-01")}}, []dateWindow{{"2026-05-01", "2026-05-01"}}},
		{[]string{"2026-05-09"}, []string{"2026-05-01"}, "", []dayRange{{d("2026-05-01"), d("2026-05-09")}}, []dateWindow{{"2026-05-01", "2026-05-09"}}},
		{nil, nil, "2026-05-01..2026-05-02", []dayRange{{d("2026-05-01"), d("2026-05-02")}}, []dateWindow{{"2026-05-01", "2026-05-02"}}},
	}
	for _, tc := range cases {
		ranges, windows, err := parseDateWindows(tc.from, tc.to, fallback, tc.legacy)
		if err != nil || !reflect.DeepEqual(ranges, tc.ranges) || !reflect.DeepEqual(windows, tc.windows) {
			t.Errorf("%v/%v/%q = %v %v %v", tc.from, tc.to, tc.legacy, ranges, windows, err)
		}
	}
}

func TestCountDaysCovered(t *testing.T) {
	cases := []struct {
		ranges []dayRange
		want   int
	}{
		{nil, 0},
		{[]dayRange{{fallback, fallback}}, 1},
		{[]dayRange{{d("2026-05-01"), d("2026-05-05")}, {d("2026-05-03"), d("2026-05-07")}}, 7},
		{[]dayRange{{d("2026-05-01"), d("2026-05-02")}, {d("2026-05-03"), d("2026-05-04")}}, 4},
		{[]dayRange{{d("2026-05-10"), d("2026-05-11")}, {d("2026-05-01"), d("2026-05-02")}}, 4},
		{[]dayRange{{fallback, fallback}, {fallback, fallback}}, 1},
	}
	for _, tc := range cases {
		if got := countDaysCovered(tc.ranges); got != tc.want {
			t.Errorf("%v = %d, want %d", tc.ranges, got, tc.want)
		}
	}
}

func TestS3KeyScoping(t *testing.T) {
	s := &Server{allowedRoots: []string{"emails/"}}
	for key, want := range map[string]bool{
		"emails/2026/06/01/abc123":            true,
		"secrets/backup.tar.gz":               false,
		"":                                    false,
		"emails/\x00bad":                      false,
		"emails/" + strings.Repeat("a", 1100): false,
	} {
		if got := s.isAllowedS3Key(key); got != want {
			t.Errorf("%q = %v", key, got)
		}
	}
}

func TestSafeLocalPath(t *testing.T) {
	for raw, want := range map[string]string{
		"/?mode=view":                   "/?mode=view",
		"/email?s3_key=emails%2Fx":      "/email?s3_key=emails%2Fx",
		"https://evil.example/":         "/",
		"//evil.example":                "/",
		`/\evil.example`:                "/",
		"relative":                      "/",
		"/a\x7fb":                       "/",
		"/" + strings.Repeat("a", 3000): "/",
	} {
		if got := safeLocalPath(raw, "/"); got != want {
			t.Errorf("%q = %q, want %q", raw, got, want)
		}
	}
}

func TestViewCursorRequiresSignatureAndOwner(t *testing.T) {
	jobs := newJobStore(time.Now)
	state := &archive.CursorState{PrefixIndex: 1}
	id := jobs.stashCursor(state, "sig-a", "owner-1")
	if jobs.loadCursor(id, "sig-a", "owner-1") != state {
		t.Fatal("round trip failed")
	}
	for _, c := range [][2]string{{"sig-b", "owner-1"}, {"sig-a", "owner-2"}} {
		if jobs.loadCursor(id, c[0], c[1]) != nil {
			t.Errorf("cursor loaded with %v", c)
		}
	}
	if jobs.loadCursor("missing", "sig-a", "owner-1") != nil {
		t.Error("missing id loaded")
	}
}

func TestSessionCookieIsSignedAndExpires(t *testing.T) {
	now := time.Now()
	codec := sessionCodec{key: []byte("k"), secure: true, now: func() time.Time { return now }}
	s := &uiSession{data: uiSessionData{SearchOwnerID: "abc"}, dirty: true}
	ck := codec.cookie(s)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	if got := codec.decode(req); got.data.SearchOwnerID != "abc" {
		t.Fatalf("round trip = %+v", got.data)
	}
	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(&http.Cookie{Name: uiCookieName, Value: strings.Replace(ck.Value, ck.Value[:4], "AAAA", 1)})
	if got := codec.decode(tampered); got.data.SearchOwnerID != "" {
		t.Fatal("tampered cookie accepted")
	}
	other := sessionCodec{key: []byte("other"), now: codec.now}
	if got := other.decode(req); got.data.SearchOwnerID != "" {
		t.Fatal("cookie verified under another secret")
	}
	later := sessionCodec{key: []byte("k"), now: func() time.Time { return now.Add(15 * 24 * time.Hour) }}
	if got := later.decode(req); got.data.SearchOwnerID != "" {
		t.Fatal("expired cookie accepted")
	}
}

func TestParseSender(t *testing.T) {
	for raw, want := range map[string]sender{
		`"Ada Lovelace" <ada@example.com>`: {"Ada Lovelace", "ada@example.com", "Ada Lovelace", "A"},
		"grace@example.com":                {"grace@example.com", "grace@example.com", "grace@example.com", "G"},
		"<x@example.com>":                  {"", "x@example.com", "x@example.com", "X"},
		"":                                 {"", "", "", "?"},
	} {
		if got := parseSender(raw); got != want {
			t.Errorf("%q = %+v, want %+v", raw, got, want)
		}
	}
}

func TestSafeAttachmentType(t *testing.T) {
	for name, want := range map[string]string{
		"logo.png":   "image/png",
		"x.svg":      "application/octet-stream",
		"page.html":  "application/octet-stream",
		"a.js":       "application/octet-stream",
		"notes.txt":  "text/plain; charset=utf-8",
		"report.pdf": "application/pdf",
		"blob":       "application/octet-stream",
	} {
		if got := safeAttachmentType(name, ""); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestRequestURLTrustsProtoOnlyFromLoopback(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://explorer.example.com/a?b=c", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.RemoteAddr = "127.0.0.1:5000"
	if got := requestURL(r); got != "https://explorer.example.com/a?b=c" {
		t.Errorf("loopback proxy: %q", got)
	}
	r.RemoteAddr = "203.0.113.9:5000"
	if got := requestURL(r); got != "http://explorer.example.com/a?b=c" {
		t.Errorf("remote client: %q", got)
	}
}
