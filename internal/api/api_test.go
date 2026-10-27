// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/config"
)

const passAuth = "amazonses.com; dmarc=pass header.from=vendor.example"

var now = time.Date(2026, 6, 3, 15, 0, 0, 0, time.UTC)

// fakeStore is an in-memory archive.Store. failPrefix makes List fail like
// an S3 AccessDenied for that prefix.
type fakeStore struct {
	mu         sync.Mutex
	objects    map[string][]byte
	modified   map[string]time.Time
	failPrefix string
}

func (f *fakeStore) List(_ context.Context, prefix, _ string, _ int32) (archive.ListPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPrefix != "" && prefix == f.failPrefix {
		return archive.ListPage{}, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	}
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	page := archive.ListPage{}
	for _, k := range keys {
		page.Objects = append(page.Objects, archive.Object{Key: k, LastModified: f.modified[k], Size: int64(len(f.objects[k]))})
	}
	return page, nil
}

func (f *fakeStore) Get(_ context.Context, key string, maxBytes int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return data[:maxBytes], nil
	}
	return data, nil
}

func mailFrom(from, auth, subject, body string) []byte {
	head := ""
	if auth != "" {
		head = "Authentication-Results: " + auth + "\r\n"
	}
	return []byte(head + "From: <" + from + ">\r\nTo: inbox@example.com\r\nSubject: " + subject +
		"\r\nDate: Mon, 01 Jun 2026 10:00:00 +0000\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n")
}

type harness struct {
	t     *testing.T
	store *fakeStore
	api   *API
	raw   string
}

func newHarness(t *testing.T, env map[string]string) *harness {
	t.Helper()
	full := map[string]string{"EMAIL_S3_BUCKET": "b"}
	for k, v := range env {
		full[k] = v
	}
	s, err := config.FromEnv(full)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{objects: map[string][]byte{}, modified: map[string]time.Time{}}
	tokens := apitoken.NewStore(filepath.Join(t.TempDir(), "api_tokens.db"))
	t.Cleanup(func() { _ = tokens.Close() })
	_, raw, err := tokens.Create(context.Background(), "test", apitoken.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{Inbox: archive.New(store, s), Settings: s, Tokens: tokens, Now: func() time.Time { return now }})
	return &harness{t: t, store: store, api: a, raw: raw}
}

func (h *harness) put(key string, data []byte) {
	h.store.objects[key] = data
	day := strings.Split(key, "/")
	h.store.modified[key] = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if len(day) >= 4 {
		if t, err := time.Parse("2006/01/02", strings.Join(day[1:4], "/")); err == nil {
			h.store.modified[key] = t.Add(12 * time.Hour)
		}
	}
}

func (h *harness) post(op string, args any, token string) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(args)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+op, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.api.Routes().ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		h.t.Fatalf("%s: not JSON: %s", op, rec.Body.String())
	}
	return rec.Code, body
}

func codes(body map[string]any) []string {
	ws, _ := body["search_warnings"].([]any)
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.(map[string]any)["code"].(string))
	}
	return out
}

func TestRESTRequiresAToken(t *testing.T) {
	h := newHarness(t, nil)
	status, body := h.post("search_emails", map[string]any{}, "")
	if status != http.StatusUnauthorized || body["code"] != "unauthorized" {
		t.Fatalf("%d %v", status, body)
	}
	status, _ = h.post("search_emails", map[string]any{}, apitoken.TokenPrefix+"nope")
	if status != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", status)
	}
}

func TestSearchEmailsShapeAndWarnings(t *testing.T) {
	h := newHarness(t, nil)
	h.put("emails/2026/06/01/ok", mailFrom("reports@vendor.example", passAuth, "Daily report", "x"))
	h.put("emails/2026/06/01/forged", mailFrom("reports@vendor.example", "", "Daily report", "x"))
	status, body := h.post("search_emails", map[string]any{
		"sender_contains": "vendor.example,exchange", "date_from": "2026-06-01", "date_to": "2026-06-01",
	}, h.raw)
	if status != http.StatusOK || body["ok"] != true || body["status"] != "success" || body["matches_found"].(float64) != 1 {
		t.Fatalf("%d %v", status, body)
	}
	email := body["emails"].([]any)[0].(map[string]any)
	if email["s3_key"] != "emails/2026/06/01/ok" || email["sender_authenticated"] != true || email["payload_checked"] != false {
		t.Fatalf("email %v", email)
	}
	got := strings.Join(codes(body), ",")
	if !strings.Contains(got, "sender_filter_entries_ignored") || !strings.Contains(got, "unauthenticated_sender_skipped") {
		t.Fatalf("warnings %v", got)
	}
	criteria := body["search_criteria"].(map[string]any)
	if criteria["effective_date_to"] != "2026-06-01T23:59:59.999999+00:00" || criteria["has_payload"] != nil {
		t.Fatalf("criteria %v", criteria)
	}
}

func TestSearchEmailsValidation(t *testing.T) {
	h := newHarness(t, nil)
	for _, tc := range []struct {
		args map[string]any
		code string
	}{
		{map[string]any{"date_from": "2026-06-01"}, "bounded_date_window_required"},
		{map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01", "bogus": 1}, "invalid_argument"},
		{map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01", "sender_contains": "!!"}, "filter_not_meaningful"},
		{map[string]any{"date_from": "June 1", "date_to": "2026-06-01"}, "invalid_argument"},
		{map[string]any{"date_from": "2026-01-01", "date_to": "2026-06-01"}, "invalid_argument"},
		{map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01", "max_results": 501}, "invalid_argument"},
		{map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01", "has_payload": "yes"}, "invalid_argument"},
	} {
		status, body := h.post("search_emails", tc.args, h.raw)
		if status != http.StatusBadRequest || body["code"] != tc.code || body["status"] != "error" {
			t.Errorf("%v: %d %v", tc.args, status, body)
		}
	}
	status, body := h.post("search_emails", map[string]any{"date_from": "2026-06-04", "date_to": "2026-06-01"}, h.raw)
	if status != http.StatusOK || !strings.Contains(strings.Join(codes(body), ","), "date_window_auto_chunked") {
		t.Fatalf("auto-chunked window: %d %v", status, body)
	}
}

func TestAnS3FailureIsARetryableError(t *testing.T) {
	h := newHarness(t, nil)
	h.store.failPrefix = "emails/2026/06/01/"
	status, body := h.post("search_emails", map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01"}, h.raw)
	if status != http.StatusBadGateway || body["code"] != "archive_unavailable" || body["retryable"] != true ||
		!strings.Contains(body["error"].(string), "AccessDenied") {
		t.Fatalf("%d %v", status, body)
	}
}

func TestFindLatestReportWalksBackAndFailsOnAFailedDay(t *testing.T) {
	h := newHarness(t, nil)
	h.put("emails/2026/06/01/report", mailFrom("reports@vendor.example", passAuth, "Daily report",
		"Download: https://vendor.example/files/daily.csv"))
	h.put("emails/2026/06/02/forged", mailFrom("reports@vendor.example", "", "Daily report", "https://vendor.example/files/daily.csv"))
	h.put("emails/2026/06/03/forged", mailFrom("reports@vendor.example", "", "Daily report", "https://vendor.example/files/daily.csv"))
	status, body := h.post("find_latest_report", map[string]any{"sender_contains": "vendor.example", "lookback_days": 5}, h.raw)
	if status != http.StatusOK || body["first_match_date"] != "2026-06-01" || body["days_searched"].(float64) != 3 ||
		body["anchor_date"] != "2026-06-03" {
		t.Fatalf("%d %v", status, body)
	}
	email := body["emails"].([]any)[0].(map[string]any)
	if email["has_download_links"] != true || email["payload_checked"] != true {
		t.Fatalf("email %v", email)
	}
	ws := body["search_warnings"].([]any)
	if len(ws) != 1 {
		t.Fatalf("warnings %v", ws)
	}
	w := ws[0].(map[string]any)
	if w["code"] != "unauthenticated_sender_unchecked" || w["count"].(float64) != 2 || len(w["days"].([]any)) != 2 ||
		!strings.HasPrefix(w["message"].(string), "2 email(s) across 2 day(s)") {
		t.Fatalf("merged warning %v", w)
	}

	// A newer day that cannot be searched fails the call: the older report
	// must not pass for the latest.
	h.store.failPrefix = "emails/2026/06/02/"
	status, body = h.post("find_latest_report", map[string]any{"sender_contains": "vendor.example", "lookback_days": 5}, h.raw)
	if status != http.StatusBadGateway || body["failed_day"] != "2026-06-02" || body["retryable"] != true ||
		len(body["emails"].([]any)) != 0 || !strings.HasPrefix(body["error"].(string), "Search for 2026-06-02 failed") {
		t.Fatalf("%d %v", status, body)
	}
}

func TestSearchEmailsFuzzy(t *testing.T) {
	h := newHarness(t, nil)
	h.put("emails/2026/06/01/a", mailFrom("reports@vendor.example", passAuth, "Weekly pacing", "x"))
	status, body := h.post("search_emails_fuzzy", map[string]any{
		"keywords": []string{"pacing", "vendor.example"}, "match_all": true, "date_from": "2026-06-01", "date_to": "2026-06-01",
	}, h.raw)
	if status != http.StatusOK || body["matches_found"].(float64) != 1 {
		t.Fatalf("%d %v", status, body)
	}
	for _, tc := range []map[string]any{
		{"keywords": []string{" "}, "date_from": "2026-06-01"},
		{"keywords": []string{"x"}},
		{"keywords": []string{"x"}, "search_fields": []string{"headers"}, "date_from": "2026-06-01"},
		{"keywords": []string{"x"}, "search_fields": []string{"body"}, "date_from": "2026-05-01", "date_to": "2026-06-01"},
	} {
		if status, body := h.post("search_emails_fuzzy", tc, h.raw); status != http.StatusBadRequest {
			t.Errorf("%v: %d %v", tc, status, body)
		}
	}
}

func TestOperationListing(t *testing.T) {
	h := newHarness(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/", nil)
	req.Header.Set("Authorization", "Bearer "+h.raw)
	rec := httptest.NewRecorder()
	h.api.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "find_latest_report") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	status, _ := h.post("nope", map[string]any{}, h.raw)
	if status != http.StatusNotFound {
		t.Fatalf("unknown op: %d", status)
	}
}
