// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
)

const reportLink = "https://reports.vendor.example/dl?id=1&amp;sig=abc"

func reportEmail() []byte {
	return []byte("Authentication-Results: " + passAuth + "\r\nFrom: <reports@vendor.example>\r\nTo: inbox@example.com\r\n" +
		"Subject: Daily report\r\nDate: Mon, 01 Jun 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/html\r\n\r\n" +
		`<a href="` + reportLink + `">Download</a> <a href="https://live.vendor.example/export?format=csv">live</a>` + "\r\n" +
		"--XX\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename=\"summary.csv\"\r\n\r\nx,y\r\n--XX--\r\n")
}

func (h *harness) withReport() (email, cachedKey string) {
	email = "emails/2026/06/01/msg1"
	cachedKey = "emails/attachments/by-url/" + archive.URLHash(reportLink) + "/report.csv"
	h.put(email, reportEmail())
	h.put("emails/attachments/manifests/2026/06/01/msg1.json", []byte(`{"email_key":"`+email+`","processed_at":"2026-06-01T12:05:00+00:00",`+
		`"links_found":2,"download_candidates":2,"archived":1,"links":[{"url":"`+reportLink+`","status":"archived","archive_key":"`+cachedKey+
		`","filename":"report.csv","size":11}]}`))
	h.put(cachedKey, []byte("cached,data"))
	return email, cachedKey
}

func (h *harness) fetch(url string) (int, string, http.Header) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	h.api.Routes().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return rec.Code, string(body), rec.Header()
}

func TestGetEmailShowsLinksWithTheirCacheState(t *testing.T) {
	h := newHarness(t, nil)
	email, _ := h.withReport()
	status, body := h.post("get_email", map[string]any{"s3_key": email}, h.raw)
	if status != http.StatusOK || body["sender_authenticated"] != true || body["attachment_count"].(float64) != 1 {
		t.Fatalf("%d %v", status, body)
	}
	links := body["download_links"].([]any)
	first, second := links[0].(map[string]any), links[1].(map[string]any)
	if first["url"] != reportLink || first["cache"].(map[string]any)["cached"] != true ||
		second["cache"].(map[string]any)["status"] != "not_in_manifest" {
		t.Fatalf("links %v", links)
	}
	if body["link_cache"].(map[string]any)["status"] != "present" {
		t.Fatalf("link_cache %v", body["link_cache"])
	}
	status, body = h.post("list_archived_attachments", map[string]any{"s3_key": email}, h.raw)
	if status != http.StatusOK || body["status"] != "success" || body["email_key"] != email {
		t.Fatalf("manifest %d %v", status, body)
	}
	for _, key := range []string{"emails/attachments/by-url/x/report.csv", "../etc/passwd", "other/2026/06/01/x"} {
		if status, _ := h.post("get_email", map[string]any{"s3_key": key}, h.raw); status != http.StatusNotFound {
			t.Errorf("%s: %d", key, status)
		}
	}
	if status, body := h.post("get_email", map[string]any{"s3_key": "emails/2026/06/01/missing"}, h.raw); status != http.StatusNotFound {
		t.Fatalf("missing email: %d %v", status, body)
	}
}

func TestDownloadLinksServeTheCachedCopyAndAttachments(t *testing.T) {
	h := newHarness(t, nil)
	email, _ := h.withReport()

	status, body := h.post("get_download_link", map[string]any{"s3_key": email, "url": reportLink}, h.raw)
	if status != http.StatusOK || body["source"] != "cached" || body["filename"] != "report.csv" {
		t.Fatalf("%d %v", status, body)
	}
	url := body["download_url"].(string)
	if !strings.HasPrefix(url, "https://example.com/api/v1/download?ticket=") {
		t.Fatalf("url %s", url)
	}
	code, data, hdr := h.fetch(strings.TrimPrefix(url, "https://example.com"))
	if code != http.StatusOK || data != "cached,data" || hdr.Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(hdr.Get("Content-Disposition"), "report.csv") || !strings.Contains(hdr.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download %d %q %v", code, data, hdr)
	}

	status, body = h.post("get_download_link", map[string]any{"s3_key": email, "filename": "summary.csv"}, h.raw)
	if status != http.StatusOK || body["source"] != "attachment" {
		t.Fatalf("%d %v", status, body)
	}
	code, data, _ = h.fetch(strings.TrimPrefix(body["download_url"].(string), "https://example.com"))
	if code != http.StatusOK || data != "x,y" {
		t.Fatalf("attachment %d %q", code, data)
	}

	status, body = h.post("get_download_link", map[string]any{"s3_key": email, "url": "https://live.vendor.example/export?format=csv"}, h.raw)
	if status != http.StatusOK || body["source"] != "live" || body["download_url"] != "https://live.vendor.example/export?format=csv" {
		t.Fatalf("live %d %v", status, body)
	}
	for _, args := range []map[string]any{
		{"s3_key": email},
		{"s3_key": email, "url": reportLink, "filename": "summary.csv"},
	} {
		if status, _ := h.post("get_download_link", args, h.raw); status != http.StatusBadRequest {
			t.Errorf("%v: %d", args, status)
		}
	}
	for _, args := range []map[string]any{
		{"s3_key": email, "url": "https://evil.example/x.csv"},
		{"s3_key": email, "filename": "nope.csv"},
	} {
		if status, _ := h.post("get_download_link", args, h.raw); status != http.StatusNotFound {
			t.Errorf("%v: %d", args, status)
		}
	}
}

func TestTicketsAreBoundToTheirTokenAndScope(t *testing.T) {
	h := newHarness(t, nil)
	email, _ := h.withReport()
	_, body := h.post("get_download_link", map[string]any{"s3_key": email, "url": reportLink}, h.raw)
	path := strings.TrimPrefix(body["download_url"].(string), "https://example.com")
	if code, _, _ := h.fetch(path + "x"); code != http.StatusUnauthorized {
		t.Fatalf("tampered ticket: %d", code)
	}
	if code, _, _ := h.fetch("/api/v1/download"); code != http.StatusUnauthorized {
		t.Fatalf("no ticket: %d", code)
	}
	if ok, err := h.tokens.Revoke(context.Background(), 1); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if code, _, _ := h.fetch(path); code != http.StatusUnauthorized {
		t.Fatalf("revoked token's ticket: %d", code)
	}

	// A search-only token cannot read messages or mint links.
	_, raw, err := h.tokens.Create(context.Background(), "search-only", []string{apitoken.ScopeSearch})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := h.post("get_email", map[string]any{"s3_key": email}, raw); status != http.StatusNotFound {
		t.Fatalf("search-only get_email: %d", status)
	}
	if status, _ := h.post("search_emails", map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01"}, raw); status != http.StatusOK {
		t.Fatalf("search-only search: %d", status)
	}
}
