package api

import (
	"net/http"
	"strings"
	"testing"
)

// Calls a client deployment's agent made (2026-10) that were refused for an
// argument spelling, each costing a model round trip: a free-text query in
// place of keywords, limit in place of max_results, output_dir (the
// download_url tool's own argument) on get_download_link, and a date window
// too wide with no hint of the date_from that would fit.

func TestFuzzyQueryIsItsWordsAsKeywords(t *testing.T) {
	h := newHarness(t, nil)
	h.put("emails/2026/06/01/a", mailFrom("reports@vendor.example", passAuth, "Weekly pacing", "x"))
	status, body := h.post("search_emails_fuzzy", map[string]any{
		"query": "pacing, vendor.example", "match_all": true, "date_from": "2026-06-01", "date_to": "2026-06-01",
	}, h.raw)
	if status != http.StatusOK || body["matches_found"].(float64) != 1 {
		t.Fatalf("%d %v", status, body)
	}
}

func TestFuzzyLimitIsMaxResults(t *testing.T) {
	h := newHarness(t, nil)
	h.put("emails/2026/06/01/a", mailFrom("reports@vendor.example", passAuth, "Weekly pacing", "x"))
	h.put("emails/2026/06/01/b", mailFrom("reports@vendor.example", passAuth, "Daily pacing", "x"))
	status, body := h.post("search_emails_fuzzy", map[string]any{
		"keywords": []string{"pacing"}, "limit": 1, "date_from": "2026-06-01", "date_to": "2026-06-01",
	}, h.raw)
	if status != http.StatusOK || len(body["emails"].([]any)) != 1 {
		t.Fatalf("%d %v", status, body)
	}
}

func TestFuzzyWithNeitherKeywordsNorQueryIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	status, body := h.post("search_emails_fuzzy", map[string]any{"query": " , ", "date_from": "2026-06-01"}, h.raw)
	if status != http.StatusBadRequest || !strings.Contains(body["error"].(string), "query") {
		t.Fatalf("%d %v", status, body)
	}
}

func TestATooWideWindowNamesTheDateFromThatFits(t *testing.T) {
	h := newHarness(t, nil)
	status, body := h.post("search_emails_fuzzy", map[string]any{
		"keywords": []string{"pacing"}, "date_from": "2026-01-01", "date_to": "2026-06-01",
	}, h.raw)
	msg, _ := body["error"].(string)
	if status != http.StatusBadRequest || !strings.Contains(msg, "date_from ") || !strings.Contains(msg, "fits with this date_to") {
		t.Fatalf("%d %v", status, body)
	}
	maxDays := h.api.settings.MaxDatePrefixDays
	status, body = h.post("search_emails_fuzzy", map[string]any{
		"keywords": []string{"pacing"}, "date_from": strings.Fields(strings.SplitN(msg, "(date_from ", 2)[1])[0], "date_to": "2026-06-01",
	}, h.raw)
	if status != http.StatusOK {
		t.Fatalf("the suggested %d-day window was refused: %d %v", maxDays, status, body)
	}
}

func TestDownloadLinkIgnoresOutputDir(t *testing.T) {
	h := newHarness(t, nil)
	email, _ := h.withReport()
	status, body := h.post("get_download_link", map[string]any{
		"s3_key": email, "url": reportLink, "output_dir": "/var/lib/fleet/workspace/x",
	}, h.raw)
	if status != http.StatusOK || body["source"] != "cached" {
		t.Fatalf("%d %v", status, body)
	}
}
