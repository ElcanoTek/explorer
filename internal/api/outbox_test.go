// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"net/http"
	"testing"
)

const sentRecord = `{"schema":1,"message_id":"m1","sent_at":"2026-06-01T09:00:00Z","from":"victoria@northwind.example",
"to":["alice@client.example"],"cc":[],"bcc":["audit@northwind.example"],"subject":"Weekly report",
"content_type":"text/html","attachments":[{"name":"r.csv","mime_type":"text/csv","size":12,"inline":false}],
"sent_by":"dana@northwind.example","task_id":"","eml_key":"outbox/2026/06/01/m1.eml","eml_size":99}`

func TestSearchOutboxThenReadTheMessage(t *testing.T) {
	h := newHarness(t, nil)
	h.put("outbox/2026/06/01/m1.eml", mailFrom("victoria@northwind.example", "", "Weekly report", "Numbers."))
	h.put("outbox/2026/06/01/m1.json", []byte(sentRecord))

	code, body := h.post("search_outbox", map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01",
		"recipient_contains": "audit@"}, h.raw)
	if code != http.StatusOK || body["matches_found"] != float64(1) {
		t.Fatalf("%d %v", code, body)
	}
	email := body["emails"].([]any)[0].(map[string]any)
	if email["s3_key"] != "outbox/2026/06/01/m1.eml" || email["sent_by"] != "dana@northwind.example" ||
		email["bcc"].([]any)[0] != "audit@northwind.example" {
		t.Fatalf("email %v", email)
	}

	code, body = h.post("get_email", map[string]any{"s3_key": email["s3_key"]}, h.raw)
	if code != http.StatusOK || body["subject"] != "Weekly report" {
		t.Fatalf("get_email %d %v", code, body)
	}
}

func TestAnOutboxRecordIsNotAnEmail(t *testing.T) {
	h := newHarness(t, nil)
	h.put("outbox/2026/06/01/m1.json", []byte(sentRecord))
	code, body := h.post("get_email", map[string]any{"s3_key": "outbox/2026/06/01/m1.json"}, h.raw)
	if code != http.StatusNotFound {
		t.Fatalf("%d %v", code, body)
	}
}

func TestSearchOutboxNeedsADateWindow(t *testing.T) {
	h := newHarness(t, nil)
	code, body := h.post("search_outbox", map[string]any{"date_from": "2026-06-01"}, h.raw)
	if code != http.StatusBadRequest {
		t.Fatalf("%d %v", code, body)
	}
}

func TestSearchOutboxWhenTheOutboxIsOff(t *testing.T) {
	h := newHarness(t, map[string]string{"EMAIL_S3_OUTBOX_PREFIX": ""})
	code, body := h.post("search_outbox", map[string]any{"date_from": "2026-06-01", "date_to": "2026-06-01"}, h.raw)
	if code != http.StatusNotFound || body["code"] != "outbox_off" {
		t.Fatalf("%d %v", code, body)
	}
}
