// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func putSent(e *testEnv, name, subject, sentBy string) string {
	now := time.Now().UTC()
	base := "outbox/" + now.Format("2006/01/02") + "/" + name
	e.store.put(base+".eml", strings.Replace(sampleMessage, "Northwind daily totals", subject, 1), now)
	e.store.put(base+".json", string(mustJSON(map[string]any{
		"schema": 1, "message_id": name, "sent_at": now.Format(time.RFC3339), "subject": subject,
		"to": []string{"alice@client.example"}, "sent_by": sentBy, "eml_key": base + ".eml",
	})), now)
	return base + ".eml"
}

func TestOutboxPageListsSentEmail(t *testing.T) {
	e := elcanoEnv(t)
	putSent(e, "m1", "Weekly report", "dana@northwind.example")
	putSent(e, "m2", "Deal sheet", "")
	resp := e.get("/outbox")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"Sent (2)", "Weekly report", "dana@northwind.example", "Deal sheet",
		`href="/email?s3_key=outbox%2f`} {
		if !strings.Contains(resp.body, want) {
			t.Fatalf("missing %q:\n%s", want, resp.body)
		}
	}
	resp = e.get("/outbox?sent_by=dana")
	if !strings.Contains(resp.body, "Sent (1)") || strings.Contains(resp.body, "Deal sheet") {
		t.Fatalf("filter:\n%s", resp.body)
	}
}

func TestOutboxPageRefusesAWindowPastTheLimit(t *testing.T) {
	e := elcanoEnv(t)
	resp := e.get("/outbox?date_from=2025-01-01&date_to=2026-06-01")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, "Keep the window at or under 62 days") {
		t.Fatalf("status %d:\n%s", resp.StatusCode, resp.body)
	}
}

func TestASentEmailOpensWithABackLinkToTheOutbox(t *testing.T) {
	e := elcanoEnv(t)
	key := putSent(e, "m1", "Weekly report", "dana@northwind.example")
	resp := e.get("/email?s3_key=" + key)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, "Back to Outbox") {
		t.Fatalf("status %d:\n%s", resp.StatusCode, resp.body)
	}
	if resp := e.get("/email?s3_key=" + strings.TrimSuffix(key, ".eml") + ".json"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a record opened as an email: %d", resp.StatusCode)
	}
}

func TestInboxLinksToTheOutboxOnlyWhenItIsOn(t *testing.T) {
	if resp := elcanoEnv(t).get("/"); !strings.Contains(resp.body, `href="/outbox"`) {
		t.Fatal("no Outbox link")
	}
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano", "EMAIL_S3_OUTBOX_PREFIX": ""})
	e.setCookie("elcano_auth", mintElcano(e.priv, "alice@example.com", time.Now().Add(time.Hour)))
	if resp := e.get("/"); strings.Contains(resp.body, `href="/outbox"`) {
		t.Fatal("Outbox link while it is off")
	}
	if resp := e.get("/outbox"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/outbox while off: %d", resp.StatusCode)
	}
}
