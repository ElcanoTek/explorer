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
	// The Outbox opens on View, listed at once. The fixtures are filed by
	// their UTC day, so ask for that day: today on the host's clock can be
	// another date.
	day := time.Now().UTC().Format("2006-01-02")
	resp := e.get("/outbox?day=" + day)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"Sent on " + day + " (2)", "Weekly report", "dana@northwind.example", "Deal sheet",
		`href="/email?s3_key=outbox%2f`} {
		if !strings.Contains(resp.body, want) {
			t.Fatalf("missing %q:\n%s", want, resp.body)
		}
	}
	resp = e.get("/outbox?mode=exact&run_search=1&sent_by=dana&date_from=" + day + "&date_to=" + day)
	if !strings.Contains(resp.body, "Sent (1)") || strings.Contains(resp.body, "Deal sheet") {
		t.Fatalf("filter:\n%s", resp.body)
	}
}

func TestOutboxSearchAndFuzzyRunOnlyWhenSubmitted(t *testing.T) {
	e := elcanoEnv(t)
	putSent(e, "m1", "Quarterly totals", "")
	for _, mode := range []string{"exact", "fuzzy"} {
		resp := e.get("/outbox?mode=" + mode)
		if resp.StatusCode != http.StatusOK || strings.Contains(resp.body, "Quarterly totals") {
			t.Fatalf("%s searched before it was submitted:\n%s", mode, resp.body)
		}
	}
}

func TestOutboxFuzzySearch(t *testing.T) {
	e := elcanoEnv(t)
	putSent(e, "m1", "Weekly report", "")
	putSent(e, "m2", "Deal sheet", "")
	days := "&date_from=" + time.Now().UTC().Format("2006-01-02") + "&date_to=" + time.Now().UTC().Format("2006-01-02")
	// A first visit checks Subject and Recipients; Body starts off.
	resp := e.get("/outbox?mode=fuzzy")
	for _, want := range []string{`id="search-subject-checkbox" name="search_subject" checked`,
		`id="search-recipients-checkbox" name="search_recipients" checked`} {
		if !strings.Contains(resp.body, want) {
			t.Fatalf("missing %q:\n%s", want, resp.body)
		}
	}
	if strings.Contains(resp.body, `name="search_body" checked`) {
		t.Fatal("Body is checked on a first visit")
	}
	resp = e.get("/outbox?mode=fuzzy&run_search=1&keywords=weekly,+nothing&search_subject=on" + days)
	if !strings.Contains(resp.body, "Sent (1)") || !strings.Contains(resp.body, "Weekly report") ||
		strings.Contains(resp.body, "Deal sheet") {
		t.Fatalf("fuzzy:\n%s", resp.body)
	}
	// A submitted form keeps its own boxes: Subject alone, so a recipient
	// keyword finds nothing.
	resp = e.get("/outbox?mode=fuzzy&run_search=1&keywords=alice&search_subject=on" + days)
	if !strings.Contains(resp.body, "Sent (0)") {
		t.Fatalf("searched an unchecked field:\n%s", resp.body)
	}
	for query, want := range map[string]string{
		"keywords=+,+&search_subject=on": "Enter at least one keyword.",
		"keywords=weekly":                "Choose at least one field to search",
		"keywords=weekly&search_body=on&date_from=2026-01-01&date_to=2026-02-28": "Body fuzzy search spans 59 days",
	} {
		resp := e.get("/outbox?mode=fuzzy&run_search=1&" + query)
		if !strings.Contains(resp.body, want) {
			t.Fatalf("%s: missing %q:\n%s", query, want, resp.body)
		}
	}
}

func TestOutboxViewDayButtonNamesTheDay(t *testing.T) {
	if body := elcanoEnv(t).get("/outbox").body; !strings.Contains(body, `aria-label="Choose day"`) {
		t.Fatalf("day button label:\n%s", body)
	}
}

func TestTheMailboxTabsMarkTheCurrentPage(t *testing.T) {
	e := elcanoEnv(t)
	if body := e.get("/").body; !strings.Contains(body, `<a class="tab" href="/" aria-current="page">Inbox</a>`) ||
		!strings.Contains(body, `<a class="tab" href="/outbox">Outbox</a>`) {
		t.Fatalf("inbox tabs:\n%s", body)
	}
	if body := e.get("/outbox").body; !strings.Contains(body, `<a class="tab" href="/">Inbox</a>`) ||
		!strings.Contains(body, `<a class="tab" href="/outbox" aria-current="page">Outbox</a>`) {
		t.Fatalf("outbox tabs:\n%s", body)
	}
}

func TestOutboxPageRefusesAWindowPastTheLimit(t *testing.T) {
	e := elcanoEnv(t)
	resp := e.get("/outbox?mode=exact&run_search=1&date_from=2025-01-01&date_to=2026-06-01")
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

func TestALinkFromTheSingleFormOutboxStillSearches(t *testing.T) {
	e := elcanoEnv(t)
	putSent(e, "m1", "Weekly report", "dana@northwind.example")
	putSent(e, "m2", "Deal sheet", "")
	day := time.Now().UTC().Format("2006-01-02")
	resp := e.get("/outbox?date_from=" + day + "&date_to=" + day + "&sent_by=dana")
	if !strings.Contains(resp.body, "Sent (1)") || strings.Contains(resp.body, "Deal sheet") ||
		!strings.Contains(resp.body, `<input type="hidden" name="mode" value="exact" />`) {
		t.Fatalf("legacy link:\n%s", resp.body)
	}
}
