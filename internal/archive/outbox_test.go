// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func outboxRecord(t *testing.T, key string, rec SentRecord) []byte {
	t.Helper()
	if rec.EmlKey == "" {
		rec.EmlKey = key[:len(key)-len(".json")] + ".eml"
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func outboxFixture(t *testing.T) *fakeStore {
	t.Helper()
	const d = "outbox/2026/06/01/"
	return newFake(map[string][]byte{
		d + "a.eml": []byte("From: v@x\r\nSubject: Weekly\r\n\r\nhi"),
		d + "a.json": outboxRecord(t, d+"a.json", SentRecord{SentAt: "2026-06-01T09:00:00Z", Subject: "Weekly report",
			To: []string{"alice@client.example"}, Bcc: []string{"audit@northwind.example"}, SentBy: "dana@northwind.example"}),
		d + "b.eml": []byte("From: v@x\r\n\r\nhi"),
		d + "b.json": outboxRecord(t, d+"b.json", SentRecord{SentAt: "2026-06-01T15:00:00Z", Subject: "Deal sheet",
			To: []string{"bob@client.example"}, TaskID: "task-42"}),
		// A record pointing at another key is never trusted.
		d + "c.json": outboxRecord(t, d+"c.json", SentRecord{SentAt: "2026-06-01T16:00:00Z", Subject: "Elsewhere",
			EmlKey: "emails/2026/06/01/secret"}),
		d + "d.json": []byte("{not json"),
		d + "e.json": {},
	})
}

func TestOutboxSearchReadsRecordsNewestFirst(t *testing.T) {
	o := NewOutbox(outboxFixture(t), settings())
	got, stats, err := o.Search(context.Background(), day, day.Add(24*time.Hour-time.Nanosecond), OutboxQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Subject != "Deal sheet" || got[1].Subject != "Weekly report" {
		t.Fatalf("got %+v", got)
	}
	if got[1].EmlKey != "outbox/2026/06/01/a.eml" {
		t.Fatalf("eml key %q", got[1].EmlKey)
	}
	if stats.Scanned != 2 || stats.Unreadable != 3 || stats.Truncated {
		t.Fatalf("stats %+v", stats)
	}
}

func TestOutboxSearchFilters(t *testing.T) {
	o := NewOutbox(outboxFixture(t), settings())
	for name, tc := range map[string]struct {
		q    OutboxQuery
		want string
	}{
		"recipient in to":  {OutboxQuery{Recipient: "BOB@"}, "Deal sheet"},
		"recipient in bcc": {OutboxQuery{Recipient: "audit@"}, "Weekly report"},
		"subject":          {OutboxQuery{Subject: "weekly"}, "Weekly report"},
		"sent by":          {OutboxQuery{SentBy: "dana"}, "Weekly report"},
	} {
		got, _, err := o.Search(context.Background(), day, day.Add(24*time.Hour-time.Nanosecond), tc.q)
		if err != nil || len(got) != 1 || got[0].Subject != tc.want {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	got, stats, _ := o.Search(context.Background(), day, day.Add(24*time.Hour-time.Nanosecond), OutboxQuery{Limit: 1})
	if len(got) != 1 || !stats.Truncated {
		t.Fatalf("limit: %+v %+v", got, stats)
	}
}

func TestOutboxSearchKeepsToItsDays(t *testing.T) {
	o := NewOutbox(outboxFixture(t), settings())
	next := day.AddDate(0, 0, 1)
	got, _, err := o.Search(context.Background(), next, next.Add(24*time.Hour-time.Nanosecond), OutboxQuery{})
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestOutboxIsOffWithoutAPrefix(t *testing.T) {
	s := settings()
	s.OutboxPrefix = ""
	if NewOutbox(newFake(nil), s) != nil {
		t.Fatal("an empty prefix must turn the Outbox off")
	}
}

func TestInboxSearchNeverListsTheOutbox(t *testing.T) {
	store := outboxFixture(t)
	store.objects["emails/2026/06/01/in1"] = fakeObj{data: []byte("From: a@b\r\nSubject: In\r\n\r\nx"), modified: received}
	in := New(store, settings())
	// A window wider than the per-day limit lists the whole inbox prefix.
	wide := []DateRange{{Start: day.AddDate(0, -6, 0), End: day}}
	rows, _, err := in.Search(context.Background(), wide, ExactQuery{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.S3Key != "emails/2026/06/01/in1" {
			t.Fatalf("inbox listed %q", r.S3Key)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
}

func TestOutboxSearchUsesSentAtNotUploadTime(t *testing.T) {
	store := outboxFixture(t)
	// Sent at 23:59:59 on June 1 and saved just after midnight: still June 1.
	const k = "outbox/2026/06/01/late.json"
	store.objects[k] = fakeObj{modified: day.AddDate(0, 0, 1).Add(time.Second), data: outboxRecord(t, k,
		SentRecord{SentAt: "2026-06-01T23:59:59Z", Subject: "Late"})}
	o := NewOutbox(store, settings())
	got, _, err := o.Search(context.Background(), day, day.Add(24*time.Hour-time.Nanosecond), OutboxQuery{Subject: "late"})
	if err != nil || len(got) != 1 {
		t.Fatalf("late send lost: %+v %v", got, err)
	}
	// Exact bounds: only what was sent between 12:00 and 16:00.
	got, _, _ = o.Search(context.Background(), day.Add(12*time.Hour), day.Add(16*time.Hour), OutboxQuery{})
	if len(got) != 1 || got[0].Subject != "Deal sheet" {
		t.Fatalf("bounds: %+v", got)
	}
}

func fuzzyOutbox(t *testing.T, q OutboxFuzzy) ([]string, *fakeStore) {
	t.Helper()
	store := outboxFixture(t)
	got, _, err := NewOutbox(store, settings()).SearchFuzzy(context.Background(), day,
		day.Add(24*time.Hour-time.Nanosecond), q)
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([]string, 0, len(got))
	for _, r := range got {
		subjects = append(subjects, r.Subject)
	}
	return subjects, store
}

func TestOutboxFuzzyScoresLikeTheInbox(t *testing.T) {
	both := OutboxFuzzy{Subject: true, Recipients: true}
	for name, tc := range map[string]struct {
		keywords []string
		matchAll bool
		want     string
	}{
		"subject":          {[]string{"WEEKLY"}, false, "Weekly report"},
		"recipient in to":  {[]string{"bob@"}, false, "Deal sheet"},
		"recipient in bcc": {[]string{"audit"}, false, "Weekly report"},
		// A subject hit (3) outranks a recipient hit (2), though Deal sheet
		// was sent later.
		"best first":    {[]string{"weekly", " bob ", ""}, false, "Weekly report,Deal sheet"},
		"match all":     {[]string{"weekly", "alice"}, true, "Weekly report"},
		"match all off": {[]string{"weekly", "nothing"}, true, ""},
		"no keywords":   {[]string{" ", ""}, false, ""},
	} {
		q := both
		q.Keywords, q.MatchAll = tc.keywords, tc.matchAll
		got, _ := fuzzyOutbox(t, q)
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
	if got, _ := fuzzyOutbox(t, OutboxFuzzy{Keywords: []string{"weekly"}, Recipients: true}); len(got) != 0 {
		t.Fatalf("matched a field that is off: %q", got)
	}
	if got, _ := fuzzyOutbox(t, OutboxFuzzy{Keywords: []string{"weekly", "deal"}, Subject: true, Limit: 1}); len(got) != 1 {
		t.Fatalf("limit: %q", got)
	}
}

func TestOutboxFuzzyReadsABodyOnlyWhenTheRecordCannotDecide(t *testing.T) {
	// The Weekly report's subject decides it; only the Deal sheet is read.
	got, store := fuzzyOutbox(t, OutboxFuzzy{Keywords: []string{"weekly"}, Subject: true, Body: true})
	if strings.Join(got, ",") != "Weekly report" || store.fullGets != 1 {
		t.Fatalf("got %q after %d message reads", got, store.fullGets)
	}
	// "hi" is only in the bodies: both messages are read and match.
	got, store = fuzzyOutbox(t, OutboxFuzzy{Keywords: []string{"HI"}, Body: true})
	if len(got) != 2 || store.fullGets != 2 {
		t.Fatalf("got %q after %d message reads", got, store.fullGets)
	}
	if got, _ := fuzzyOutbox(t, OutboxFuzzy{Keywords: []string{"hi"}, Subject: true}); len(got) != 0 {
		t.Fatalf("searched a body that is off: %q", got)
	}
}

func TestOutboxFuzzySkipsAMissingMessage(t *testing.T) {
	store := outboxFixture(t)
	delete(store.objects, "outbox/2026/06/01/a.eml")
	got, _, err := NewOutbox(store, settings()).SearchFuzzy(context.Background(), day,
		day.Add(24*time.Hour-time.Nanosecond), OutboxFuzzy{Keywords: []string{"hi"}, Body: true})
	if err != nil || len(got) != 1 || got[0].Subject != "Deal sheet" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestOutboxFuzzyBodyIsTheMessagesOwnText(t *testing.T) {
	store := outboxFixture(t)
	// An HTML report that attaches an email: the report's HTML is searched,
	// the attached email's text is not.
	store.objects["outbox/2026/06/01/a.eml"] = fakeObj{modified: received, data: []byte("From: v@x\r\n" +
		"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" +
		"--XX\r\nContent-Type: text/html\r\n\r\n<p>Spend pacing summary</p>\r\n" +
		"--XX\r\nContent-Type: message/rfc822\r\n\r\nFrom: a@b\r\nContent-Type: text/plain\r\n\r\nforwarded secret\r\n" +
		"--XX--\r\n")}
	o := NewOutbox(store, settings())
	search := func(keyword string) []SentRecord {
		got, _, err := o.SearchFuzzy(context.Background(), day, day.Add(24*time.Hour-time.Nanosecond),
			OutboxFuzzy{Keywords: []string{keyword}, Body: true})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := search("pacing"); len(got) != 1 || got[0].Subject != "Weekly report" {
		t.Fatalf("the report's HTML was not searched: %+v", got)
	}
	if got := search("forwarded"); len(got) != 0 {
		t.Fatalf("an attached email's text matched: %+v", got)
	}
}
