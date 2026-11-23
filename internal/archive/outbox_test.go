// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"encoding/json"
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
