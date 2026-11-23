// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/config"
)

// The client Outbox: a copy of every email Fleet's sender sent, under
// EMAIL_S3_OUTBOX_PREFIX as <prefix>YYYY/MM/DD/<id>.eml with a <id>.json
// record beside it (example-config mcp/outbox.py writes both). Search reads
// only the small records, never the messages; a message is opened by its
// .eml key like any inbox email.
//
// There is no sender-authentication check here: only the sender's IAM user
// can write under the prefix, so the prefix is the proof of origin.

// maxRecordBytes caps one record read; a record is a few hundred bytes.
const maxRecordBytes = 64 * 1024

// SentAttachment is one attachment the record lists.
type SentAttachment struct {
	Name     string `json:"name"`
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size"`
	Inline   bool   `json:"inline"`
}

// SentRecord is one Outbox .json record, as the sender wrote it.
type SentRecord struct {
	Schema      int              `json:"schema"`
	MessageID   string           `json:"message_id"`
	SentAt      string           `json:"sent_at"`
	From        string           `json:"from"`
	To          []string         `json:"to"`
	Cc          []string         `json:"cc"`
	Bcc         []string         `json:"bcc"`
	ReplyTo     string           `json:"reply_to"`
	Subject     string           `json:"subject"`
	ContentType string           `json:"content_type"`
	Attachments []SentAttachment `json:"attachments"`
	SentBy      string           `json:"sent_by"`
	TaskID      string           `json:"task_id"`
	Tenant      string           `json:"tenant"`
	EmlKey      string           `json:"eml_key"`
	EmlSize     int64            `json:"eml_size"`
}

// Recipients is every address the email went to: to, cc and bcc.
func (r SentRecord) Recipients() []string {
	return append(append(append([]string{}, r.To...), r.Cc...), r.Bcc...)
}

// OutboxQuery holds the case-insensitive substring filters of an Outbox
// search; an empty field does not filter.
type OutboxQuery struct {
	Recipient, Subject, SentBy string
	Limit                      int
}

// OutboxStats says what a search skipped.
type OutboxStats struct {
	Scanned int // records read
	// Unreadable counts records that were missing, too large or not JSON,
	// and records whose message key is outside the Outbox.
	Unreadable int
	Truncated  bool // more matches than Limit
}

// Outbox is the Outbox reader.
type Outbox struct {
	store Store
	s     config.Settings
}

// NewOutbox returns the Outbox reader, or nil when EMAIL_S3_OUTBOX_PREFIX is
// empty (the Outbox is off).
func NewOutbox(store Store, s config.Settings) *Outbox {
	if s.OutboxPrefix == "" {
		return nil
	}
	return &Outbox{store: store, s: s}
}

// Prefix is the Outbox's key prefix.
func (o *Outbox) Prefix() string { return o.s.OutboxPrefix }

// Search returns the records of email sent from from to to (inclusive
// instants) that match q, newest first, at most q.Limit (0 means no limit).
// It lists the day folders the span touches and keeps a record by its own
// sent_at, never the object's upload time: a copy saved just after midnight
// is still filed under, and found on, the day it was sent.
func (o *Outbox) Search(ctx context.Context, from, to time.Time, q OutboxQuery) ([]SentRecord, OutboxStats, error) {
	var stats OutboxStats
	if to.Before(from) {
		from, to = to, from
	}
	keys, err := o.recordKeys(ctx, []DateRange{{Start: from, End: to}})
	if err != nil {
		return nil, stats, err
	}
	records := make([]*SentRecord, len(keys))
	err = parallel(ctx, len(keys), func(i int) error {
		rec, err := o.readRecord(ctx, keys[i])
		if err != nil {
			if errors.Is(err, ErrNoSuchKey) || errors.Is(err, ErrInvalidRange) || errors.Is(err, errBadRecord) {
				return nil
			}
			return err
		}
		records[i] = rec
		return nil
	})
	if err != nil {
		return nil, stats, err
	}
	type hit struct {
		rec SentRecord
		at  time.Time
	}
	var hits []hit
	for _, rec := range records {
		if rec == nil {
			stats.Unreadable++
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rec.SentAt)
		if err != nil {
			stats.Unreadable++
			continue
		}
		stats.Scanned++
		if !at.Before(from) && !at.After(to) && q.matches(*rec) {
			hits = append(hits, hit{*rec, at})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at.After(hits[j].at) })
	out := make([]SentRecord, len(hits))
	for i, h := range hits {
		out[i] = h.rec
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out, stats.Truncated = out[:q.Limit], true
	}
	return out, stats, nil
}

func (q OutboxQuery) matches(r SentRecord) bool {
	has := func(field, want string) bool {
		return want == "" || strings.Contains(strings.ToLower(field), strings.ToLower(want))
	}
	return has(r.Subject, q.Subject) && has(r.SentBy, q.SentBy) &&
		has(strings.Join(r.Recipients(), " "), q.Recipient)
}

// recordKeys lists the .json records under the day folders ranges touch.
func (o *Outbox) recordKeys(ctx context.Context, ranges []DateRange) ([]string, error) {
	_, prefixes := windowsAndPrefixes(o.s.OutboxPrefix, o.s.OutboxPrefix+"%Y/%m/%d/", o.s.MaxDatePrefixDays, ranges)
	var keys []string
	listed := map[string]bool{}
	for _, prefix := range prefixes {
		token := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			page, err := o.store.List(ctx, prefix, token, listPageSize)
			if err != nil {
				return nil, err
			}
			for _, obj := range page.Objects {
				if !strings.HasSuffix(obj.Key, ".json") || listed[obj.Key] {
					continue
				}
				listed[obj.Key] = true
				keys = append(keys, obj.Key)
			}
			if page.NextToken == "" {
				break
			}
			token = page.NextToken
		}
	}
	return keys, nil
}

var errBadRecord = errors.New("archive: unreadable outbox record")

// readRecord reads one record. Its eml_key is trusted only when it is the
// .eml beside the record, so a record can never point a reader elsewhere.
func (o *Outbox) readRecord(ctx context.Context, key string) (*SentRecord, error) {
	raw, err := o.store.Get(ctx, key, maxRecordBytes+1)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRecordBytes {
		return nil, errBadRecord
	}
	var rec SentRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, errBadRecord
	}
	if want := strings.TrimSuffix(key, ".json") + ".eml"; rec.EmlKey != want {
		return nil, errBadRecord
	}
	return &rec, nil
}
