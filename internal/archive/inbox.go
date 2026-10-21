// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package archive reads the SES-written email archive in S3: it lists the
// day partitions a search needs, reads each candidate's headers with a
// ranged GET, filters and scores, and renders a single message with its
// attachments. Every key it touches comes from a listing under the
// configured prefixes or from the caller, which must have checked the key
// against the archive boundary first.
package archive

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ElcanoTek/explorer/internal/config"
	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// listPageSize is the MaxKeys for a search listing; viewPageKeys for the
// paginated day view.
const (
	listPageSize = 1000
	viewPageKeys = 250
	// fetchWorkers bounds concurrent GETs per search.
	fetchWorkers = 12
)

// Inbox is the archive reader.
type Inbox struct {
	store Store
	s     config.Settings
}

// New returns an Inbox over store with the archive layout in s.
func New(store Store, s config.Settings) *Inbox {
	return &Inbox{store: store, s: s}
}

// Row is one result line.
type Row struct {
	S3Key        string
	Subject      string
	From         string
	To           string
	Date         string
	ReceivedAt   string // Python isoformat in UTC: 2026-01-02T03:04:05+00:00
	SizeBytes    int64
	FuzzyScore   int
	MatchedTerms int
}

// ExactQuery holds the case-insensitive substring filters of a targeted
// search; an empty field does not filter.
type ExactQuery struct {
	Sender, Recipient, Subject string
}

// FuzzyFields selects what a fuzzy search matches against.
type FuzzyFields struct {
	Subject, Sender, Body bool
}

// PendingObject is a listed object not yet shown on a view page.
type PendingObject struct {
	Key          string
	LastModified string
	SizeBytes    int64
}

// CursorState resumes a paginated day view.
type CursorState struct {
	PrefixIndex       int
	ContinuationToken string
	Pending           []PendingObject
}

type headers struct {
	Subject, From, To, Date string
}

// fetchHeaders reads the header block with a ranged GET of
// EMAIL_HEADER_FETCH_BYTES, so listing a day never downloads whole
// messages. A zero-byte object (S3 answers InvalidRange) is headerless.
func (in *Inbox) fetchHeaders(ctx context.Context, key string) (headers, error) {
	chunk, err := in.store.Get(ctx, key, int64(in.s.HeaderFetchBytes))
	if errors.Is(err, ErrInvalidRange) {
		return headers{}, nil
	}
	if err != nil {
		return headers{}, err
	}
	h := mailmsg.ParseHeaders(chunk)
	return headers{
		Subject: mailmsg.DecodeHeader(h.Get("Subject")),
		From:    mailmsg.DecodeHeader(h.Get("From")),
		To:      mailmsg.DecodeHeader(h.Get("To")),
		Date:    h.Get("Date"),
	}, nil
}

// parallel runs fn(i) for i in [0, n) on up to fetchWorkers goroutines and
// returns the first error (by index), or ctx's error once it is done.
func parallel(ctx context.Context, n int, fn func(i int) error) error {
	errs := make([]error, n)
	sem := make(chan struct{}, fetchWorkers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = fn(i)
		}(i)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// listObjects lists every object under the ranges' prefixes whose
// LastModified falls in one of the windows, deduplicated across prefixes.
// The window check keeps a message filed under an unexpected prefix out of
// the result.
func (in *Inbox) listObjects(ctx context.Context, ranges []DateRange) ([]Object, int, error) {
	if len(ranges) == 0 {
		return nil, 0, nil
	}
	windows, prefixes := in.windowsAndPrefixes(ranges)
	var rows []Object
	seen := map[string]bool{}
	for _, prefix := range prefixes {
		token := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			page, err := in.store.List(ctx, prefix, token, listPageSize)
			if err != nil {
				return nil, 0, err
			}
			for _, obj := range page.Objects {
				if obj.Key == prefix || seen[obj.Key] || !inWindows(obj.LastModified, windows) {
					continue
				}
				seen[obj.Key] = true
				rows = append(rows, obj)
			}
			if page.NextToken == "" {
				break
			}
			token = page.NextToken
		}
	}
	return rows, len(rows), nil
}

func rowFor(obj Object, h headers) Row {
	return Row{
		S3Key: obj.Key, Subject: h.Subject, From: h.From, To: h.To, Date: h.Date,
		ReceivedAt: isoformat(obj.LastModified), SizeBytes: obj.Size,
	}
}

func sortNewestFirst(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ReceivedAt > rows[j].ReceivedAt })
}

// ViewPage returns one page of the day view and the cursor for the next,
// nil on the last page.
func (in *Inbox) ViewPage(ctx context.Context, ranges []DateRange, pageSize int, cursor *CursorState) ([]Row, *CursorState, int, error) {
	windows, prefixes := in.windowsAndPrefixes(ranges)
	if len(prefixes) == 0 || pageSize <= 0 {
		return nil, nil, 0, nil
	}
	state := CursorState{}
	if cursor != nil {
		state = *cursor
		state.Pending = append([]PendingObject(nil), cursor.Pending...)
	}
	if state.PrefixIndex < 0 || (state.PrefixIndex >= len(prefixes) && len(state.Pending) == 0) {
		return nil, nil, 0, nil
	}
	var rows []Row
	scanned := 0
	for len(rows) < pageSize && (len(state.Pending) > 0 || state.PrefixIndex < len(prefixes)) {
		if len(state.Pending) == 0 {
			prefix := prefixes[state.PrefixIndex]
			page, err := in.store.List(ctx, prefix, state.ContinuationToken, viewPageKeys)
			if err != nil {
				return nil, nil, 0, err
			}
			state.ContinuationToken = page.NextToken
			for _, obj := range page.Objects {
				if obj.Key == prefix || !inWindows(obj.LastModified, windows) {
					continue
				}
				state.Pending = append(state.Pending, PendingObject{
					Key: obj.Key, LastModified: isoformat(obj.LastModified), SizeBytes: obj.Size,
				})
				scanned++
			}
			if state.ContinuationToken == "" {
				state.PrefixIndex++
			}
		}
		take := min(len(state.Pending), pageSize-len(rows))
		batch := state.Pending[:take]
		hs := make([]headers, take)
		if err := parallel(ctx, take, func(i int) error {
			h, err := in.fetchHeaders(ctx, batch[i].Key)
			hs[i] = h
			return err
		}); err != nil {
			return nil, nil, 0, err
		}
		for i, p := range batch {
			rows = append(rows, Row{
				S3Key: p.Key, Subject: hs[i].Subject, From: hs[i].From, To: hs[i].To,
				Date: hs[i].Date, ReceivedAt: p.LastModified, SizeBytes: p.SizeBytes,
			})
		}
		state.Pending = state.Pending[take:]
	}
	if state.PrefixIndex >= len(prefixes) && len(state.Pending) == 0 {
		return rows, nil, scanned, nil
	}
	return rows, &state, scanned, nil
}

// Search is the targeted search: objects in the windows whose From, To and
// Subject contain the given substrings (case-insensitive). It stops at limit
// matches in listing order, then sorts newest first.
func (in *Inbox) Search(ctx context.Context, ranges []DateRange, q ExactQuery, limit int) ([]Row, int, error) {
	sender, recipient, subject := strings.ToLower(q.Sender), strings.ToLower(q.Recipient), strings.ToLower(q.Subject)
	objects, scanned, err := in.listObjects(ctx, ranges)
	if err != nil {
		return nil, 0, err
	}
	var matches []Row
	for start := 0; start < len(objects); start += fetchWorkers {
		batch := objects[start:min(start+fetchWorkers, len(objects))]
		hs := make([]headers, len(batch))
		if err := parallel(ctx, len(batch), func(i int) error {
			h, err := in.fetchHeaders(ctx, batch[i].Key)
			hs[i] = h
			return err
		}); err != nil {
			return nil, 0, err
		}
		for i, obj := range batch {
			h := hs[i]
			if sender != "" && !strings.Contains(strings.ToLower(h.From), sender) ||
				recipient != "" && !strings.Contains(strings.ToLower(h.To), recipient) ||
				subject != "" && !strings.Contains(strings.ToLower(h.Subject), subject) {
				continue
			}
			matches = append(matches, rowFor(obj, h))
			if len(matches) >= limit {
				sortNewestFirst(matches)
				return matches, scanned, nil
			}
		}
	}
	sortNewestFirst(matches)
	return matches, scanned, nil
}

// extractBodies returns the first text/plain and first text/html bodies
// that are not attachments, decoded to text.
func extractBodies(msg *mailmsg.Part) (plain, html string) {
	for _, part := range msg.Walk() {
		if part.MainType() == "multipart" || strings.Contains(part.Header.Get("Content-Disposition"), "attachment") {
			continue
		}
		payload, ok := part.Payload()
		if !ok {
			continue
		}
		decoded := mailmsg.DecodeBytes(payload, part.Charset())
		switch part.ContentType() {
		case "text/plain":
			if plain == "" {
				plain = decoded
			}
		case "text/html":
			if html == "" {
				html = decoded
			}
		}
	}
	return plain, html
}

func (in *Inbox) readFull(ctx context.Context, key string) (*mailmsg.Part, error) {
	raw, err := in.store.Get(ctx, key, 0)
	if err != nil {
		return nil, err
	}
	return mailmsg.Parse(raw), nil
}

// SearchFuzzy scores loose keyword matches: 3 per term in the subject, 2 in
// the sender, 1 in the body, plus 1 for matching at all. Bodies are only
// downloaded when the headers alone cannot decide the match.
func (in *Inbox) SearchFuzzy(ctx context.Context, ranges []DateRange, keywords []string, fields FuzzyFields, matchAll bool, limit int) ([]Row, int, error) {
	var terms []string
	for _, k := range keywords {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			terms = append(terms, k)
		}
	}
	if len(terms) == 0 {
		return nil, 0, nil
	}
	objects, scanned, err := in.listObjects(ctx, ranges)
	if err != nil {
		return nil, 0, err
	}
	results := make([]*Row, len(objects))
	for start := 0; start < len(objects); start += fetchWorkers {
		end := min(start+fetchWorkers, len(objects))
		if err := parallel(ctx, end-start, func(i int) error {
			row, err := in.fuzzyScore(ctx, objects[start+i], terms, fields, matchAll)
			results[start+i] = row
			return err
		}); err != nil {
			return nil, 0, err
		}
	}
	var matches []Row
	for _, r := range results {
		if r != nil {
			matches = append(matches, *r)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].FuzzyScore != matches[j].FuzzyScore {
			return matches[i].FuzzyScore > matches[j].FuzzyScore
		}
		return matches[i].ReceivedAt > matches[j].ReceivedAt
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches, scanned, nil
}

func (in *Inbox) fuzzyScore(ctx context.Context, obj Object, terms []string, f FuzzyFields, matchAll bool) (*Row, error) {
	h, err := in.fetchHeaders(ctx, obj.Key)
	if err != nil {
		return nil, err
	}
	subject, sender := "", ""
	if f.Subject {
		subject = strings.ToLower(h.Subject)
	}
	if f.Sender {
		sender = strings.ToLower(h.From)
	}
	hits := make([]bool, len(terms))
	bodyHits := make([]bool, len(terms))
	for i, t := range terms {
		hits[i] = (f.Subject && strings.Contains(subject, t)) || (f.Sender && strings.Contains(sender, t))
	}
	if f.Body {
		need := !anyTrue(hits)
		if matchAll {
			need = !allTrue(hits)
		}
		if need {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			msg, err := in.readFull(ctx, obj.Key)
			if err != nil {
				return nil, err
			}
			plain, html := extractBodies(msg)
			body := plain
			if body == "" {
				body = html
			}
			body = strings.ToLower(body)
			for i, t := range terms {
				bodyHits[i] = strings.Contains(body, t)
				hits[i] = hits[i] || bodyHits[i]
			}
		}
	}
	score := 0
	for i, t := range terms {
		if f.Subject && strings.Contains(subject, t) {
			score += 3
		}
		if f.Sender && strings.Contains(sender, t) {
			score += 2
		}
		if f.Body && bodyHits[i] {
			score++
		}
	}
	matched := anyTrue(hits)
	if matchAll {
		matched = allTrue(hits)
	}
	if !matched {
		return nil, nil
	}
	row := rowFor(obj, h)
	row.FuzzyScore = score + 1
	for _, hit := range hits {
		if hit {
			row.MatchedTerms++
		}
	}
	return &row, nil
}

func anyTrue(v []bool) bool {
	for _, b := range v {
		if b {
			return true
		}
	}
	return false
}

func allTrue(v []bool) bool {
	for _, b := range v {
		if !b {
			return false
		}
	}
	return true
}

// Today is the host-local date as midnight UTC, the day the inbox opens on.
func Today() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}
