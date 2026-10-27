// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// The agent search API: what /mcp and /api/v1 run for Fleet's agents. It is
// the Go home of the bundles' Python search tools (search_emails,
// search_emails_fuzzy, find_latest_report) and keeps their contract, so the
// web UI's own searches (Search, SearchFuzzy, ViewPage) are untouched by it.
//
// Differences from the UI searches, all deliberate:
//
//   - Sender authentication (senderauth.go): by default only mail whose
//     From domain the receiver authenticated is returned, and sender filters
//     match the parsed From mailbox, never the display name. Skipped mail is
//     counted so the caller can say so instead of reporting "no report".
//   - Payload detection: has_payload asks for an attachment or a
//     download-likely body link (links.go), which needs the full message.
//   - A day partition is authoritative for the day it names: an object
//     listed under it is not filtered again by LastModified (a copy made
//     just after midnight still belongs to its partition's day).
//   - Operator-trusted legacy imports (EMAIL_TRUSTED_LEGACY_PREFIXES) count
//     as authenticated and are windowed by their partition day or Date
//     header, because their LastModified is the import time.
//   - Fail loudly: any S3 error fails the whole search. Only a message that
//     cannot be read as mail (an empty object, an oversize object) is
//     skipped, and counted in ParseErrors.

// AgentMatch is one search result.
type AgentMatch struct {
	S3Key               string
	Subject, From, To   string
	Date                string
	ReceivedAt          string
	SizeBytes           int64
	SenderAuthenticated bool
	TrustedLegacy       bool
	// Opened reports whether the full message was read (payload filter or
	// body preview): only then are Attachments and DownloadLinks known.
	Opened        bool
	Attachments   []string
	DownloadLinks []DownloadLink
	BodyPreview   string
	// Fuzzy only.
	MatchScore      float64
	MatchedKeywords []string

	sortAt time.Time
}

// AgentStats describe one search's scan.
type AgentStats struct {
	Scanned, HeaderFetches, FullFetches, ParseErrors int
	// UnauthenticatedSkipped matched every filter but its sender was not
	// authenticated; UnauthenticatedUnchecked matched the header filters
	// but was left unopened, so its payload was never checked.
	UnauthenticatedSkipped, UnauthenticatedUnchecked int
	Prefixes                                         int
	UsedPartitions                                   bool
}

// AgentQuery is a targeted search. From and To are inclusive instants
// (UTC); both are required.
type AgentQuery struct {
	SubjectContains    string
	SubjectKeywords    []string
	SenderContains     string
	RecipientContains  string
	From, To           time.Time
	HasPayload         *bool
	MaxResults         int
	IncludeBodyPreview bool
}

// AgentFuzzyQuery is a keyword search.
type AgentFuzzyQuery struct {
	Keywords              []string
	Subject, Sender, Body bool
	MatchAll              bool
	From, To              time.Time
	MaxResults            int
}

// bodyPreviewChars is the include_body_preview length.
const bodyPreviewChars = 500

// SenderAuthOff reports whether EMAIL_SENDER_AUTH=off.
func (in *Inbox) SenderAuthOff() bool { return in.s.SenderAuth == "off" }

type agentHeaders struct {
	subject, from, to, date string
	authenticated           bool
}

// readAgentHeaders reads the header block with a ranged GET. ok is false for
// an object that is not mail (empty: S3 answers InvalidRange); any other
// error is an S3 failure.
func (in *Inbox) readAgentHeaders(ctx context.Context, key string) (agentHeaders, bool, error) {
	chunk, err := in.store.Get(ctx, key, int64(in.s.HeaderFetchBytes))
	if errors.Is(err, ErrInvalidRange) {
		return agentHeaders{}, false, nil
	}
	if err != nil {
		return agentHeaders{}, false, err
	}
	return in.headersOf(mailmsg.ParseHeaders(chunk)), true, nil
}

func (in *Inbox) headersOf(h mailmsg.Header) agentHeaders {
	from := mailmsg.DecodeHeader(h.Get("From"))
	var results []string
	for _, f := range h {
		if strings.EqualFold(f.Name, "Authentication-Results") {
			results = append(results, f.Value)
		}
	}
	domain := AuthenticatedSenderDomain(results, from, in.s.AuthservID)
	return agentHeaders{
		subject:       mailmsg.DecodeHeader(h.Get("Subject")),
		from:          from,
		to:            mailmsg.DecodeHeader(h.Get("To")),
		date:          h.Get("Date"),
		authenticated: domain != "" && domain == addressDomain(from),
	}
}

type opened struct {
	h           agentHeaders
	attachments []string
	links       []DownloadLink
	plain, html string
	ok          bool
}

// openMessage reads and parses a whole message. ok is false for an object
// that cannot be read as mail; any other error is an S3 failure.
func (in *Inbox) openMessage(ctx context.Context, key string) (opened, error) {
	raw, err := in.store.Get(ctx, key, 0)
	if errors.Is(err, ErrTooLarge) {
		return opened{}, nil
	}
	if err != nil {
		return opened{}, err
	}
	msg := mailmsg.Parse(raw)
	out := opened{h: in.headersOf(msg.Header), ok: true}
	for _, part := range msg.Walk() {
		if part.MainType() == "multipart" {
			continue
		}
		disposition := part.Header.Get("Content-Disposition")
		name := part.Filename()
		if strings.Contains(strings.ToLower(disposition), "attachment") || name != "" {
			if name = cleanReportedFilename(mailmsg.DecodeHeader(name)); name != "" {
				out.attachments = append(out.attachments, name)
			}
		}
	}
	out.plain, out.html = extractBodies(msg)
	out.links = downloadLinks(out.plain, out.html)
	return out, nil
}

// cleanReportedFilename collapses folded whitespace, so a name copied back
// into a download tool matches the part.
func cleanReportedFilename(name string) string {
	return strings.Trim(strings.Join(strings.Fields(name), " "), " .")
}

// isLegacyKey reports whether key lies under an operator-trusted legacy
// prefix.
func (in *Inbox) isLegacyKey(key string) bool {
	for _, p := range in.s.TrustedLegacyPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// inDateTree approximates "prefix starts with a date partition": it extends
// the date format's literal head with a digit (every shipped format starts
// its date part with %Y).
func (in *Inbox) inDateTree(prefix string) bool {
	root := strings.SplitN(in.s.DatePrefixFormat, "%", 2)[0]
	if in.s.DatePrefixFormat == "" || !strings.HasPrefix(prefix, root) || len(prefix) <= len(root) {
		return false
	}
	c := prefix[len(root)]
	return c >= '0' && c <= '9'
}

// scanPrefix is one prefix to list: a day partition (day set), a trusted
// legacy prefix outside the date tree, or the root prefix.
type scanPrefix struct {
	prefix string
	day    time.Time
	legacy bool
}

func (in *Inbox) agentPrefixes(from, to time.Time) ([]scanPrefix, bool) {
	start, end := Day(from), Day(to)
	prefixes := BuildSearchPrefixes(in.s.Prefix, in.s.DatePrefixFormat, in.s.MaxDatePrefixDays, start, end)
	if len(prefixes) == 1 && prefixes[0] == in.s.Prefix {
		return []scanPrefix{{prefix: in.s.Prefix}}, false
	}
	out := make([]scanPrefix, 0, len(prefixes)+len(in.s.TrustedLegacyPrefixes))
	for i, p := range prefixes {
		out = append(out, scanPrefix{prefix: p, day: end.AddDate(0, 0, -i)})
	}
	for _, legacy := range in.s.TrustedLegacyPrefixes {
		inside := in.inDateTree(legacy)
		for _, p := range prefixes {
			if strings.HasPrefix(legacy, p) {
				inside = true
			}
		}
		if !inside {
			out = append(out, scanPrefix{prefix: legacy, legacy: true})
		}
	}
	return out, true
}

func sentAt(date string) (time.Time, bool) {
	t, err := mail.ParseDate(strings.TrimSpace(date))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// legacyPlacement windows a trusted legacy object and gives its sort time.
// Inside a day partition, a Date header on that day gives the sub-day
// position and anything else falls back to the day; outside the date tree
// only the Date header can place it, and an unreadable one drops it.
func legacyPlacement(sp scanPrefix, date string, from, to time.Time) (time.Time, bool) {
	sent, ok := sentAt(date)
	if !sp.day.IsZero() {
		dayEnd := sp.day.Add(24*time.Hour - time.Microsecond)
		if ok && !sent.Before(sp.day) && !sent.After(dayEnd) {
			return sent, !sent.Before(from) && !sent.After(to)
		}
		return sp.day, !dayEnd.Before(from) && !sp.day.After(to)
	}
	if !ok {
		return time.Time{}, false
	}
	return sent, !sent.Before(from) && !sent.After(to)
}

// candidate is one listed object with where it came from.
type candidate struct {
	obj Object
	sp  scanPrefix
}

// eachPage lists the prefixes and hands each page's in-window objects to fn
// (deduplicated, link-archive objects dropped). fn returns stop=true once
// the limit is reached: with day partitions the current partition is still
// finished by the caller (keys are not in time order) and only later
// partitions are skipped, except trusted legacy prefixes, which are always
// scanned; without partitions listing stops at once.
func (in *Inbox) eachPage(ctx context.Context, from, to time.Time, stats *AgentStats,
	fn func([]candidate) (stop bool, err error),
) error {
	prefixes, partitioned := in.agentPrefixes(from, to)
	stats.Prefixes, stats.UsedPartitions = len(prefixes), partitioned
	seen := map[string]bool{}
	stopped := false
	for _, sp := range prefixes {
		if stopped && !sp.legacy {
			continue
		}
		token := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := in.store.List(ctx, sp.prefix, token, listPageSize)
			if err != nil {
				return err
			}
			var batch []candidate
			for _, obj := range page.Objects {
				if obj.Key == sp.prefix || seen[obj.Key] {
					continue
				}
				seen[obj.Key] = true
				if in.s.ArchivePrefix != "" && strings.HasPrefix(obj.Key, in.s.ArchivePrefix) {
					continue
				}
				if !partitioned && !in.isLegacyKey(obj.Key) {
					if lm := obj.LastModified.UTC(); lm.Before(from) || lm.After(to) {
						continue
					}
				}
				batch = append(batch, candidate{obj, sp})
			}
			if len(batch) > 0 {
				stop, err := fn(batch)
				if err != nil {
					return err
				}
				if stop {
					stopped = true
					if !partitioned {
						return nil
					}
				}
			}
			if page.NextToken == "" {
				break
			}
			token = page.NextToken
		}
	}
	return nil
}

// headerBatch reads the headers of every candidate concurrently.
func (in *Inbox) headerBatch(ctx context.Context, batch []candidate, stats *AgentStats) ([]agentHeaders, []bool, error) {
	hs := make([]agentHeaders, len(batch))
	oks := make([]bool, len(batch))
	err := parallel(ctx, len(batch), func(i int) error {
		h, ok, err := in.readAgentHeaders(ctx, batch[i].obj.Key)
		hs[i], oks[i] = h, ok
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	for _, ok := range oks {
		stats.Scanned++
		if ok {
			stats.HeaderFetches++
		} else {
			stats.ParseErrors++
		}
	}
	return hs, oks, nil
}

// openBatch reads the full messages at idx concurrently.
func (in *Inbox) openBatch(ctx context.Context, batch []candidate, idx []int, stats *AgentStats) (map[int]opened, error) {
	out := make([]opened, len(idx))
	err := parallel(ctx, len(idx), func(i int) error {
		o, err := in.openMessage(ctx, batch[idx[i]].obj.Key)
		out[i] = o
		return err
	})
	if err != nil {
		return nil, err
	}
	m := make(map[int]opened, len(idx))
	for i, j := range idx {
		if out[i].ok {
			stats.FullFetches++
		} else {
			stats.ParseErrors++
		}
		m[j] = out[i]
	}
	return m, nil
}

// placement windows a candidate and gives its sort time; non-legacy
// objects are already windowed by their listing.
func (in *Inbox) placement(c candidate, date string, from, to time.Time) (time.Time, bool) {
	if in.isLegacyKey(c.obj.Key) {
		return legacyPlacement(c.sp, date, from, to)
	}
	return c.obj.LastModified.UTC(), true
}

func matchFor(c candidate, h agentHeaders, legacy bool, sortAt time.Time) AgentMatch {
	return AgentMatch{
		S3Key: c.obj.Key, Subject: h.subject, From: h.from, To: h.to, Date: h.date,
		ReceivedAt: isoformat(c.obj.LastModified), SizeBytes: c.obj.Size,
		SenderAuthenticated: h.authenticated, TrustedLegacy: legacy, sortAt: sortAt,
	}
}

func trimToLimit(matches []AgentMatch, limit int, less func(a, b AgentMatch) bool) []AgentMatch {
	sort.SliceStable(matches, func(i, j int) bool { return less(matches[i], matches[j]) })
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

func newestFirst(a, b AgentMatch) bool { return a.sortAt.After(b.sortAt) }

// AgentSearch is the targeted search (search_emails).
func (in *Inbox) AgentSearch(ctx context.Context, q AgentQuery) ([]AgentMatch, AgentStats, error) {
	var stats AgentStats
	subject := strings.ToLower(q.SubjectContains)
	recipient := strings.ToLower(q.RecipientContains)
	sender := strings.ToLower(q.SenderContains)
	var keywords []string
	for _, k := range q.SubjectKeywords {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			keywords = append(keywords, k)
		}
	}
	authOff := in.SenderAuthOff()
	needFull := q.HasPayload != nil || q.IncludeBodyPreview
	var matches []AgentMatch
	err := in.eachPage(ctx, q.From, q.To, &stats, func(batch []candidate) (bool, error) {
		hs, oks, err := in.headerBatch(ctx, batch, &stats)
		if err != nil {
			return false, err
		}
		type pick struct {
			i      int
			sortAt time.Time
			legacy bool
		}
		var picks []pick
		for i, c := range batch {
			if !oks[i] {
				continue
			}
			h := hs[i]
			sortAt, inWindow := in.placement(c, h.date, q.From, q.To)
			if !inWindow {
				continue
			}
			lowerSubject := strings.ToLower(h.subject)
			if subject != "" && !strings.Contains(lowerSubject, subject) {
				continue
			}
			if len(keywords) > 0 && !containsAny(lowerSubject, keywords) {
				continue
			}
			if sender != "" && !senderFilterMatches(sender, h.from, authOff) {
				continue
			}
			if recipient != "" && !strings.Contains(strings.ToLower(h.to), recipient) {
				continue
			}
			legacy := in.isLegacyKey(c.obj.Key)
			if !authOff && !h.authenticated && !legacy {
				// Never open an untrusted message. It is counted as skipped
				// only when the header filters alone decide the match; with a
				// payload filter whether it would match is unknown.
				if q.HasPayload == nil {
					stats.UnauthenticatedSkipped++
				} else {
					stats.UnauthenticatedUnchecked++
				}
				continue
			}
			picks = append(picks, pick{i, sortAt, legacy})
		}
		var full map[int]opened
		if needFull && len(picks) > 0 {
			idx := make([]int, len(picks))
			for k, p := range picks {
				idx[k] = p.i
			}
			if full, err = in.openBatch(ctx, batch, idx, &stats); err != nil {
				return false, err
			}
		}
		for _, p := range picks {
			m := matchFor(batch[p.i], hs[p.i], p.legacy, p.sortAt)
			if needFull {
				o := full[p.i]
				if !o.ok {
					continue
				}
				m.Opened, m.Attachments, m.DownloadLinks = true, o.attachments, o.links
				payload := len(o.attachments)+len(o.links) > 0
				if q.HasPayload != nil && payload != *q.HasPayload {
					continue
				}
				if q.IncludeBodyPreview {
					body := o.plain
					if body == "" {
						body = o.html
					}
					m.BodyPreview = truncateRunes(body, bodyPreviewChars)
				}
			}
			matches = append(matches, m)
		}
		reached := len(matches) >= q.MaxResults
		matches = trimToLimit(matches, q.MaxResults, newestFirst) // bound memory within a busy partition
		return reached, nil
	})
	if err != nil {
		return nil, stats, err
	}
	return trimToLimit(matches, q.MaxResults, newestFirst), stats, nil
}

func containsAny(text string, terms []string) bool {
	for _, t := range terms {
		if strings.Contains(text, t) {
			return true
		}
	}
	return false
}

// AgentFuzzy is the keyword search (search_emails_fuzzy). Keywords match
// case-insensitively in the chosen fields. While the sender is searched with
// authentication on, a domain- or address-shaped keyword is a sender
// constraint only (matched against the From mailbox), and a plain word never
// matches a sender. An untrusted message's body is never read.
func (in *Inbox) AgentFuzzy(ctx context.Context, q AgentFuzzyQuery) ([]AgentMatch, AgentStats, error) {
	var stats AgentStats
	var keywords []fuzzyKeyword
	for _, k := range q.Keywords {
		if t := strings.TrimSpace(k); t != "" {
			keywords = append(keywords, fuzzyKeyword{k, strings.ToLower(k)})
		}
	}
	authOff := in.SenderAuthOff()
	var matches []AgentMatch
	err := in.eachPage(ctx, q.From, q.To, &stats, func(batch []candidate) (bool, error) {
		hs, oks, err := in.headerBatch(ctx, batch, &stats)
		if err != nil {
			return false, err
		}
		// A body search opens trusted messages (and, with auth off, all).
		var idx []int
		if q.Body {
			for i, c := range batch {
				if oks[i] && (authOff || hs[i].authenticated || in.isLegacyKey(c.obj.Key)) {
					idx = append(idx, i)
				}
			}
		}
		full := map[int]opened{}
		if len(idx) > 0 {
			if full, err = in.openBatch(ctx, batch, idx, &stats); err != nil {
				return false, err
			}
		}
		for i, c := range batch {
			if !oks[i] {
				continue
			}
			h, body, attachments, openedMsg := hs[i], "", []string(nil), false
			if o, ok := full[i]; ok {
				if !o.ok {
					continue
				}
				body, attachments, openedMsg = o.plain, o.attachments, true
			}
			sortAt, inWindow := in.placement(c, h.date, q.From, q.To)
			if !inWindow {
				continue
			}
			legacy := in.isLegacyKey(c.obj.Key)
			trusted := authOff || h.authenticated || legacy
			var parts []string
			if q.Subject {
				parts = append(parts, h.subject)
			}
			if q.Body {
				parts = append(parts, body)
			}
			hits := fuzzyHits(keywords, strings.ToLower(strings.Join(parts, " ")), h.from, q.Sender, authOff)
			if (q.MatchAll && len(hits) != len(keywords)) || len(hits) == 0 {
				continue
			}
			if !trusted {
				stats.UnauthenticatedSkipped++
				continue
			}
			m := matchFor(c, h, legacy, sortAt)
			m.Opened, m.Attachments = openedMsg, attachments
			m.MatchScore = float64(len(hits)) / float64(len(keywords))
			m.MatchedKeywords = hits
			matches = append(matches, m)
		}
		reached := len(matches) >= q.MaxResults
		matches = trimToLimit(matches, q.MaxResults, bestFirst)
		return reached, nil
	})
	if err != nil {
		return nil, stats, err
	}
	return trimToLimit(matches, q.MaxResults, bestFirst), stats, nil
}

type fuzzyKeyword struct{ original, lower string }

// fuzzyHits returns the keywords (as given) that match searchable (the
// lower-cased subject and/or body) or the sender. While the sender is
// searched with authentication on, a domain- or address-shaped keyword is a
// sender constraint only (vendor.example in a subject on mail from
// attacker@evil.example must not select it), and a plain word never matches
// a sender (MailboxMatches would read "media" as a domain suffix). With
// authentication off a keyword matches anywhere in the whole From header.
func fuzzyHits(keywords []fuzzyKeyword, searchable, from string, searchSender, authOff bool) []string {
	mailbox, header := "", ""
	if searchSender {
		mailbox, header = strings.ToLower(parseMailbox(from)), strings.ToLower(from)
	}
	senderHit := func(k string) bool {
		if authOff {
			return header != "" && strings.Contains(header, k)
		}
		return mailbox != "" && MailboxMatches(strings.TrimLeft(strings.TrimSpace(k), "@"), mailbox)
	}
	var hits []string
	for _, k := range keywords {
		var hit bool
		if searchSender && !authOff {
			if SenderShaped(k.lower) {
				hit = senderHit(k.lower)
			} else {
				hit = strings.Contains(searchable, k.lower)
			}
		} else {
			hit = senderHit(k.lower) || strings.Contains(searchable, k.lower)
		}
		if hit {
			hits = append(hits, k.original)
		}
	}
	return hits
}

func bestFirst(a, b AgentMatch) bool {
	if a.MatchScore != b.MatchScore {
		return a.MatchScore > b.MatchScore
	}
	return a.sortAt.After(b.sortAt)
}
