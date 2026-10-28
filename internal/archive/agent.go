// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"errors"
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
//     listed under a day the window covers in full is not filtered again by
//     LastModified (a copy made just after midnight still belongs to its
//     partition's day). A window that cuts a day short is checked against
//     LastModified on that day.
//   - Fail loudly: any S3 error fails the whole search. Only a message that
//     cannot be read as mail (an empty object, an oversize object) is
//     skipped, and counted in ParseErrors.
//   - Bounded memory: candidates are read fetchWorkers at a time, a whole
//     message is reduced to its small result (names, links, a preview) as
//     soon as it is read, and the kept matches never exceed the limit.

// AgentMatch is one search result.
type AgentMatch struct {
	S3Key               string
	Subject, From, To   string
	Date                string
	ReceivedAt          string
	SizeBytes           int64
	SenderAuthenticated bool
	// Opened reports whether the full message was read (payload filter,
	// body preview or a body search): only then are Attachments and
	// DownloadLinks known.
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
	// authenticated; UnauthenticatedUnchecked matched what could be checked
	// without opening it (its payload or body was never read).
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

// digest is what a search keeps of a whole message: never the message.
type digest struct {
	attachments []string
	links       []DownloadLink
	preview     string
	body        string // lower-cased, only for a body search
	ok          bool
}

// digestMessage reads one whole message and reduces it to a digest. ok is
// false for an object that cannot be read as mail; any other error is an S3
// failure.
func (in *Inbox) digestMessage(ctx context.Context, key string, keepBody bool) (digest, error) {
	raw, err := in.store.Get(ctx, key, 0)
	if errors.Is(err, ErrTooLarge) {
		return digest{}, nil
	}
	if err != nil {
		return digest{}, err
	}
	msg := mailmsg.Parse(raw)
	d := digest{ok: true}
	for _, a := range attachmentParts(msg) {
		if !a.inline {
			d.attachments = append(d.attachments, a.Filename)
		}
	}
	plain, html := allBodies(msg)
	d.links = downloadLinks(plain, html)
	text := plain
	if text == "" {
		text = html
	}
	d.preview = truncateRunes(text, bodyPreviewChars)
	if keepBody {
		// Both alternatives: a keyword may be only in the HTML part.
		d.body = strings.ToLower(plain + "\n" + html)
	}
	return d, nil
}

// cleanReportedFilename collapses folded whitespace, so a name copied back
// into a download tool matches the part.
func cleanReportedFilename(name string) string {
	return strings.Trim(strings.Join(strings.Fields(name), " "), " .")
}

// reportedAttachment finds the part attachmentParts reported as name, so
// every name search and get_email hand out (collapsed whitespace,
// "unknown") resolves for get_download_link.
func reportedAttachment(msg *mailmsg.Part, name string) (*mailmsg.Part, bool) {
	seen := map[string]bool{}
	for _, part := range msg.Walk() {
		n, ok := reportedName(part)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		if n == name {
			return part, true
		}
	}
	return nil, false
}

// isInlineResource reports a body resource (a logo or tracking image
// referenced by Content-ID) rather than a delivered file: get_email lists
// it, but it never makes an email a payload match.
func isInlineResource(part *mailmsg.Part) bool {
	disposition := strings.ToLower(part.Header.Get("Content-Disposition"))
	return !strings.Contains(disposition, "attachment") && part.Header.Get("Content-ID") != ""
}

// reportedName is the name attachmentParts gives part, and whether part is
// an attachment at all.
func reportedName(part *mailmsg.Part) (string, bool) {
	if part.MainType() == "multipart" {
		return "", false
	}
	disposition := part.Header.Get("Content-Disposition")
	contentID := normalizeCID(part.Header.Get("Content-ID"))
	rawName := part.Filename()
	if !strings.Contains(strings.ToLower(disposition), "attachment") && rawName == "" && contentID == "" {
		return "", false
	}
	name := cleanReportedFilename(mailmsg.DecodeHeader(rawName))
	if name == "" && contentID != "" {
		name = inlineFilenameForCID(contentID, part.ContentType())
	}
	if name == "" {
		name = "unknown"
	}
	return name, true
}

// attachmentParts lists a message's attachments the way the UI names them
// (GetEmail): a part with an attachment disposition, a filename or a
// Content-ID; its decoded filename, else the Content-ID-derived inline
// name, else "unknown". Names are deduplicated.
func attachmentParts(msg *mailmsg.Part) []AttachmentInfo {
	var out []AttachmentInfo
	seen := map[string]bool{}
	for _, part := range msg.Walk() {
		name, ok := reportedName(part)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		payload, _ := part.Payload()
		out = append(out, AttachmentInfo{Filename: name, ContentType: part.ContentType(), SizeBytes: len(payload),
			inline: isInlineResource(part)})
	}
	return out
}

// scanPrefix is one prefix to list: a day partition (day set) or the root
// prefix.
type scanPrefix struct {
	prefix string
	day    time.Time
}

// dayUnique reports whether prefix p, formatted for day d, differs from the
// prefixes of the neighbouring days and of the same day a week, a month and
// a year earlier: a daily format that does not repeat (%A/, %d/ or %m/%d/
// do) is the only one whose prefix places its objects.
func (in *Inbox) dayUnique(p string, d time.Time) bool {
	f := in.s.DatePrefixFormat
	for _, other := range []time.Time{d.AddDate(0, 0, -1), d.AddDate(0, 0, 1), d.AddDate(0, 0, -7), d.AddDate(0, -1, 0), d.AddDate(-1, 0, 0)} {
		if Strftime(f, other) == p {
			return false
		}
	}
	return true
}

func (in *Inbox) agentPrefixes(from, to time.Time) ([]scanPrefix, bool) {
	start, end := Day(from), Day(to)
	prefixes := BuildSearchPrefixes(in.s.Prefix, in.s.DatePrefixFormat, in.s.MaxDatePrefixDays, start, end)
	if len(prefixes) == 1 && prefixes[0] == in.s.Prefix {
		return []scanPrefix{{prefix: in.s.Prefix}}, false
	}
	// A prefix speaks for its day only when no other day shares it, inside
	// the window or next to it (a coarser format such as %Y/ never does): a
	// shared prefix is listed once and its objects are placed by LastModified.
	days := map[string]int{}
	for _, p := range prefixes {
		days[p]++
	}
	out := make([]scanPrefix, 0, len(prefixes))
	listed := map[string]bool{}
	for i, p := range prefixes {
		if listed[p] {
			continue
		}
		listed[p] = true
		sp := scanPrefix{prefix: p}
		if d := end.AddDate(0, 0, -i); days[p] == 1 && in.dayUnique(p, d) {
			sp.day = d
		}
		out = append(out, sp)
	}
	return out, true
}

// candidate is one listed object with where it came from.
type candidate struct {
	obj Object
	sp  scanPrefix
}

// inWindow places a listed object: LastModified inside the window, or, for
// a day partition the window covers in full, simply being listed there.
func inWindow(c candidate, from, to time.Time) bool {
	lm := c.obj.LastModified.UTC()
	if !lm.Before(from) && !lm.After(to) {
		return true
	}
	if c.sp.day.IsZero() {
		return false
	}
	dayEnd := c.sp.day.Add(24*time.Hour - time.Microsecond)
	return !c.sp.day.Before(from) && !dayEnd.After(to)
}

// eachBatch lists the prefixes and hands in-window objects to fn at most
// fetchWorkers at a time (deduplicated, link-archive objects dropped). fn
// returns reached=true once the limit is reached: with day partitions the
// current partition is still finished (keys are not in time order) and only
// later, older partitions are skipped; without partitions (whole-prefix
// mode) every page is scanned, because listing order is not result order.
func (in *Inbox) eachBatch(ctx context.Context, from, to time.Time, stats *AgentStats,
	fn func([]candidate) (reached bool, err error),
) error {
	prefixes, partitioned := in.agentPrefixes(from, to)
	stats.UsedPartitions = partitioned
	// One prefix is listed once and S3 never repeats a key across its pages:
	// only several prefixes need a key set.
	dedupe := len(prefixes) > 1
	seen := map[string]bool{}
	for _, sp := range prefixes {
		stats.Prefixes++
		reached := false
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
				if obj.Key == sp.prefix || (dedupe && seen[obj.Key]) {
					continue
				}
				if dedupe {
					seen[obj.Key] = true
				}
				if in.s.ArchivePrefix != "" && strings.HasPrefix(obj.Key, in.s.ArchivePrefix) {
					continue
				}
				if c := (candidate{obj, sp}); inWindow(c, from, to) {
					batch = append(batch, c)
				}
			}
			for start := 0; start < len(batch); start += fetchWorkers {
				r, err := fn(batch[start:min(start+fetchWorkers, len(batch))])
				if err != nil {
					return err
				}
				reached = reached || r
			}
			if page.NextToken == "" {
				break
			}
			token = page.NextToken
		}
		if reached && partitioned && !sp.day.IsZero() {
			return nil
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

// digestBatch reads the whole messages at idx concurrently (at most
// fetchWorkers, the batch size) and keeps only their digests.
func (in *Inbox) digestBatch(ctx context.Context, batch []candidate, idx []int, keepBody bool, stats *AgentStats) (map[int]digest, error) {
	out := make([]digest, len(idx))
	err := parallel(ctx, len(idx), func(i int) error {
		d, err := in.digestMessage(ctx, batch[idx[i]].obj.Key, keepBody)
		out[i] = d
		return err
	})
	if err != nil {
		return nil, err
	}
	m := make(map[int]digest, len(idx))
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

func matchFor(c candidate, h agentHeaders) AgentMatch {
	return AgentMatch{
		S3Key: c.obj.Key, Subject: h.subject, From: h.from, To: h.to, Date: h.date,
		ReceivedAt: isoformat(c.obj.LastModified), SizeBytes: c.obj.Size,
		SenderAuthenticated: h.authenticated, sortAt: c.obj.LastModified.UTC(),
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

func bestFirst(a, b AgentMatch) bool {
	if a.MatchScore != b.MatchScore {
		return a.MatchScore > b.MatchScore
	}
	return a.sortAt.After(b.sortAt)
}

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
	err := in.eachBatch(ctx, q.From, q.To, &stats, func(batch []candidate) (bool, error) {
		hs, oks, err := in.headerBatch(ctx, batch, &stats)
		if err != nil {
			return false, err
		}
		var picks []int
		for i := range batch {
			if !oks[i] {
				continue
			}
			h := hs[i]
			lowerSubject := strings.ToLower(h.subject)
			if subject != "" && !strings.Contains(lowerSubject, subject) ||
				len(keywords) > 0 && !containsAny(lowerSubject, keywords) ||
				sender != "" && !senderFilterMatches(sender, h.from, authOff) ||
				recipient != "" && !strings.Contains(strings.ToLower(h.to), recipient) {
				continue
			}
			if !authOff && !h.authenticated {
				// Never open an untrusted message. It is "skipped" when the
				// header filters alone decide the match; with a payload filter
				// whether it would match is unknown, so it is "unchecked".
				if q.HasPayload == nil {
					stats.UnauthenticatedSkipped++
				} else {
					stats.UnauthenticatedUnchecked++
				}
				continue
			}
			picks = append(picks, i)
		}
		var full map[int]digest
		if needFull && len(picks) > 0 {
			if full, err = in.digestBatch(ctx, batch, picks, false, &stats); err != nil {
				return false, err
			}
		}
		for _, i := range picks {
			m := matchFor(batch[i], hs[i])
			if needFull {
				d := full[i]
				if !d.ok {
					continue
				}
				m.Opened, m.Attachments, m.DownloadLinks = true, d.attachments, d.links
				if q.HasPayload != nil && (len(d.attachments)+len(d.links) > 0) != *q.HasPayload {
					continue
				}
				if q.IncludeBodyPreview {
					m.BodyPreview = d.preview
				}
			}
			matches = append(matches, m)
		}
		reached := len(matches) >= q.MaxResults
		matches = trimToLimit(matches, q.MaxResults, newestFirst)
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

func fuzzyMatched(hits []string, total int, matchAll bool) bool {
	if matchAll {
		return len(hits) == total
	}
	return len(hits) > 0
}

// AgentFuzzy is the keyword search (search_emails_fuzzy). An untrusted
// message's body is never read: when only its body could still decide the
// match it is counted as unchecked.
func (in *Inbox) AgentFuzzy(ctx context.Context, q AgentFuzzyQuery) ([]AgentMatch, AgentStats, error) {
	var stats AgentStats
	var keywords []fuzzyKeyword
	for _, k := range q.Keywords {
		if t := strings.TrimSpace(k); t != "" {
			keywords = append(keywords, fuzzyKeyword{k, strings.ToLower(k)})
		}
	}
	authOff := in.SenderAuthOff()
	headerText := func(h agentHeaders) string {
		if q.Subject {
			return strings.ToLower(h.subject)
		}
		return ""
	}
	var matches []AgentMatch
	err := in.eachBatch(ctx, q.From, q.To, &stats, func(batch []candidate) (bool, error) {
		hs, oks, err := in.headerBatch(ctx, batch, &stats)
		if err != nil {
			return false, err
		}
		var open []int
		for i := range batch {
			if !oks[i] {
				continue
			}
			trusted := authOff || hs[i].authenticated
			headerHits := fuzzyHits(keywords, headerText(hs[i]), hs[i].from, q.Sender, authOff)
			if !trusted {
				switch {
				case fuzzyMatched(headerHits, len(keywords), q.MatchAll):
					stats.UnauthenticatedSkipped++
				case q.Body:
					stats.UnauthenticatedUnchecked++
				}
				continue
			}
			if q.Body {
				open = append(open, i)
			} else if fuzzyMatched(headerHits, len(keywords), q.MatchAll) {
				m := matchFor(batch[i], hs[i])
				scoreMatch(&m, headerHits, len(keywords))
				matches = append(matches, m)
			}
		}
		if len(open) > 0 {
			full, err := in.digestBatch(ctx, batch, open, true, &stats)
			if err != nil {
				return false, err
			}
			for _, i := range open {
				d := full[i]
				if !d.ok {
					continue
				}
				searchable := strings.TrimSpace(headerText(hs[i]) + " " + d.body)
				hits := fuzzyHits(keywords, searchable, hs[i].from, q.Sender, authOff)
				if !fuzzyMatched(hits, len(keywords), q.MatchAll) {
					continue
				}
				m := matchFor(batch[i], hs[i])
				m.Opened, m.Attachments, m.DownloadLinks = true, d.attachments, d.links
				scoreMatch(&m, hits, len(keywords))
				matches = append(matches, m)
			}
		}
		// Ranking is by match_score first, so an older partition can still
		// hold a better match: never stop early, only keep the best bounded set.
		matches = trimToLimit(matches, q.MaxResults, bestFirst)
		return false, nil
	})
	if err != nil {
		return nil, stats, err
	}
	return trimToLimit(matches, q.MaxResults, bestFirst), stats, nil
}

func scoreMatch(m *AgentMatch, hits []string, total int) {
	m.MatchScore = float64(len(hits)) / float64(total)
	m.MatchedKeywords = hits
}
