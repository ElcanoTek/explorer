// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
)

// Limits. max_results above MaxResults is refused: a model asking for more
// is better told than silently truncated.
const (
	DefaultExactResults = 25
	DefaultFuzzyResults = 50
	MaxResults          = 500
	// largeMaxResults draws the large_max_results warning.
	largeMaxResults = 250
	// autoChunkDays: a wider window is still served, day by day, with a
	// date_window_auto_chunked warning.
	autoChunkDays = 3
	// highScanCount with zero matches draws high_scan_zero_matches.
	highScanCount        = 2000
	DefaultLookbackDays  = 14
	MaxLookbackDays      = 60
	DefaultMaxCandidates = 1
	MaxCandidates        = 25
)

// Warning is one query-quality note for the calling agent.
type Warning = map[string]any

func warn(code, severity, message, suggestion string) Warning {
	return Warning{"code": code, "severity": severity, "message": message, "suggestion": suggestion}
}

func hasAlnum(s string) bool {
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return true
		}
	}
	return false
}

type queryWarningInput struct {
	subjectContains   string
	subjectKeywords   []string
	sender, recipient *string
	dateFrom, dateTo  string
	hasPayload        *bool
	maxResults        int
}

// queryWarnings is the Python _build_search_warnings.
func (a *API) queryWarnings(in queryWarningInput) []Warning {
	var out []Warning
	if in.sender != nil && !hasAlnum(*in.sender) {
		out = append(out, warn("sender_filter_not_meaningful", "high",
			"sender_contains has no letters or digits and will not narrow results reliably.",
			"Use a sender domain such as 'vendor.example' or remove sender_contains."))
	}
	if in.sender != nil && !a.inbox.SenderAuthOff() {
		if ignored := archive.IgnoredSenderEntries(*in.sender); len(ignored) > 0 {
			msg := "sender_contains entries ignored (not a full mailbox or a multi-label domain): " +
				strings.Join(ignored, ", ") + "."
			total := 0
			for _, item := range strings.Split(*in.sender, ",") {
				if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(item), "@")) != "" {
					total++
				}
			}
			if len(ignored) == total {
				msg += " No entry is usable, so the sender filter matches nothing."
			}
			out = append(out, warn("sender_filter_entries_ignored", "high", msg,
				"Pass sender domains such as 'vendor.example' or full addresses such as "+
					"'reports@vendor.example'; a bare name or TLD matches nothing."))
		}
	}
	if in.recipient != nil && !hasAlnum(*in.recipient) {
		out = append(out, warn("recipient_filter_not_meaningful", "high",
			"recipient_contains has no letters or digits and will not narrow results reliably.",
			"Use a recipient email/domain fragment or remove recipient_contains."))
	}
	if (in.dateFrom == "") != (in.dateTo == "") {
		out = append(out, warn("partially_bounded_date_window", "medium",
			"Only one date bound was provided.", "Provide both date_from and date_to for deterministic retrieval."))
	}
	hasText := in.subjectContains != "" || len(in.subjectKeywords) > 0 ||
		(in.sender != nil && *in.sender != "") || (in.recipient != nil && *in.recipient != "")
	if !hasText && in.hasPayload == nil {
		out = append(out, warn("broad_query_low_selectivity", "medium",
			"No subject/sender/recipient/payload filters were provided.",
			"Add sender_contains and/or subject filters before expanding the date window."))
	}
	if in.maxResults > largeMaxResults {
		out = append(out, warn("large_max_results", "low",
			"max_results is very high and may increase response size and latency.",
			"Start with max_results <= 25, then widen only if needed."))
	}
	return out
}

func (a *API) scanWarnings(stats archive.AgentStats, matches int, fuzzy bool) []Warning {
	var out []Warning
	if n := stats.UnauthenticatedSkipped; n > 0 {
		w := warn("unauthenticated_sender_skipped", "high",
			fmt.Sprintf("%d email(s) were left out: the receiving server did not authenticate their sender "+
				"(no DMARC / aligned SPF or DKIM pass for the From domain), so their From header may be forged.", n),
			"Do not treat those as the vendor's report. If the vendor's mail really fails authentication, "+
				"the operator can set EMAIL_SENDER_AUTH=off (header matching) for this inbox.")
		w["count"] = n
		out = append(out, w)
	}
	if n := stats.UnauthenticatedUnchecked; n > 0 {
		w := warn("unauthenticated_sender_unchecked", "high",
			fmt.Sprintf("%d email(s) matched the header filters but were left out unopened: the receiving "+
				"server did not authenticate their sender, so whether they carry a payload was not checked.", n),
			"Do not treat those as the vendor's report. If the vendor's mail really fails authentication, "+
				"the operator can set EMAIL_SENDER_AUTH=off (header matching) for this inbox.")
		w["count"] = n
		out = append(out, w)
	}
	if a.inbox.SenderAuthOff() {
		out = append(out, warn("unauthenticated_sender_match", "medium",
			"EMAIL_SENDER_AUTH=off: results include mail whose sender was not authenticated, and the "+
				"sender text matched can be forged.",
			"Check each result's sender_authenticated before trusting it as a vendor's report."))
	}
	if stats.Scanned >= highScanCount && matches == 0 {
		suggestion := "Tighten sender/subject filters and confirm date bounds before retrying."
		if fuzzy {
			suggestion = "Use sender-refined exact search_emails first, then retry fuzzy with tighter keywords."
		}
		out = append(out, warn("high_scan_zero_matches", "high",
			"Scanned a large volume with zero matches; the query is likely too broad or misconfigured.", suggestion))
	}
	return out
}

func searchStats(stats archive.AgentStats, elapsed time.Duration) Body {
	return Body{
		"header_fetches":  stats.HeaderFetches,
		"full_fetches":    stats.FullFetches,
		"parse_errors":    stats.ParseErrors,
		"prefixes_listed": stats.Prefixes,
		"elapsed_seconds": float64(elapsed.Milliseconds()) / 1000,
	}
}

func emailBody(m archive.AgentMatch) Body {
	attachments := m.Attachments
	if attachments == nil {
		attachments = []string{}
	}
	b := Body{
		"s3_key":               m.S3Key,
		"subject":              m.Subject,
		"from":                 m.From,
		"sender_authenticated": m.SenderAuthenticated,
		"to":                   m.To,
		"date":                 m.Date,
		"received_at":          m.ReceivedAt,
		"size_bytes":           m.SizeBytes,
		// payload_checked: attachments and download links were read from
		// the full message (has_payload, a body preview, or a body search);
		// otherwise only headers were read and the counts are unknown (0).
		"payload_checked":  m.Opened,
		"has_attachments":  len(attachments) > 0,
		"attachment_count": len(attachments),
		"attachment_names": attachments,
	}
	return b
}

// exactEmailBody reports one match. The links themselves (often bearer-style
// presigned URLs) are message content: only a token that may read mail gets
// them; a search-only token sees that they exist.
func exactEmailBody(m archive.AgentMatch, preview, canRead bool) Body {
	b := emailBody(m)
	b["has_download_links"] = len(m.DownloadLinks) > 0
	b["download_link_count"] = len(m.DownloadLinks)
	if len(m.DownloadLinks) > 0 && canRead {
		b["download_links"] = m.DownloadLinks
	}
	if preview {
		b["body_preview"] = m.BodyPreview
	}
	return b
}

func fuzzyEmailBody(m archive.AgentMatch) Body {
	b := emailBody(m)
	b["match_score"] = m.MatchScore
	b["matched_keywords"] = m.MatchedKeywords
	return b
}

// windowDays counts the calendar days from..to covers.
func windowDays(from, to time.Time) int {
	return int(archive.Day(to).Sub(archive.Day(from)).Hours()/24) + 1
}

// fittingWindow names both bounds of a window of maxDays ending at the later
// bound, so a refused search is corrected in one step whichever way round the
// caller wrote its dates: ` (date_from 2026-08-31 with date_to 2026-10-31 fits;
// search earlier dates in a second call)`.
func fittingWindow(to time.Time, maxDays int) string {
	if maxDays < 1 {
		return ""
	}
	end := archive.Day(to)
	from := end.AddDate(0, 0, -(maxDays - 1))
	return fmt.Sprintf(" (date_from %s with date_to %s fits; search earlier dates in a second call)",
		from.Format("2006-01-02"), end.Format("2006-01-02"))
}

func boundedDateError(tool string) *Error {
	e := invalidArg("%s requires both date_from and date_to.", tool)
	e.Code = "bounded_date_window_required"
	e.Details = map[string]any{"search_warnings": []Warning{warn("bounded_date_window_required", "high",
		tool+" requires both date_from and date_to.",
		"Use 1-day searches in sequence, or find_latest_report to walk back day by day.")}}
	return e
}

type exactArgs struct {
	subjectContains    string
	subjectKeywords    []string
	sender, recipient  *string
	dateFrom, dateTo   string
	hasPayload         *bool
	maxResults         int
	includeBodyPreview bool
	// canRead: the token holds email:read, so message content may be returned.
	canRead            bool
	fromBound, toBound time.Time
	criteria           Body
	warnings           []Warning
}

func optStringPtr(args map[string]any, name string) (*string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	s, isString := v.(string)
	if !isString {
		return nil, invalidArg("%s must be a string", name)
	}
	return &s, nil
}

// parseExact validates search_emails arguments.
func (a *API) parseExact(args map[string]any) (*exactArgs, error) {
	var x exactArgs
	var err error
	if x.subjectContains, err = optString(args, "subject_contains"); err != nil {
		return nil, err
	}
	keywords, err := optStrings(args, "subject_keywords")
	if err != nil {
		return nil, err
	}
	x.subjectKeywords = nonEmpty(keywords)
	if x.sender, err = optStringPtr(args, "sender_contains"); err != nil {
		return nil, err
	}
	if x.recipient, err = optStringPtr(args, "recipient_contains"); err != nil {
		return nil, err
	}
	if x.dateFrom, err = optString(args, "date_from"); err != nil {
		return nil, err
	}
	if x.dateTo, err = optString(args, "date_to"); err != nil {
		return nil, err
	}
	if x.hasPayload, err = optBool(args, "has_payload"); err != nil {
		return nil, err
	}
	if x.maxResults, err = intUpTo(args, "max_results", DefaultExactResults, MaxResults); err != nil {
		return nil, err
	}
	if x.includeBodyPreview, err = boolOr(args, "include_body_preview", false); err != nil {
		return nil, err
	}
	x.criteria = Body{
		"subject_contains": strOrNil(x.subjectContains), "subject_keywords": listOrNil(x.subjectKeywords),
		"sender_contains": ptrOrNil(x.sender), "recipient_contains": ptrOrNil(x.recipient),
		"date_from": strOrNil(x.dateFrom), "date_to": strOrNil(x.dateTo),
		"has_payload": boolPtrOrNil(x.hasPayload), "max_results": x.maxResults,
	}
	x.warnings = a.queryWarnings(queryWarningInput{
		subjectContains: x.subjectContains, subjectKeywords: x.subjectKeywords, sender: x.sender,
		recipient: x.recipient, dateFrom: x.dateFrom, dateTo: x.dateTo, hasPayload: x.hasPayload,
		maxResults: x.maxResults,
	})
	for _, w := range x.warnings {
		if code := w["code"]; code == "sender_filter_not_meaningful" || code == "recipient_filter_not_meaningful" {
			e := invalidArg("Query validation failed: non-meaningful sender/recipient filter.")
			e.Code = "filter_not_meaningful"
			e.Details = map[string]any{"search_warnings": []Warning{w}, "search_criteria": x.criteria}
			return nil, e
		}
	}
	if x.dateFrom == "" || x.dateTo == "" {
		return nil, boundedDateError("search_emails")
	}
	if x.fromBound, x.toBound, err = orderedBounds(x.dateFrom, x.dateTo); err != nil {
		return nil, err
	}
	days := windowDays(x.fromBound, x.toBound)
	if days > a.settings.MaxDatePrefixDays {
		return nil, invalidArg("The date window covers %d days; keep a search at or under %d days%s.",
			days, a.settings.MaxDatePrefixDays, fittingWindow(x.toBound, a.settings.MaxDatePrefixDays))
	}
	if days > autoChunkDays {
		x.warnings = append(x.warnings, chunkWarning(days))
	}
	return &x, nil
}

func ptrOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func chunkWarning(days int) Warning {
	return warn("date_window_auto_chunked", "medium",
		fmt.Sprintf("Window spans %d days; scanning one S3 prefix per day.", days),
		"Prefer targeted 1-day searches for recurring report selection; wide windows cost more scan budget.")
}

// orderedBounds parses a date window, swapping reversed bounds before the
// start-of-day / end-of-day expansion so both end days stay whole.
func orderedBounds(fromRaw, toRaw string) (from, to time.Time, err error) {
	if from, err = parseBound("date_from", fromRaw, false); err != nil {
		return from, to, err
	}
	if to, err = parseBound("date_to", toRaw, true); err != nil {
		return from, to, err
	}
	if !to.Before(from) {
		return from, to, nil
	}
	if from, err = parseBound("date_to", toRaw, false); err != nil {
		return from, to, err
	}
	to, err = parseBound("date_from", fromRaw, true)
	return from, to, err
}

// SearchEmails is search_emails.
func (a *API) SearchEmails(r *http.Request, t *apitoken.Token, args map[string]any) (Body, error) {
	x, err := a.parseExact(args)
	if err != nil {
		return nil, err
	}
	if err := contentScope(t, x); err != nil {
		return nil, err
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	return a.runExact(ctx, x)
}

// contentScope records whether t may see message content, and refuses a body
// preview to a token that may not: the preview is the message text.
func contentScope(t *apitoken.Token, x *exactArgs) error {
	x.canRead = t.Allows(apitoken.ScopeRead)
	if x.includeBodyPreview && !x.canRead {
		return RequireScope(t, apitoken.ScopeRead)
	}
	return nil
}

func (a *API) runExact(ctx context.Context, x *exactArgs) (Body, error) {
	started := a.now()
	q := archive.AgentQuery{
		SubjectContains: x.subjectContains, SubjectKeywords: x.subjectKeywords,
		From: x.fromBound, To: x.toBound, HasPayload: x.hasPayload, MaxResults: x.maxResults,
		IncludeBodyPreview: x.includeBodyPreview,
	}
	if x.sender != nil {
		q.SenderContains = *x.sender
	}
	if x.recipient != nil {
		q.RecipientContains = *x.recipient
	}
	matches, stats, err := a.inbox.AgentSearch(ctx, q)
	if err != nil {
		return nil, a.archiveError("search_emails", err)
	}
	emails := make([]Body, len(matches))
	for i, m := range matches {
		emails[i] = exactEmailBody(m, x.includeBodyPreview, x.canRead)
	}
	criteria := Body{}
	for k, v := range x.criteria {
		criteria[k] = v
	}
	criteria["effective_date_from"] = isoformat(x.fromBound)
	criteria["effective_date_to"] = isoformat(x.toBound)
	warnings := append(append([]Warning{}, x.warnings...), a.scanWarnings(stats, len(matches), false)...)
	a.log.Info("api search_emails", "scanned", stats.Scanned, "matched", len(matches),
		"full_fetches", stats.FullFetches, "elapsed_ms", a.now().Sub(started).Milliseconds())
	return Body{
		"status":          "success",
		"matches_found":   len(matches),
		"emails_scanned":  stats.Scanned,
		"search_stats":    searchStats(stats, a.now().Sub(started)),
		"search_criteria": criteria,
		"search_warnings": nonNilWarnings(warnings),
		"emails":          emails,
	}, nil
}

func nonNilWarnings(w []Warning) []Warning {
	if w == nil {
		return []Warning{}
	}
	return w
}

// SearchEmailsFuzzy is search_emails_fuzzy.
func (a *API) SearchEmailsFuzzy(r *http.Request, args map[string]any) (Body, error) {
	keywords, err := optStrings(args, "keywords")
	if err != nil {
		return nil, err
	}
	keywords = nonEmpty(keywords)
	if len(keywords) == 0 {
		// Agents also write a free-text query: its words are the keywords.
		query, err := optString(args, "query")
		if err != nil {
			return nil, err
		}
		keywords = strings.FieldsFunc(query, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	}
	if args["max_results"] == nil && args["limit"] != nil { // a null max_results is absent, as everywhere here
		args = maps.Clone(args)
		args["max_results"] = args["limit"] // limit is another word for max_results
	}
	if len(keywords) == 0 {
		e := invalidArg("keywords (or query) must contain at least one non-empty value")
		e.Details = map[string]any{"search_warnings": []Warning{warn("empty_keywords", "high",
			"Fuzzy search invoked without usable keywords.",
			"Provide 1-3 concrete keywords or use exact search_emails with sender/subject filters.")}}
		return nil, e
	}
	fields, err := optStrings(args, "search_fields")
	if err != nil {
		return nil, err
	}
	if fields == nil {
		fields = []string{"subject", "sender"}
	}
	q := archive.AgentFuzzyQuery{Keywords: keywords}
	for _, f := range fields {
		switch f {
		case "subject":
			q.Subject = true
		case "sender":
			q.Sender = true
		case "body":
			q.Body = true
		default:
			return nil, invalidArg("Invalid search_fields: each must be one of subject, sender, body (got %q)", f)
		}
	}
	if len(fields) == 0 {
		return nil, invalidArg("search_fields must name at least one of subject, sender, body")
	}
	if q.MatchAll, err = boolOr(args, "match_all", false); err != nil {
		return nil, err
	}
	dateFrom, err := optString(args, "date_from")
	if err != nil {
		return nil, err
	}
	dateTo, err := optString(args, "date_to")
	if err != nil {
		return nil, err
	}
	if q.MaxResults, err = intUpTo(args, "max_results", DefaultFuzzyResults, MaxResults); err != nil {
		return nil, err
	}
	if dateFrom == "" {
		return nil, boundedDateError("search_emails_fuzzy")
	}
	if dateTo == "" {
		if q.From, err = parseBound("date_from", dateFrom, false); err != nil {
			return nil, err
		}
		q.To = a.now().UTC() // the Python resolve_search_bounds: an open end is "now"
		if q.To.Before(q.From) {
			q.From, q.To = q.To, q.From
		}
	} else if q.From, q.To, err = orderedBounds(dateFrom, dateTo); err != nil {
		return nil, err
	}
	days := windowDays(q.From, q.To)
	maxDays := a.settings.MaxDatePrefixDays
	if q.Body {
		maxDays = min(maxDays, a.settings.MaxBodySearchDays)
	}
	if days > maxDays {
		kind := "search"
		if q.Body {
			kind = "body search"
		}
		return nil, invalidArg("The date window covers %d days; keep a %s at or under %d days%s.",
			days, kind, maxDays, fittingWindow(q.To, maxDays))
	}
	warnings := a.queryWarnings(queryWarningInput{subjectKeywords: keywords, dateFrom: dateFrom, dateTo: dateTo,
		maxResults: q.MaxResults})
	if days > autoChunkDays {
		warnings = append(warnings, chunkWarning(days))
	}
	// Fuzzy always has keywords, so the low-selectivity warning never applies.
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	started := a.now()
	matches, stats, err := a.inbox.AgentFuzzy(ctx, q)
	if err != nil {
		return nil, a.archiveError("search_emails_fuzzy", err)
	}
	emails := make([]Body, len(matches))
	for i, m := range matches {
		emails[i] = fuzzyEmailBody(m)
	}
	warnings = append(warnings, a.scanWarnings(stats, len(matches), true)...)
	a.log.Info("api search_emails_fuzzy", "scanned", stats.Scanned, "matched", len(matches),
		"full_fetches", stats.FullFetches, "elapsed_ms", a.now().Sub(started).Milliseconds())
	return Body{
		"status":         "success",
		"matches_found":  len(matches),
		"emails_scanned": stats.Scanned,
		"search_stats":   searchStats(stats, a.now().Sub(started)),
		"search_criteria": Body{
			"keywords": keywords, "search_fields": fields, "match_all": q.MatchAll,
			"date_from": strOrNil(dateFrom), "date_to": strOrNil(dateTo),
			"effective_date_from": isoformat(q.From), "effective_date_to": isoformat(q.To),
			"max_results": q.MaxResults,
		},
		"search_warnings": nonNilWarnings(warnings),
		"emails":          emails,
	}, nil
}

// mergeWarning keeps one warning per code across the days of a
// find_latest_report walk: the days it came from, and for counted warnings
// the summed count with the message rewritten to it.
func mergeWarning(warnings []Warning, w Warning, day string) []Warning {
	for _, existing := range warnings {
		if existing["code"] != w["code"] {
			continue
		}
		existing["days"] = append(existing["days"].([]string), day)
		if n, ok := w["count"].(int); ok {
			total := n
			if prev, ok := existing["count"].(int); ok {
				total += prev
			}
			existing["count"] = total
			days := len(existing["days"].([]string))
			switch w["code"] {
			case "unauthenticated_sender_skipped":
				existing["message"] = fmt.Sprintf("%d email(s) were left out across %d day(s): the receiving "+
					"server did not authenticate their sender, so their From header may be forged.", total, days)
			case "unauthenticated_sender_unchecked":
				existing["message"] = fmt.Sprintf("%d email(s) across %d day(s) matched the header filters "+
					"but were left out unopened: the receiving server did not authenticate their sender.", total, days)
			}
		}
		return warnings
	}
	copied := Warning{}
	for k, v := range w {
		copied[k] = v
	}
	copied["days"] = []string{day}
	return append(warnings, copied)
}

// FindLatestReport is find_latest_report: walk back day by day from
// on_or_before until max_candidates matches are found or lookback_days are
// searched. A day whose search fails fails the whole call: an older match
// must never pass for the latest one.
func (a *API) FindLatestReport(r *http.Request, t *apitoken.Token, args map[string]any) (Body, error) {
	onOrBefore, err := optString(args, "on_or_before")
	if err != nil {
		return nil, err
	}
	anchor := archive.Day(a.now().UTC())
	if onOrBefore != "" {
		t, err := parseBound("on_or_before", onOrBefore, false)
		if err != nil {
			return nil, err
		}
		anchor = archive.Day(t)
	}
	lookback, err := intUpTo(args, "lookback_days", DefaultLookbackDays, MaxLookbackDays)
	if err != nil {
		return nil, err
	}
	requirePayload, err := boolOr(args, "require_payload", true)
	if err != nil {
		return nil, err
	}
	maxCandidates, err := intUpTo(args, "max_candidates", DefaultMaxCandidates, MaxCandidates)
	if err != nil {
		return nil, err
	}
	dayArgs := map[string]any{}
	for _, name := range []string{"sender_contains", "subject_contains", "subject_keywords", "recipient_contains"} {
		if v, ok := args[name]; ok {
			dayArgs[name] = v
		}
	}
	if requirePayload {
		dayArgs["has_payload"] = true
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()

	collected := []Body{}
	warnings := []Warning{}
	var firstMatch any
	daysSearched := 0
	for offset := 0; offset < lookback && len(collected) < maxCandidates; offset++ {
		day := anchor.AddDate(0, 0, -offset).Format(isoDate)
		daysSearched++
		dayArgs["date_from"], dayArgs["date_to"] = day, day
		dayArgs["max_results"] = float64(maxCandidates - len(collected))
		x, err := a.parseExact(dayArgs)
		if err != nil {
			return nil, err
		}
		x.canRead = t.Allows(apitoken.ScopeRead)
		body, err := a.runExact(ctx, x)
		if err != nil {
			var e *Error
			if errors.As(err, &e) {
				e.Message = fmt.Sprintf("Search for %s failed: %s", day, e.Message)
				if e.Details == nil {
					e.Details = map[string]any{}
				}
				e.Details["failed_day"] = day
				e.Details["days_searched"] = daysSearched
				e.Details["anchor_date"] = anchor.Format(isoDate)
				e.Details["emails"] = collected
				e.Details["search_warnings"] = warnings
			}
			return nil, err
		}
		for _, w := range body["search_warnings"].([]Warning) {
			if w["code"] == "date_window_auto_chunked" {
				continue
			}
			warnings = mergeWarning(warnings, w, day)
		}
		for _, e := range body["emails"].([]Body) {
			collected = append(collected, e)
			if firstMatch == nil {
				firstMatch = day
			}
			if len(collected) >= maxCandidates {
				break
			}
		}
	}
	return Body{
		"status":           "success",
		"days_searched":    daysSearched,
		"anchor_date":      anchor.Format(isoDate),
		"first_match_date": firstMatch,
		"match_count":      len(collected),
		"emails":           collected,
		"search_warnings":  warnings,
		"search_criteria": Body{
			"sender_contains": args["sender_contains"], "subject_contains": args["subject_contains"],
			"subject_keywords": args["subject_keywords"], "recipient_contains": args["recipient_contains"],
			"on_or_before": anchor.Format(isoDate), "lookback_days": lookback,
			"require_payload": requirePayload, "max_candidates": maxCandidates,
		},
	}, nil
}
