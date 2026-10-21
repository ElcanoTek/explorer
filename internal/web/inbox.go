// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
)

type rowView struct {
	archive.Row
	SenderLabel          string
	SubjectOrPlaceholder string
	// LikelyAttachment is the list's cheap paperclip heuristic: a message
	// over 100 kB almost always carries one. Header reads never see parts.
	LikelyAttachment bool
}

type inboxPage struct {
	Mode              string
	CSRFToken         string
	MaxSearchDays     int
	MaxBodySearchDays int
	SelectedDay       string
	DateWindows       []dateWindow
	Sender, Recipient string
	Subject, Keywords string
	MatchAll          bool
	SearchSubject     bool
	SearchSender      bool
	SearchBody        bool
	MaxResults        int

	Error            string
	Searched         bool
	Rows             []rowView
	SearchedWindows  int
	Scanned          int
	PageNumber       int
	NextParams       []kv
	PrevParams       []kv
	IsPaginatedView  bool
	CursorExpired    bool
	SearchInProgress bool
	SearchStatus     string
	SearchCancelled  bool
	CancelReason     string
	PendingSeconds   int
	CompletedSeconds int
	CancelParams     []kv
}

// queryPairs is the query string in its original order, which redirects
// preserve (url.Values would sort it).
func queryPairs(raw string) []kv {
	var out []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" || strings.Contains(part, ";") {
			continue // url.ParseQuery drops these too, so the signature never saw them
		}
		k, v, _ := strings.Cut(part, "=")
		key, err1 := url.QueryUnescape(k)
		val, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, kv{key, val})
	}
	return out
}

func encodePairs(pairs []kv) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = url.QueryEscape(p.Key) + "=" + url.QueryEscape(p.Value)
	}
	return strings.Join(parts, "&")
}

func withoutKey(pairs []kv, key string) []kv {
	out := pairs[:0:0]
	for _, p := range pairs {
		if p.Key != key {
			out = append(out, p)
		}
	}
	return out
}

func searchSignature(mode string, windows []dateWindow, maxResults int, sender, recipient, subject, keywords string,
	matchAll, searchSubject, searchSender, searchBody bool,
) string {
	ws := make([]string, len(windows))
	for i, w := range windows {
		ws[i] = w.From + ".." + w.To
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	norm := func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	return strings.Join([]string{
		mode, strings.Join(ws, "|"), strconv.Itoa(maxResults),
		norm(sender), norm(recipient), norm(subject), norm(keywords),
		flag(matchAll), flag(searchSubject), flag(searchSender), flag(searchBody),
	}, "::")
}

func (s *Server) ownerID(r *http.Request) string {
	sess := sessionFrom(r)
	if sess.data.SearchOwnerID == "" {
		sess.data.SearchOwnerID = newID()
		sess.dirty = true
	}
	return sess.data.SearchOwnerID
}

func toArchiveRanges(ranges []dayRange) []archive.DateRange {
	out := make([]archive.DateRange, len(ranges))
	for i, r := range ranges {
		out[i] = archive.DateRange{Start: r.Start, End: r.End}
	}
	return out
}

func toRowViews(rows []archive.Row) []rowView {
	out := make([]rowView, len(rows))
	for i, row := range rows {
		subject := row.Subject
		if subject == "" {
			subject = "(no subject)"
		}
		out[i] = rowView{Row: row, SenderLabel: parseSender(row.From).Display,
			SubjectOrPlaceholder: subject, LikelyAttachment: row.SizeBytes > 100000}
	}
	return out
}

func today(now time.Time) day {
	l := now.Local()
	return time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.UTC)
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// GET patterns also match HEAD; a HEAD must not start an S3 search.
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	owner := s.ownerID(r)
	s.jobs.prune()

	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(q.Get("mode"), q.Get("search_mode"), "view")))
	if mode != "view" && mode != "exact" && mode != "fuzzy" {
		mode = "view"
	}
	page := &inboxPage{
		Mode:              mode,
		MaxSearchDays:     s.settings.MaxDatePrefixDays,
		MaxBodySearchDays: min(s.settings.MaxDatePrefixDays, s.settings.MaxBodySearchDays),
		Sender:            q.Get("sender"),
		Recipient:         q.Get("recipient"),
		Subject:           q.Get("subject"),
		Keywords:          q.Get("keywords"),
		MaxResults:        100,
		PageNumber:        1,
		IsPaginatedView:   mode == "view",
		SearchStatus:      "idle",
		Searched:          q.Get("run_search") == "1",
	}
	if p, ok := s.auth.(*centralProvider); ok {
		page.CSRFToken = p.csrfToken(r)
	}

	hasSearchParams := false
	for _, k := range []string{"search_subject", "search_sender", "search_body", "match_all", "keywords", "mode", "search_mode"} {
		if q.Has(k) {
			hasSearchParams = true
		}
	}
	page.SearchSubject = !hasSearchParams || q.Has("search_subject")
	page.SearchSender = !hasSearchParams || q.Has("search_sender")
	page.SearchBody = q.Has("search_body")
	page.MatchAll = q.Has("match_all")

	if raw := q.Get("max_results"); raw != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 1 || n > 500 {
			page.Error = "Results per search must be a number from 1 to 500."
		} else {
			page.MaxResults = n
		}
	}
	if raw := q.Get("page"); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 1 {
			page.PageNumber = n
		}
	}

	selectedDay := today(s.now())
	ranges := []dayRange{{selectedDay, selectedDay}}
	if raw := q.Get("day"); raw != "" && page.Error == "" {
		d, err := parseDay(raw)
		if err != nil {
			page.Error = "Invalid date. Use YYYY-MM-DD."
		} else {
			selectedDay = d
		}
	}
	page.SelectedDay = selectedDay.Format(isoDate)
	page.DateWindows = []dateWindow{{page.SelectedDay, page.SelectedDay}}
	if page.Error == "" {
		if mode == "view" {
			ranges = []dayRange{{selectedDay, selectedDay}}
		} else {
			parsed, windows, err := parseDateWindows(q["date_from"], q["date_to"], selectedDay, q.Get("date_ranges"))
			if err != nil {
				page.Error = errBadRanges.Error()
			} else {
				ranges, page.DateWindows = parsed, windows
				total := countDaysCovered(ranges)
				maxDays := s.settings.MaxDatePrefixDays
				bodySearch := mode == "fuzzy" && page.SearchBody
				if bodySearch {
					maxDays = min(maxDays, s.settings.MaxBodySearchDays)
				}
				if total > maxDays {
					if bodySearch {
						page.Error = fmt.Sprintf("Body fuzzy search spans %d days. Keep it at or under %d days per search, or uncheck Body.", total, maxDays)
					} else {
						page.Error = fmt.Sprintf("Date ranges cover %d days. Keep it at or under %d days per search.", total, maxDays)
					}
				}
			}
		}
	}
	page.SearchedWindows = len(ranges)

	if page.Searched && page.Error == "" {
		if mode == "view" {
			s.viewPage(r, page, ranges, owner)
		} else if s.searchPage(w, r, page, ranges, owner) {
			return
		}
	}
	s.render(w, r, http.StatusOK, "inbox", page)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// viewPage lists one day with cursor pagination. Cursors are opaque ids for
// server-held S3 continuation state; the page keeps a stack of them so
// "Previous page" can step back.
func (s *Server) viewPage(r *http.Request, page *inboxPage, ranges []dayRange, owner string) {
	q := r.URL.Query()
	cursor := q.Get("cursor")
	signature := viewSignature(page.DateWindows, page.MaxResults)
	var stack []string
	for _, item := range strings.Split(q.Get("cursor_stack"), ",") {
		if item != "" {
			stack = append(stack, item)
		}
	}
	state := s.jobs.loadCursor(cursor, signature, owner)
	if cursor != "" && state == nil {
		page.CursorExpired = true
		stack = nil
	}
	rows, next, scanned, err := s.inbox.ViewPage(r.Context(), toArchiveRanges(ranges), page.MaxResults, state)
	if err != nil {
		page.Error = userError(err)
		return
	}
	page.Rows, page.Scanned = toRowViews(rows), scanned
	common := []kv{{"run_search", "1"}, {"mode", page.Mode}, {"max_results", strconv.Itoa(page.MaxResults)}, {"day", page.SelectedDay}}
	if next != nil {
		nextID := s.jobs.stashCursor(next, signature, owner)
		marker := cursor
		if marker == "" {
			marker = "FIRST"
		}
		page.NextParams = append(append([]kv{}, common...),
			kv{"cursor", nextID}, kv{"cursor_stack", strings.Join(append(append([]string{}, stack...), marker), ",")},
			kv{"page", strconv.Itoa(page.PageNumber + 1)})
	}
	if len(stack) > 0 {
		prev := append(append([]kv{}, common...), kv{"page", strconv.Itoa(max(1, page.PageNumber-1))})
		if marker := stack[len(stack)-1]; marker != "FIRST" {
			prev = append(prev, kv{"cursor", marker})
		}
		if rest := stack[:len(stack)-1]; len(rest) > 0 {
			prev = append(prev, kv{"cursor_stack", strings.Join(rest, ",")})
		}
		page.PrevParams = prev
	}
}

// searchPage runs, polls or cancels a background search. It returns true
// when it already answered with a redirect.
func (s *Server) searchPage(w http.ResponseWriter, r *http.Request, page *inboxPage, ranges []dayRange, owner string) bool {
	q := r.URL.Query()
	jobID := q.Get("search_job")
	signature := searchSignature(page.Mode, page.DateWindows, page.MaxResults, page.Sender, page.Recipient,
		page.Subject, page.Keywords, page.MatchAll, page.SearchSubject, page.SearchSender, page.SearchBody)
	job := s.jobs.load(jobID, signature, owner)

	if q.Get("cancel_search") == "1" {
		switch {
		case jobID == "":
			page.Error = "No active search to cancel."
		case job == nil:
			page.Error = "This search session expired. Run the search again."
		default:
			s.jobs.requestCancel(jobID)
			http.Redirect(w, r, "/?"+encodePairs(withoutKey(queryPairs(r.URL.RawQuery), "cancel_search")), http.StatusSeeOther)
			return true
		}
		return false
	}
	if jobID != "" && job == nil {
		page.Error = "This search session expired. Run the search again."
		return false
	}
	if job == nil {
		id := s.startSearch(page, ranges, signature, owner)
		pairs := append(withoutKey(queryPairs(r.URL.RawQuery), "search_job"), kv{"search_job", id})
		http.Redirect(w, r, "/?"+encodePairs(pairs), http.StatusSeeOther)
		return true
	}

	now := s.now()
	page.SearchStatus = string(job.Status)
	page.PendingSeconds = max(0, int(now.Sub(job.StartedAt).Seconds()))
	switch job.Status {
	case jobDone:
		page.Rows, page.Scanned = toRowViews(job.Rows), job.Scanned
		page.CompletedSeconds = max(0, int(job.CompletedAt.Sub(job.StartedAt).Seconds()))
	case jobCancelled:
		page.SearchCancelled = true
		page.CancelReason = job.CancelReason
		page.CompletedSeconds = max(0, int(job.CompletedAt.Sub(job.StartedAt).Seconds()))
	case jobError:
		page.Error = job.Err
	default:
		page.SearchInProgress = true
		cancel := []kv{{"run_search", "1"}, {"mode", page.Mode}, {"max_results", strconv.Itoa(page.MaxResults)},
			{"search_job", jobID}, {"cancel_search", "1"}}
		if page.Mode == "exact" {
			cancel = append(cancel, kv{"sender", page.Sender}, kv{"recipient", page.Recipient}, kv{"subject", page.Subject})
		} else {
			cancel = append(cancel, kv{"keywords", page.Keywords})
			for _, f := range []struct {
				on   bool
				name string
			}{{page.MatchAll, "match_all"}, {page.SearchSubject, "search_subject"}, {page.SearchSender, "search_sender"}, {page.SearchBody, "search_body"}} {
				if f.on {
					cancel = append(cancel, kv{f.name, "on"})
				}
			}
		}
		for _, w := range page.DateWindows {
			cancel = append(cancel, kv{"date_from", w.From})
		}
		for _, w := range page.DateWindows {
			cancel = append(cancel, kv{"date_to", w.To})
		}
		page.CancelParams = cancel
	}
	return false
}

func (s *Server) startSearch(page *inboxPage, ranges []dayRange, signature, owner string) string {
	mode, maxResults := page.Mode, page.MaxResults
	sender, recipient, subject, keywords := page.Sender, page.Recipient, page.Subject, page.Keywords
	fields := archive.FuzzyFields{Subject: page.SearchSubject, Sender: page.SearchSender, Body: page.SearchBody}
	matchAll := page.MatchAll
	dr := toArchiveRanges(ranges)
	return s.jobs.start(signature, owner, time.Duration(s.settings.SearchJobMaxSeconds)*time.Second,
		func(ctx context.Context) ([]archive.Row, int, error) {
			if mode == "fuzzy" {
				if !fields.Subject && !fields.Sender && !fields.Body {
					return nil, 0, errors.New("Choose at least one fuzzy search field.") //nolint:revive,staticcheck // ST1005: shown to the user verbatim.
				}
				if strings.TrimSpace(keywords) == "" {
					return nil, 0, errors.New("Enter at least one fuzzy keyword.") //nolint:revive,staticcheck // ST1005: shown to the user verbatim.
				}
				return s.inbox.SearchFuzzy(ctx, dr, strings.Split(keywords, ","), fields, matchAll, maxResults)
			}
			return s.inbox.Search(ctx, dr, archive.ExactQuery{Sender: sender, Recipient: recipient, Subject: subject}, maxResults)
		})
}

// userError turns a storage failure into the message the page shows.
func userError(err error) string {
	if isCancellation(err) {
		return "The request was cancelled before it finished."
	}
	return err.Error()
}
