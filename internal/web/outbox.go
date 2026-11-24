// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
)

const (
	// outboxDefaultDays is the window Search and Fuzzy Search open on: the
	// last week.
	outboxDefaultDays = 7
	// outboxLimit caps one Outbox result list.
	outboxLimit = 500
)

type outboxRow struct {
	archive.SentRecord
	SubjectOrPlaceholder string
	ToLine               string
}

type outboxPage struct {
	// Mode is the inbox's: view (one day), exact (filters) or fuzzy
	// (keywords).
	Mode                       string
	CSRFToken                  string
	SelectedDay                string
	From, To                   string
	Recipient, Subject, SentBy string
	Keywords                   string
	MatchAll                   bool
	SearchSubject              bool
	SearchRecipients           bool
	SearchBody                 bool
	MaxSearchDays              int
	MaxBodySearchDays          int
	Limit                      int
	Rows                       []outboxRow
	Scanned, Unreadable        int
	Truncated, Searched        bool
	Error                      string
}

// handleOutbox is the Outbox: every email Fleet sent for this client, read
// from the sender's .json records; each row opens the message at /email.
// It has the inbox's three modes. View lists one day and runs on opening
// (a day of records is small); Search and Fuzzy Search run when submitted.
func (s *Server) handleOutbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.outbox == nil {
		s.notFound(w, r, "This Explorer has no Outbox.")
		return
	}
	q := r.URL.Query()
	mode := strings.ToLower(strings.TrimSpace(q.Get("mode")))
	legacy := false
	if mode == "" {
		// A link from the single-form Outbox (before the modes) has its
		// dates and filters but no mode: it was a Search, run at once.
		for _, k := range []string{"date_from", "date_to", "recipient", "subject", "sent_by"} {
			legacy = legacy || q.Has(k)
		}
	}
	switch {
	case legacy:
		mode = "exact"
	case mode != "exact" && mode != "fuzzy":
		mode = "view"
	}
	end := today(s.now())
	page := &outboxPage{
		Mode:        mode,
		SelectedDay: end.Format(isoDate),
		From:        end.AddDate(0, 0, 1-outboxDefaultDays).Format(isoDate), To: end.Format(isoDate),
		Recipient: q.Get("recipient"), Subject: q.Get("subject"), SentBy: q.Get("sent_by"),
		Keywords:          q.Get("keywords"),
		MaxSearchDays:     s.settings.MaxDatePrefixDays,
		MaxBodySearchDays: min(s.settings.MaxDatePrefixDays, s.settings.MaxBodySearchDays),
		Limit:             outboxLimit,
		Searched:          mode == "view" || legacy || q.Get("run_search") == "1",
	}
	if p, ok := s.auth.(*centralProvider); ok {
		page.CSRFToken = p.csrfToken(r)
	}
	// The fuzzy fields start as Subject and Recipients; once the form is
	// submitted, its checkboxes say.
	submitted := q.Get("run_search") == "1"
	page.SearchSubject = !submitted || q.Has("search_subject")
	page.SearchRecipients = !submitted || q.Has("search_recipients")
	page.SearchBody = q.Has("search_body")
	page.MatchAll = q.Has("match_all")
	if raw := q.Get("day"); raw != "" {
		page.SelectedDay = raw
	}
	if raw := q.Get("date_from"); raw != "" {
		page.From = raw
	}
	if raw := q.Get("date_to"); raw != "" {
		page.To = raw
	}
	if page.Searched {
		page.Error = s.searchOutbox(r.Context(), page)
		page.Searched = page.Error == ""
	}
	s.render(w, r, http.StatusOK, "outbox", page)
}

// searchOutbox runs page's search and fills its rows, or returns the error
// to show.
func (s *Server) searchOutbox(ctx context.Context, page *outboxPage) string {
	var window dayRange
	if page.Mode == "view" {
		d, err := parseDay(page.SelectedDay)
		if err != nil {
			return "Invalid date. Use YYYY-MM-DD."
		}
		window = dayRange{d, d}
	} else {
		from, errFrom := parseDay(page.From)
		to, errTo := parseDay(page.To)
		if errFrom != nil || errTo != nil {
			return "Invalid date. Use YYYY-MM-DD."
		}
		window = ordered(from, to)
		days := int(window.End.Sub(window.Start).Hours()/24) + 1
		if page.Mode == "fuzzy" && page.SearchBody && days > page.MaxBodySearchDays {
			return fmt.Sprintf("Body fuzzy search spans %d days. Keep it at or under %d days per search, or uncheck Body.",
				days, page.MaxBodySearchDays)
		}
		if days > page.MaxSearchDays {
			return fmt.Sprintf("Keep the window at or under %d days.", page.MaxSearchDays)
		}
	}
	if page.Mode == "fuzzy" {
		if strings.TrimSpace(strings.ReplaceAll(page.Keywords, ",", "")) == "" {
			return "Enter at least one keyword."
		}
		if !page.SearchSubject && !page.SearchRecipients && !page.SearchBody {
			return "Choose at least one field to search: Subject, Recipients or Body."
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.settings.SearchJobMaxSeconds)*time.Second)
	defer cancel()
	from, to := window.Start, window.End.Add(24*time.Hour-time.Nanosecond)
	var (
		records []archive.SentRecord
		stats   archive.OutboxStats
		err     error
	)
	switch page.Mode {
	case "fuzzy":
		records, stats, err = s.outbox.SearchFuzzy(ctx, from, to, archive.OutboxFuzzy{
			Keywords: strings.Split(page.Keywords, ","), Subject: page.SearchSubject,
			Recipients: page.SearchRecipients, Body: page.SearchBody, MatchAll: page.MatchAll, Limit: page.Limit})
	case "exact":
		records, stats, err = s.outbox.Search(ctx, from, to, archive.OutboxQuery{
			Recipient: page.Recipient, Subject: page.Subject, SentBy: page.SentBy, Limit: page.Limit})
	default:
		records, stats, err = s.outbox.Search(ctx, from, to, archive.OutboxQuery{Limit: page.Limit})
	}
	if err != nil {
		slog.Warn("outbox search", "err", err)
		return "The Outbox could not be read. Try again, or narrow the dates."
	}
	page.Scanned, page.Unreadable, page.Truncated = stats.Scanned, stats.Unreadable, stats.Truncated
	for _, rec := range records {
		subject := rec.Subject
		if subject == "" {
			subject = "(no subject)"
		}
		page.Rows = append(page.Rows, outboxRow{SentRecord: rec, SubjectOrPlaceholder: subject,
			ToLine: strings.Join(rec.To, ", ")})
	}
	return ""
}
