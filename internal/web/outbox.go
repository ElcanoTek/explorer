// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
)

// outboxDefaultDays is the window the Outbox page opens on: the last week.
const outboxDefaultDays = 7

type outboxRow struct {
	archive.SentRecord
	SubjectOrPlaceholder string
	ToLine               string
}

type outboxPage struct {
	CSRFToken                  string
	From, To                   string
	Recipient, Subject, SentBy string
	MaxSearchDays              int
	Rows                       []outboxRow
	Scanned, Unreadable        int
	Truncated, Searched        bool
	Error                      string
}

// handleOutbox is the Outbox: every email Fleet sent for this client, read
// from the sender's .json records; each row opens the message at /email.
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
	end := today(s.now())
	page := &outboxPage{
		From: end.AddDate(0, 0, 1-outboxDefaultDays).Format(isoDate), To: end.Format(isoDate),
		Recipient: q.Get("recipient"), Subject: q.Get("subject"), SentBy: q.Get("sent_by"),
		MaxSearchDays: s.settings.MaxDatePrefixDays,
	}
	if p, ok := s.auth.(*centralProvider); ok {
		page.CSRFToken = p.csrfToken(r)
	}
	if raw := q.Get("date_from"); raw != "" {
		page.From = raw
	}
	if raw := q.Get("date_to"); raw != "" {
		page.To = raw
	}
	from, errFrom := parseDay(page.From)
	to, errTo := parseDay(page.To)
	window := ordered(from, to)
	switch {
	case errFrom != nil || errTo != nil:
		page.Error = "Invalid date. Use YYYY-MM-DD."
	case int(window.End.Sub(window.Start).Hours()/24)+1 > s.settings.MaxDatePrefixDays:
		page.Error = "Keep the window at or under " + strconv.Itoa(s.settings.MaxDatePrefixDays) + " days."
	default:
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.settings.SearchJobMaxSeconds)*time.Second)
		defer cancel()
		records, stats, err := s.outbox.Search(ctx, window.Start, window.End.Add(24*time.Hour-time.Nanosecond),
			archive.OutboxQuery{Recipient: page.Recipient, Subject: page.Subject, SentBy: page.SentBy, Limit: 500})
		if err != nil {
			slog.Warn("outbox search", "err", err)
			page.Error = "The Outbox could not be read. Try again, or narrow the dates."
			break
		}
		page.Searched, page.Scanned, page.Unreadable, page.Truncated = true, stats.Scanned, stats.Unreadable, stats.Truncated
		for _, rec := range records {
			subject := rec.Subject
			if subject == "" {
				subject = "(no subject)"
			}
			page.Rows = append(page.Rows, outboxRow{SentRecord: rec, SubjectOrPlaceholder: subject,
				ToLine: strings.Join(rec.To, ", ")})
		}
	}
	s.render(w, r, http.StatusOK, "outbox", page)
}
