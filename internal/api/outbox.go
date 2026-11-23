// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"net/http"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
)

// DefaultOutboxResults is search_outbox's max_results default.
const DefaultOutboxResults = 50

// SearchOutbox is search_outbox: the email Fleet sent for this client, from
// the Outbox records. Each result's s3_key opens the message with get_email.
func (a *API) SearchOutbox(r *http.Request, _ *apitoken.Token, args map[string]any) (Body, error) {
	if a.outbox == nil {
		return nil, apiErr(http.StatusNotFound, "outbox_off",
			"This Explorer has no Outbox (EMAIL_S3_OUTBOX_PREFIX is empty).")
	}
	var (
		q                archive.OutboxQuery
		dateFrom, dateTo string
		err              error
	)
	for name, dst := range map[string]*string{
		"date_from": &dateFrom, "date_to": &dateTo, "recipient_contains": &q.Recipient,
		"subject_contains": &q.Subject, "sent_by": &q.SentBy,
	} {
		if *dst, err = optString(args, name); err != nil {
			return nil, err
		}
	}
	if q.Limit, err = intUpTo(args, "max_results", DefaultOutboxResults, MaxResults); err != nil {
		return nil, err
	}
	if dateFrom == "" || dateTo == "" {
		return nil, boundedDateError("search_outbox")
	}
	from, to, err := orderedBounds(dateFrom, dateTo)
	if err != nil {
		return nil, err
	}
	if days := windowDays(from, to); days > a.settings.MaxDatePrefixDays {
		return nil, invalidArg("The date window covers %d days; keep a search at or under %d days%s.",
			days, a.settings.MaxDatePrefixDays, fittingWindow(to, a.settings.MaxDatePrefixDays))
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	records, stats, err := a.outbox.Search(ctx, from, to, q)
	if err != nil {
		return nil, a.archiveError("search_outbox", err)
	}
	emails := make([]Body, len(records))
	for i, rec := range records {
		attachments := make([]Body, len(rec.Attachments))
		for j, att := range rec.Attachments {
			attachments[j] = Body{"filename": att.Name, "content_type": att.MIMEType, "size_bytes": att.Size,
				"inline": att.Inline}
		}
		emails[i] = Body{
			"s3_key": rec.EmlKey, "sent_at": rec.SentAt, "subject": rec.Subject, "from": rec.From,
			"to": nonNil(rec.To), "cc": nonNil(rec.Cc), "bcc": nonNil(rec.Bcc), "sent_by": rec.SentBy,
			"task_id": rec.TaskID, "attachments": attachments, "message_id": rec.MessageID,
		}
	}
	a.log.Info("api search_outbox", "scanned", stats.Scanned, "matched", len(records))
	body := Body{
		"status": "success", "matches_found": len(records), "emails_scanned": stats.Scanned,
		"truncated": stats.Truncated, "emails": emails,
		"search_criteria": Body{"date_from": dateFrom, "date_to": dateTo, "recipient_contains": q.Recipient,
			"subject_contains": q.Subject, "sent_by": q.SentBy, "max_results": q.Limit,
			"effective_date_from": isoformat(from), "effective_date_to": isoformat(to)},
	}
	if stats.Unreadable > 0 {
		body["unreadable_records"] = stats.Unreadable
	}
	return body, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
