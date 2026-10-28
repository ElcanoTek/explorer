// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
)

// The email:read operations: one message by s3_key, its links and the link
// cache, and signed download links. Files never pass through the model:
// get_download_link mints a 15-minute, bearer-free URL that Fleet's
// download_url tool fetches straight into the workspace.

// s3KeyArg reads and bounds the s3_key argument: inside the archive prefix
// (the boundary the web UI enforces too), never in the link cache, no
// control characters, at most 1024 bytes.
func (a *API) s3KeyArg(args map[string]any) (string, error) {
	key, err := optString(args, "s3_key")
	if err != nil {
		return "", err
	}
	if !a.allowedEmailKey(key) {
		return "", apiErr(http.StatusNotFound, "not_found",
			"Unknown email key %q: pass an s3_key returned by search_emails or find_latest_report.", key)
	}
	return key, nil
}

func (a *API) allowedEmailKey(key string) bool {
	if key == "" || len(key) > 1024 || strings.ContainsFunc(key, func(r rune) bool { return r < 32 || r == 127 }) {
		return false
	}
	if a.settings.ArchivePrefix != "" && strings.HasPrefix(key, a.settings.ArchivePrefix) {
		return false
	}
	roots := a.settings.AllowedKeyRoots()
	if len(roots) == 0 {
		return true
	}
	for _, root := range roots {
		if strings.HasPrefix(key, root) {
			return true
		}
	}
	return false
}

func (a *API) readError(op string, err error) error {
	if errors.Is(err, archive.ErrNoSuchKey) {
		return apiErr(http.StatusNotFound, "not_found", "No email with that s3_key exists.")
	}
	if errors.Is(err, archive.ErrTooLarge) {
		return apiErr(http.StatusRequestEntityTooLarge, "too_large", "That message is larger than Explorer will read.")
	}
	return a.archiveError(op, err)
}

func cacheBody(l archive.ManifestLink) Body {
	b := Body{"status": l.Status, "cached": l.Cached()}
	if l.Cached() {
		name := l.Filename
		if name == "" {
			name = path.Base(l.ArchiveKey)
		}
		b["filename"] = name
		if l.Size > 0 {
			b["size_bytes"] = l.Size
		}
	}
	return b
}

func linkBodies(e *archive.AgentEmail) []Body {
	out := make([]Body, 0, len(e.Links))
	for _, l := range e.Links {
		b := Body{"url": l.URL, "is_click_tracker": l.IsClickTracker}
		if l.Filename != "" {
			b["filename"] = l.Filename
		}
		if l.LinkText != "" {
			b["link_text"] = l.LinkText
		}
		switch {
		case l.HasCache:
			b["cache"] = cacheBody(l.Cache)
		case e.Manifest != nil:
			b["cache"] = Body{"status": "not_in_manifest", "cached": false}
		default:
			b["cache"] = Body{"status": "no_manifest", "cached": false}
		}
		out = append(out, b)
	}
	return out
}

func manifestState(e *archive.AgentEmail) Body {
	switch {
	case e.Manifest != nil:
		return Body{"status": "present", "manifest_key": e.ManifestKey, "processed_at": e.Manifest.ProcessedAt,
			"links_found": e.Manifest.LinksFound, "download_candidates": e.Manifest.Candidates,
			"archived": e.Manifest.Archived, "truncated_over_cap": e.Manifest.Truncated}
	case e.ManifestExpectedButAbsent:
		return Body{"status": "absent", "manifest_key": e.ManifestKey,
			"message": "The link archiver has no record of this email (it may still be processing, or it predates the archiver)."}
	default:
		return Body{"status": "not_applicable",
			"message": "This key is not a date-partitioned email the link archiver processes."}
	}
}

// GetEmail is get_email.
func (a *API) GetEmail(r *http.Request, _ *apitoken.Token, args map[string]any) (Body, error) {
	key, err := a.s3KeyArg(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	e, err := a.inbox.ReadAgentEmail(ctx, key)
	if err != nil {
		return nil, a.readError("get_email", err)
	}
	attachments := make([]Body, len(e.Attachments))
	for i, att := range e.Attachments {
		attachments[i] = Body{"filename": att.Filename, "content_type": att.ContentType, "size_bytes": att.SizeBytes}
	}
	return Body{
		"status": "success", "s3_key": e.S3Key, "subject": e.Subject, "from": e.From, "to": e.To, "cc": e.Cc,
		"date": e.Date, "message_id": e.MessageID, "sender_authenticated": e.SenderAuthenticated,
		"attachments": attachments, "attachment_count": len(attachments),
		"body_text": e.BodyText, "body_truncated": e.BodyTruncated,
		"download_links": linkBodies(e), "link_cache": manifestState(e),
	}, nil
}

// ExtractDownloadLinks is extract_download_links: the download-likely links
// of one email with their cache state.
func (a *API) ExtractDownloadLinks(r *http.Request, _ *apitoken.Token, args map[string]any) (Body, error) {
	key, err := a.s3KeyArg(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	e, err := a.inbox.ReadAgentEmail(ctx, key)
	if err != nil {
		return nil, a.readError("extract_download_links", err)
	}
	links := linkBodies(e)
	return Body{"status": "success", "s3_key": key, "subject": e.Subject, "link_count": len(links),
		"download_links": links, "link_cache": manifestState(e)}, nil
}

// ListArchivedAttachments is list_archived_attachments: the link
// archiver's manifest for one email, as it wrote it.
func (a *API) ListArchivedAttachments(r *http.Request, _ *apitoken.Token, args map[string]any) (Body, error) {
	key, err := a.s3KeyArg(args)
	if err != nil {
		return nil, err
	}
	manifestKey, ok := a.inbox.ManifestKey(key)
	if !ok {
		return nil, invalidArg("Could not derive a date partition from this key; expected a key like emails/YYYY/MM/DD/<messageId>.")
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	m, err := a.inbox.ReadManifest(ctx, key)
	if err != nil {
		return nil, a.readError("list_archived_attachments", err)
	}
	if m == nil {
		return Body{"status": "not_found", "s3_key": key, "manifest_key": manifestKey,
			"message": "No link-archive manifest for this email: it predates the link archiver or archiving has not run yet. " +
				"get_download_link still returns its live links."}, nil
	}
	out := Body{}
	for k, v := range m.Raw {
		out[k] = v
	}
	out["status"], out["s3_key"], out["manifest_key"] = "success", key, manifestKey
	return out, nil
}

// GetDownloadLink is get_download_link: a signed URL for one attachment
// (filename) or one body link (url), preferring the link cache's copy. An
// uncached link comes back as its live URL, which may have expired.
func (a *API) GetDownloadLink(r *http.Request, t *apitoken.Token, args map[string]any) (Body, error) {
	key, err := a.s3KeyArg(args)
	if err != nil {
		return nil, err
	}
	filename, err := optString(args, "filename")
	if err != nil {
		return nil, err
	}
	link, err := optString(args, "url")
	if err != nil {
		return nil, err
	}
	if (filename == "") == (link == "") {
		return nil, invalidArg("Pass exactly one of filename (an attachment from get_email) or url (a download link from get_email).")
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	if filename != "" {
		att, err := a.inbox.Attachment(ctx, key, filename)
		if errors.Is(err, archive.ErrNotFound) {
			return nil, apiErr(http.StatusNotFound, "not_found",
				"No attachment %q in this email; use a filename from get_email's attachments.", filename)
		}
		if err != nil {
			return nil, a.readError("get_download_link", err)
		}
		return a.signed(r, t, apitoken.Download{Kind: "attachment", Key: key, Name: filename},
			Body{"source": "attachment", "filename": safeName(att.Name), "size_bytes": len(att.Data)})
	}
	dl, cached, found, err := a.inbox.FindCachedPayload(ctx, key, link)
	if err != nil {
		return nil, a.readError("get_download_link", err)
	}
	if !found {
		return nil, apiErr(http.StatusNotFound, "not_found",
			"That url is not a download link of this email; use a url from get_email's download_links.")
	}
	if cached == nil {
		return Body{
			"source": "live", "download_url": dl.FetchURL, "cached": false,
			"message": "The link archiver holds no copy of this link, so this is the live link from the email. " +
				"Report links often expire about 48 hours after delivery; if download_url fails, the file is gone.",
		}, nil
	}
	extra := Body{"source": "cached", "cached": true, "filename": safeName(cached.Filename), "original_url": dl.URL}
	if cached.Size > 0 {
		extra["size_bytes"] = cached.Size
	}
	return a.signed(r, t, apitoken.Download{Kind: "cached", Key: cached.Key, Name: cached.Filename}, extra)
}

func (a *API) signed(r *http.Request, t *apitoken.Token, d apitoken.Download, extra Body) (Body, error) {
	ticket, expires, err := a.tokens.SignDownload(r.Context(), t, d)
	if err != nil {
		return nil, err
	}
	out := Body{
		"download_url": a.publicBaseURL(r) + "/api/v1/download?ticket=" + ticket,
		"expires_at":   time.Unix(expires, 0).UTC().Format(time.RFC3339),
		"message":      "Fetch download_url with the download_url tool within 15 minutes; it needs no token.",
	}
	for k, v := range extra {
		out[k] = v
	}
	return out, nil
}

// publicBaseURL is EXPLORER_PUBLIC_URL, or this request's origin as the
// loopback proxy forwarded it.
func (a *API) publicBaseURL(r *http.Request) string {
	if u := strings.TrimRight(strings.TrimSpace(a.settings.PublicURL), "/"); u != "" {
		return u
	}
	scheme := "https"
	if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p == "http" || p == "https" {
		scheme = p
	} else if r.TLS == nil && (strings.HasPrefix(r.Host, "127.0.0.1") || strings.HasPrefix(r.Host, "localhost")) {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func safeName(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == "/" || name == "" || name == ".." {
		return "download"
	}
	return name
}

// DownloadMaxDuration bounds one cached-payload transfer: 450 MB at about
// 1 Mbit/s.
const DownloadMaxDuration = time.Hour

// ServeDownload is GET /api/v1/download?ticket=…: bearer-free (the ticket
// is the credential), always served as an opaque, sandboxed download.
func (a *API) ServeDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.WriteError(w, apiErr(http.StatusMethodNotAllowed, "method_not_allowed", "Use GET"))
		return
	}
	_, d, err := a.tokens.VerifyDownload(r.Context(), r.URL.Query().Get("ticket"))
	if err != nil {
		var te *apitoken.TokenError
		if errors.As(err, &te) {
			a.WriteError(w, apiErr(http.StatusUnauthorized, "unauthorized", "%s", te.Error()))
			return
		}
		a.WriteError(w, err)
		return
	}
	ctx, cancel := a.withDeadline(r)
	defer cancel()
	header := func(name string, size int64) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": safeName(name)}))
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "private, no-store")
		if size > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		}
	}
	switch d.Kind {
	case "attachment":
		if !a.allowedEmailKey(d.Key) {
			a.WriteError(w, apiErr(http.StatusNotFound, "not_found", "Not found"))
			return
		}
		att, err := a.inbox.Attachment(ctx, d.Key, d.Name)
		if err != nil {
			if errors.Is(err, archive.ErrNotFound) {
				a.WriteError(w, apiErr(http.StatusNotFound, "not_found", "That attachment is no longer in the message."))
				return
			}
			a.WriteError(w, a.readError("download", err))
			return
		}
		header(att.Name, int64(len(att.Data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(att.Data)
	case "cached":
		// A cached payload can be hundreds of MB: the transfer runs on the
		// request's own context, not the API operation deadline, and gets a
		// download-sized write deadline instead of the server-wide one.
		st, err := a.inbox.OpenCached(r.Context(), d.Key)
		if err != nil {
			if errors.Is(err, archive.ErrNotFound) || errors.Is(err, archive.ErrNoSuchKey) {
				a.WriteError(w, apiErr(http.StatusNotFound, "not_found", "That cached file no longer exists."))
				return
			}
			a.WriteError(w, a.readError("download", err))
			return
		}
		defer st.Body.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(a.now().Add(DownloadMaxDuration))
		header(d.Name, st.Size)
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, st.Body); err != nil {
			a.log.Warn("cached download interrupted", "err", fmt.Sprint(err))
		}
	}
}
