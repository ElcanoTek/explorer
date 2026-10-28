// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// Reading one message for the agent API (get_email, extract_download_links,
// list_archived_attachments, get_download_link), and the link cache the
// production-support link archiver keeps beside the mail:
//
//	<archive>by-url/<sha256(url)>/<filename>          cached link payloads, kept forever
//	<archive>manifests/YYYY/MM/DD/<messageId>.json    per-email link outcomes
//
// where <archive> is EMAIL_S3_ARCHIVE_PREFIX (default emails/attachments/)
// and the manifest's date and id come from the email's key
// (emails/YYYY/MM/DD/<messageId>). Report links are presigned or one-shot
// and die after about 48 hours; the archiver fetches them minutes after the
// mail arrives, so the cached copy is what an agent should download.

// maxBodyTextRunes bounds the body text get_email returns.
const maxBodyTextRunes = 6000

// maxManifestBytes bounds a manifest read (15 links per email; a few KB).
const maxManifestBytes = 1 << 20

// ManifestLink is one link of an archiver manifest.
type ManifestLink struct {
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Status     string `json:"status"`
	InnerURL   string `json:"inner_url,omitempty"`
	AnchorText string `json:"anchor_text,omitempty"`
	ArchiveKey string `json:"archive_key,omitempty"`
	Filename   string `json:"filename,omitempty"`
	Size       int64  `json:"size,omitempty"`
}

// Cached reports whether the archiver holds this link's payload.
func (l ManifestLink) Cached() bool {
	return (l.Status == "archived" || l.Status == "already_archived") && l.ArchiveKey != ""
}

// LinkManifest is the archiver's record for one email.
type LinkManifest struct {
	Key string `json:"-"`
	// Raw is the whole manifest as the archiver wrote it.
	Raw         map[string]any `json:"-"`
	ProcessedAt string         `json:"processed_at"`
	LinksFound  int            `json:"links_found"`
	Candidates  int            `json:"download_candidates"`
	Archived    int            `json:"archived"`
	Truncated   int            `json:"truncated_over_cap"`
	Links       []ManifestLink `json:"links"`
}

// partitionedKeyRE matches the archiver's email keys:
// <prefix>YYYY/MM/DD/<messageId>.
var partitionedKeyRE = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2})/([^/]+)$`)

// ManifestKey is the archiver manifest key for an email key, or false when
// the key is not a date-partitioned email the archiver processes.
func (in *Inbox) ManifestKey(emailKey string) (string, bool) {
	if in.s.ArchivePrefix == "" || !strings.HasPrefix(emailKey, in.s.Prefix) {
		return "", false
	}
	m := partitionedKeyRE.FindStringSubmatch(strings.TrimPrefix(emailKey, in.s.Prefix))
	if m == nil {
		return "", false
	}
	return in.s.ArchivePrefix + "manifests/" + m[1] + "/" + m[2] + ".json", true
}

// ReadManifest returns the archiver's manifest for an email, or nil when it
// has none (not processed yet, or not a partitioned email).
func (in *Inbox) ReadManifest(ctx context.Context, emailKey string) (*LinkManifest, error) {
	key, ok := in.ManifestKey(emailKey)
	if !ok {
		return nil, nil
	}
	raw, err := in.store.Get(ctx, key, maxManifestBytes)
	if errors.Is(err, ErrNoSuchKey) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m LinkManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("link manifest %s is not valid JSON: %w", key, err)
	}
	if err := json.Unmarshal(raw, &m.Raw); err != nil {
		return nil, fmt.Errorf("link manifest %s is not a JSON object: %w", key, err)
	}
	m.Key = key
	return &m, nil
}

// EmailLink is a download-likely body link with its cache state.
type EmailLink struct {
	DownloadLink
	// Cache is the archiver's outcome for this link ("" when no manifest
	// names it): archived / already_archived / failed_http_404 / ...
	Cache    ManifestLink
	HasCache bool
}

// AgentEmail is one message as the agent API returns it.
type AgentEmail struct {
	S3Key                     string
	Subject, From, To, Cc     string
	Date, MessageID           string
	SenderAuthenticated       bool
	Attachments               []AttachmentInfo
	BodyText                  string
	BodyTruncated             bool
	Links                     []EmailLink
	Manifest                  *LinkManifest
	ManifestKey               string
	ManifestExpectedButAbsent bool
}

// ReadAgentEmail reads one message, its download links and the archiver's
// manifest for it.
func (in *Inbox) ReadAgentEmail(ctx context.Context, key string) (*AgentEmail, error) {
	raw, err := in.store.Get(ctx, key, 0)
	if err != nil {
		return nil, err
	}
	manifest, err := in.ReadManifest(ctx, key)
	if err != nil {
		return nil, err
	}
	msg := mailmsg.Parse(raw)
	h := in.headersOf(msg.Header)
	plain, html := allBodies(msg)
	text := plain
	if text == "" {
		text = html
	}
	e := &AgentEmail{
		S3Key: key, Subject: h.subject, From: h.from, To: h.to, Date: h.date,
		Cc:                  mailmsg.DecodeHeader(msg.Header.Get("Cc")),
		MessageID:           strings.TrimSpace(msg.Header.Get("Message-ID")),
		SenderAuthenticated: h.authenticated,
		Attachments:         attachmentParts(msg),
		BodyText:            truncateRunes(text, maxBodyTextRunes),
		Manifest:            manifest,
	}
	e.BodyTruncated = len(e.BodyText) < len(text)
	if mk, ok := in.ManifestKey(key); ok {
		e.ManifestKey = mk
		e.ManifestExpectedButAbsent = manifest == nil
	}
	byURL := map[string]ManifestLink{}
	if manifest != nil {
		for _, l := range manifest.Links {
			byURL[l.URL] = l
		}
	}
	for _, l := range downloadLinks(plain, html) {
		el := EmailLink{DownloadLink: l}
		el.Cache, el.HasCache = byURL[l.URL]
		e.Links = append(e.Links, el)
	}
	return e, nil
}

// CachedObject is a link payload the archiver stored.
type CachedObject struct {
	Key      string
	Filename string
	Size     int64
}

// FindCachedPayload resolves url (as given by get_email: the extracted
// form, or its entity-decoded fetch form) to the archiver's cached payload
// for the email at emailKey. The manifest is consulted first; without one
// the hash contract (by-url/<sha256(url)>/) is tried directly. found is
// false when url is not a link of this email; cached is false when it is
// but no copy exists.
func (in *Inbox) FindCachedPayload(ctx context.Context, emailKey, url string) (link DownloadLink, cached *CachedObject, found bool, err error) {
	e, err := in.ReadAgentEmail(ctx, emailKey)
	if err != nil {
		return DownloadLink{}, nil, false, err
	}
	for _, l := range e.Links {
		if l.URL != url && l.FetchURL != url {
			continue
		}
		if l.HasCache && l.Cache.Cached() && strings.HasPrefix(l.Cache.ArchiveKey, in.s.ArchivePrefix+"by-url/") {
			name := l.Cache.Filename
			if name == "" {
				name = pathName(l.Cache.ArchiveKey)
			}
			return l.DownloadLink, &CachedObject{Key: l.Cache.ArchiveKey, Filename: name, Size: l.Cache.Size}, true, nil
		}
		obj, err := in.cachedByHash(ctx, l.URL)
		return l.DownloadLink, obj, true, err
	}
	// A link the manifest names but the extraction here missed (a different
	// MIME decoding): the manifest is the archiver's own record.
	if e.Manifest != nil {
		for _, ml := range e.Manifest.Links {
			if ml.URL != url || !ml.Cached() || !strings.HasPrefix(ml.ArchiveKey, in.s.ArchivePrefix+"by-url/") {
				continue
			}
			link := DownloadLink{URL: ml.URL, FetchURL: ml.URL, LinkText: ml.AnchorText}
			return link, &CachedObject{Key: ml.ArchiveKey, Filename: pathName(ml.ArchiveKey), Size: ml.Size}, true, nil
		}
	}
	return DownloadLink{}, nil, false, nil
}

// cachedByHash lists by-url/<sha256(url)>/ for a payload.
func (in *Inbox) cachedByHash(ctx context.Context, url string) (*CachedObject, error) {
	if in.s.ArchivePrefix == "" {
		return nil, nil
	}
	prefix := in.s.ArchivePrefix + "by-url/" + URLHash(url) + "/"
	page, err := in.store.List(ctx, prefix, "", 10)
	if err != nil {
		return nil, err
	}
	for _, o := range page.Objects {
		if o.Key != prefix {
			return &CachedObject{Key: o.Key, Filename: pathName(o.Key), Size: o.Size}, nil
		}
	}
	return nil, nil
}

// OpenCached streams a cached payload; key must be under the cache.
func (in *Inbox) OpenCached(ctx context.Context, key string) (*ObjectStream, error) {
	if in.s.ArchivePrefix == "" || !strings.HasPrefix(key, in.s.ArchivePrefix+"by-url/") {
		return nil, ErrNotFound
	}
	st, ok := in.store.(Streamer)
	if !ok {
		data, err := in.store.Get(ctx, key, 0)
		if err != nil {
			return nil, err
		}
		return &ObjectStream{Body: nopCloser{strings.NewReader(string(data))}, Size: int64(len(data))}, nil
	}
	return st.Open(ctx, key)
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }
