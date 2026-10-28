// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"crypto/sha256"
	"encoding/hex"
	stdhtml "html"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/ElcanoTek/explorer/internal/mailmsg"
)

// Download-link detection (the agent API's has_payload filter and the links
// get_email reports).
//
// Vendors split roughly evenly between attaching report files and putting a
// download link in the body, so "has a payload" means an attachment OR a
// link the classifier calls download-likely. This is the Go port of the
// link archiver's classify_url (ElcanoTek/production-support
// ses-s3/lambdas/ses_email_link_archiver.py).
//
// Hash contract: the archiver caches each download-likely link's payload at
// <EMAIL_S3_ARCHIVE_PREFIX>by-url/<sha256(url)>/<filename>, where url is the
// string exactly as it extracts it from the body (outer wrapper, after
// clean_url, &amp; NOT decoded). Extraction here mirrors it (all text/plain
// parts' URLs, then all text/html parts' anchors) so the url a caller is
// given hashes to the cached copy.

var downloadExtensions = setOf(
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt",
	".csv", ".json", ".xml", ".yaml", ".yml",
	".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
	".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp",
	".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
	".py", ".js", ".ts", ".html", ".css", ".sql",
	".exe", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
)

// imageExtensions are banners, logos and tracking pixels, never a report.
var imageExtensions = setOf(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico")

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// clickTrackerPatterns are email-marketing click redirectors (host suffix,
// path substring): they hide the target's extension but are often the only
// path to the payload.
var clickTrackerPatterns = [][2]string{
	{"sendgrid.net", "/ls/click"}, {"sendgrid.net", "/wf/click"},
	{"list-manage.com", "/track/click"}, {"mailchimp.com", "/track/click"},
	{"hubspotlinks.com", ""}, {"hs-sites.com", "/e1t/c/"},
	{"iterable.com", "/api/email/click"}, {"links.iterable.com", ""},
	{"mkt.com", "/trk"}, {"eloqua.com", "/e/er"}, {"pardot.com", "/e/"},
	{"exct.net", ""}, {"exacttarget.com", ""}, {"pstmrk.it", ""},
	{"", "/ls/click"}, {"", "/wf/click"}, {"", "/track/click"},
}

var junkHostSuffixes = []string{
	"advertising.amazon.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
	"calendly.com", "calendar.google.com", "zoom.us", "youtube.com", "vimeo.com",
}

var (
	lineContRE    = regexp.MustCompile(`=[\r\n]+`)
	textURLRE     = regexp.MustCompile(`(?i)https?://[^\s<>"')\]}>]*(?:=[\r\n]+[^\s<>"')\]}>]*)*`)
	htmlLinkRE    = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref=["']([^"']+)["'][^>]*>(.*?)</a\s*>`)
	tagRE         = regexp.MustCompile(`<[^>]*>`)
	unsubscribeRE = regexp.MustCompile(`(?i)unsubscribe|opt[-_]?out|email[-_]?preferences|manage[-_]?preferences`)
	proofpointV3  = regexp.MustCompile(`/v3/__(.+?)__;`)
)

var downloadKeywords = []string{
	"download", "attachment", "file", "export", "get", "report", "generate", "csv", "xlsx", "pdf",
	"api/download", "api/export", "api/report",
}

var downloadParams = []string{
	"format=csv", "format=xlsx", "format=pdf", "type=csv", "fmt=csv", "fmt=xls", "fmt=xlsx", "fmt=pdf",
	"export=", "download=", "action=download", "action=export",
}

func cleanURL(u string) string {
	u = lineContRE.ReplaceAllString(u, "")
	u = strings.NewReplacer("\n", "", "\r", "").Replace(u)
	return strings.TrimRight(strings.TrimSpace(u), ".,;:!?")
}

func extractTextURLs(text string) []string {
	var out []string
	for _, u := range textURLRE.FindAllString(text, -1) {
		if u = cleanURL(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

type bodyLink struct{ url, text string }

func extractHTMLLinks(html string) []bodyLink {
	var out []bodyLink
	for _, m := range htmlLinkRE.FindAllStringSubmatch(html, -1) {
		href := strings.TrimSpace(m[1])
		if lower := strings.ToLower(href); strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			text := strings.Join(strings.Fields(tagRE.ReplaceAllString(m[2], " ")), " ")
			out = append(out, bodyLink{cleanURL(href), text})
		}
	}
	return out
}

// allBodies joins every non-attachment text/plain part and every
// text/html part, as the archiver does.
func allBodies(msg *mailmsg.Part) (plain, html string) {
	var plains, htmls []string
	for _, part := range msg.Walk() {
		if part.MainType() == "multipart" || strings.Contains(strings.ToLower(part.Header.Get("Content-Disposition")), "attachment") {
			continue
		}
		payload, ok := part.Payload()
		if !ok {
			continue
		}
		switch part.ContentType() {
		case "text/plain":
			plains = append(plains, mailmsg.DecodeBytes(payload, part.Charset()))
		case "text/html":
			htmls = append(htmls, mailmsg.DecodeBytes(payload, part.Charset()))
		}
	}
	return strings.Join(plains, "\n"), strings.Join(htmls, "\n")
}

func parsedURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func isClickTracker(raw string) bool {
	u := parsedURL(raw)
	host, p := strings.ToLower(u.Host), strings.ToLower(u.Path)
	for _, pat := range clickTrackerPatterns {
		hostOK := pat[0] == "" || host == pat[0] || strings.HasSuffix(host, "."+pat[0])
		pathOK := pat[1] == "" || strings.Contains(p, pat[1])
		if (pat[0] != "" || pat[1] != "") && hostOK && pathOK {
			return true
		}
	}
	return false
}

func hasHTTPScheme(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// unwrapOnce peels one known redirector/security wrapper (Proofpoint v2/v3,
// Amazon Ads CL0, awstrack L0), or returns "".
func unwrapOnce(raw string) string {
	u := parsedURL(raw)
	host := strings.ToLower(u.Host)
	if strings.Contains(host, "urldefense.proofpoint.com") && strings.Contains(u.Path, "/v2/url") {
		if enc := u.Query().Get("u"); enc != "" {
			return unquote(strings.ReplaceAll(strings.ReplaceAll(enc, "_", "/"), "-", "%"))
		}
	}
	if strings.Contains(host, "urldefense.com") || strings.Contains(host, "urldefense.proofpoint.com") {
		if m := proofpointV3.FindStringSubmatch(raw); m != nil {
			return m[1]
		}
	}
	marker := ""
	switch {
	case strings.HasSuffix(host, "r.ads.amazon.com"):
		marker = "/CL0/"
	case strings.HasSuffix(host, "awstrack.me"):
		marker = "/L0/"
	}
	if marker != "" {
		if i := strings.Index(raw, marker); i >= 0 {
			seg, _, _ := strings.Cut(raw[i+len(marker):], "/")
			if inner := unquote(seg); hasHTTPScheme(inner) {
				return inner
			}
		}
	}
	return ""
}

func unwrapURL(raw string) string {
	current := raw
	for range 3 {
		inner := unwrapOnce(current)
		if inner == "" || !hasHTTPScheme(inner) {
			return current
		}
		current = cleanURL(inner)
	}
	return current
}

func isPresigned(u *url.URL) bool {
	q := strings.ToLower(u.RawQuery)
	if strings.Contains(q, "x-amz-signature") || strings.Contains(q, "x-amz-credential") || strings.Contains(q, "x-goog-signature") {
		return true
	}
	return strings.Contains(strings.ToLower(u.Host), "blob.core.windows.net") && strings.Contains(q, "sig=") && strings.Contains(q, "sv=")
}

func isJunkHost(host string) bool {
	host = strings.ToLower(host)
	for _, s := range junkHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// DownloadLink is a body link classified as a likely payload. URL is the
// string exactly as extracted (the cache key); FetchURL is the same link
// with HTML entities (&amp;) decoded, the form a live request needs.
type DownloadLink struct {
	URL            string `json:"url"`
	FetchURL       string `json:"-"`
	Filename       string `json:"filename,omitempty"`
	LinkText       string `json:"link_text,omitempty"`
	IsClickTracker bool   `json:"is_click_tracker"`
}

// URLHash is the archiver's cache key for url: hex SHA-256 of the exact
// string.
func URLHash(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
}

// classifyURL reports whether raw is a likely download link and its
// cleaned form and filename.
func classifyURL(raw string) (cleaned, filename string, downloadLikely, clickTracker bool) {
	cleaned = cleanURL(raw)
	target := unwrapURL(cleaned)
	u := parsedURL(target)
	p := unquote(u.EscapedPath())
	if p != "" {
		if base := path.Base(p); base != "/" && base != "." {
			filename = base
		}
	}
	ext := strings.ToLower(path.Ext(filename))
	isImage := imageExtensions[ext]
	isDownloadExt := downloadExtensions[ext] && !isImage
	lowerTarget := strings.ToLower(target)
	hasKeyword := false
	for _, kw := range downloadKeywords {
		if strings.Contains(lowerTarget, kw) {
			hasKeyword = true
			break
		}
	}
	query := strings.ToLower(u.RawQuery)
	hasParam := false
	for _, prm := range downloadParams {
		if strings.Contains(query, prm) {
			hasParam = true
			break
		}
	}
	clickTracker = isClickTracker(cleaned) || isClickTracker(target)
	presigned := isPresigned(u)
	unsubscribe := (unsubscribeRE.MatchString(cleaned) || unsubscribeRE.MatchString(target)) && !isDownloadExt && !presigned
	downloadLikely = (isDownloadExt || hasKeyword || hasParam || clickTracker || presigned) &&
		!isImage && !isJunkHost(u.Host) && !unsubscribe
	return cleaned, filename, downloadLikely, clickTracker
}

// bodyURLs lists a body's distinct links in the archiver's order:
// plain-text URLs, then HTML anchors (whose text wins).
func bodyURLs(plain, html string) []bodyLink {
	var out []bodyLink
	index := map[string]int{}
	add := func(l bodyLink) {
		if i, ok := index[l.url]; ok {
			if l.text != "" {
				out[i].text = l.text
			}
			return
		}
		index[l.url] = len(out)
		out = append(out, l)
	}
	for _, u := range extractTextURLs(plain) {
		add(bodyLink{url: u})
	}
	for _, l := range extractHTMLLinks(html) {
		add(l)
	}
	return out
}

// downloadLinks lists the distinct likely-payload links of a body.
func downloadLinks(plain, html string) []DownloadLink {
	var out []DownloadLink
	for _, l := range bodyURLs(plain, html) {
		cleaned, filename, likely, tracker := classifyURL(l.url)
		if likely {
			out = append(out, DownloadLink{URL: cleaned, FetchURL: stdhtml.UnescapeString(cleaned),
				Filename: filename, LinkText: truncateRunes(l.text, 200), IsClickTracker: tracker})
		}
	}
	return out
}
