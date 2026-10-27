// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Download-link detection (the agent search API's has_payload filter).
//
// Vendors split roughly evenly between attaching report files and putting a
// download link in the body, so "has a payload" means an attachment OR a
// link the classifier calls download-likely. This is the Go port of the
// bundles' classify_url; the bundle tools that actually fetch links keep
// their own copy, so a change here must be made there too.

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
	textURLRE     = regexp.MustCompile(`https?://[^\s<>"')\]}>]*(?:=[\r\n]+[^\s<>"')\]}>]*)*`)
	htmlLinkRE    = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)</a>`)
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
		if strings.HasPrefix(m[1], "http://") || strings.HasPrefix(m[1], "https://") {
			out = append(out, bodyLink{cleanURL(m[1]), strings.TrimSpace(m[2])})
		}
	}
	return out
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

// DownloadLink is a body link classified as a likely payload.
type DownloadLink struct {
	URL            string `json:"url"`
	Filename       string `json:"filename,omitempty"`
	LinkText       string `json:"link_text,omitempty"`
	IsClickTracker bool   `json:"is_click_tracker"`
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

// downloadLinks lists the distinct likely-payload links of a body: HTML
// anchors, then plain-text URLs, then URLs in the HTML outside anchors.
func downloadLinks(plain, html string) []DownloadLink {
	seen := map[string]bool{}
	var out []DownloadLink
	record := func(raw, text string) {
		cleaned, filename, likely, tracker := classifyURL(raw)
		if seen[cleaned] {
			return
		}
		seen[cleaned] = true
		if likely {
			out = append(out, DownloadLink{URL: cleaned, Filename: filename, LinkText: text, IsClickTracker: tracker})
		}
	}
	if html != "" {
		for _, l := range extractHTMLLinks(html) {
			record(l.url, l.text)
		}
	}
	if plain != "" {
		for _, u := range extractTextURLs(plain) {
			record(u, "")
		}
	}
	if html != "" {
		for _, u := range extractTextURLs(html) {
			record(u, "")
		}
	}
	return out
}
