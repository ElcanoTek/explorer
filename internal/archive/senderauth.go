// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Authenticated senders (the agent search API).
//
// A From header is text anyone can write: "From: reports@vendor.example" on
// mail from anywhere must not be selected as that vendor's report. The
// receiving MTA (SES inbound) records what it verified in an
// Authentication-Results header it PREPENDS, so the topmost header carrying
// its authserv-id (EMAIL_AUTHSERV_ID) is the receiver's verdict; anything
// below it came with the message and is ignored.
//
// This is the Go port of the bundles' ses_s3_email.py sender rules; the
// agent search tools keep their contract (sender_contains, the
// unauthenticated_sender_skipped warning) across the move.

var (
	authMethodRE = regexp.MustCompile(`(?is)^(dmarc|dkim|spf)\s*=\s*([a-z]+)\b(.*)$`)
	authPropRE   = regexp.MustCompile(`(?i)\b(header\.from|header\.d|header\.i|smtp\.mailfrom|smtp\.from|envelope-from)\s*=\s*((?:"(?:[^"\\]|\\.)*"|[^\s;"])+)`)
	ldhLabelRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tldRE        = regexp.MustCompile(`^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)
)

// idnaProfile is IDNA 2008 / UTS 46, non-transitional: "faß.de" is
// xn--fa-hia.de, never fass.de.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false))

// splitResinfo splits an Authentication-Results value on ';' the RFC 8601 /
// 5322 way: never inside a "quoted-string" (backslash escapes honoured) or a
// (comment), which may nest; comments are dropped. A quoted MAIL FROM local
// part such as "x;dmarc=pass;header.from=vendor.example"@attacker.example
// therefore stays one value and cannot inject a verdict.
func splitResinfo(text string) []string {
	var items []string
	var current strings.Builder
	depth := 0
	inQuote, escaped := false, false
	for _, ch := range text {
		switch {
		case escaped:
			if depth == 0 {
				current.WriteRune(ch)
			}
			escaped = false
		case ch == '\\' && (inQuote || depth > 0):
			escaped = true
			if depth == 0 {
				current.WriteRune(ch)
			}
		case inQuote:
			current.WriteRune(ch)
			if ch == '"' {
				inQuote = false
			}
		case ch == '(':
			depth++
		case ch == ')' && depth > 0:
			depth--
		case depth > 0:
		case ch == '"':
			inQuote = true
			current.WriteRune(ch)
		case ch == ';':
			items = append(items, current.String())
			current.Reset()
		default:
			current.WriteRune(ch)
		}
	}
	return append(items, current.String())
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// idnaDomain is domain in its canonical ASCII (A-label) form, lower-cased.
// A domain that cannot be encoded is only lower-cased: it then equals no
// A-label, so it fails closed (no alignment, no keyword match).
func idnaDomain(domain string) string {
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if isASCII(domain) {
		return strings.ToLower(domain)
	}
	if ascii, err := idnaProfile.ToASCII(domain); err == nil {
		return strings.ToLower(ascii)
	}
	return strings.ToLower(domain)
}

// parseMailbox is the address part of a From-style value, leniently (Python's
// email.utils.parseaddr): "Name <a@b>" and "a@b" both give a@b.
func parseMailbox(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(value); err == nil {
		return addr.Address
	}
	if i := strings.LastIndex(value, "<"); i >= 0 {
		if j := strings.Index(value[i:], ">"); j > 0 {
			return strings.TrimSpace(value[i+1 : i+j])
		}
	}
	if !strings.ContainsFunc(value, unicode.IsSpace) {
		return value
	}
	return ""
}

func canonicalMailbox(mailbox string) string {
	mailbox = strings.ToLower(strings.TrimSpace(mailbox))
	i := strings.LastIndex(mailbox, "@")
	if i < 0 {
		return idnaDomain(mailbox)
	}
	return mailbox[:i] + "@" + idnaDomain(mailbox[i+1:])
}

func addressDomain(value string) string {
	address := strings.TrimSpace(value)
	if strings.Contains(value, "<") || strings.ContainsFunc(address, unicode.IsSpace) {
		address = parseMailbox(value)
	}
	if i := strings.LastIndex(address, "@"); i >= 0 {
		address = address[i+1:]
	}
	return idnaDomain(address)
}

type authResult struct {
	method, result string
	domains        []string
}

func propDomains(text string) []string {
	matches := authPropRE.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, addressDomain(m[2]))
	}
	return out
}

// parseAuthResults reads [(method, result, [property domains])] from one
// Authentication-Results value. SES writes a method's properties as further
// ;-separated items, so an item that does not start a method belongs to the
// one before it.
func parseAuthResults(text string) []authResult {
	var found []authResult
	items := splitResinfo(text)
	for _, item := range items[1:] {
		item = strings.TrimSpace(item)
		if m := authMethodRE.FindStringSubmatch(item); m != nil {
			found = append(found, authResult{strings.ToLower(m[1]), strings.ToLower(m[2]), propDomains(m[3])})
		} else if len(found) > 0 {
			found[len(found)-1].domains = append(found[len(found)-1].domains, propDomains(item)...)
		}
	}
	return found
}

// AuthenticatedSenderDomain is the From domain when the receiver
// authenticated it, else "". Only the topmost Authentication-Results whose
// authserv-id is authservID counts. Accepted: dmarc=pass for the From domain
// (relaxed alignment, decided by the receiver with the real public-suffix
// list), or, only when DMARC is absent or dmarc=none, dkim=pass / spf=pass
// for exactly the From domain. Any other DMARC result is final.
func AuthenticatedSenderDomain(authResults []string, fromHeader, authservID string) string {
	fromDomain := addressDomain(fromHeader)
	if fromDomain == "" {
		return ""
	}
	for _, header := range authResults {
		text := strings.Join(strings.Fields(header), " ")
		authserv := strings.Fields(strings.TrimSpace(splitResinfo(text)[0]))
		if len(authserv) == 0 || strings.ToLower(authserv[0]) != authservID {
			continue
		}
		results := parseAuthResults(text)
		for _, r := range results {
			if r.method == "dmarc" && r.result == "pass" && (len(r.domains) == 0 || contains(r.domains, fromDomain)) {
				return fromDomain
			}
		}
		for _, r := range results {
			if r.method == "dmarc" && r.result != "none" {
				return ""
			}
		}
		for _, r := range results {
			if (r.method == "dkim" || r.method == "spf") && r.result == "pass" && contains(r.domains, fromDomain) {
				return fromDomain
			}
		}
		return "" // only the receiver's own (topmost) verdict counts
	}
	return ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// senderNeedles are the comma-separated sender filter items, lower-cased;
// "@vendor.example" is the domain "vendor.example".
func senderNeedles(filter string) []string {
	var out []string
	for _, item := range strings.Split(filter, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if strings.HasPrefix(item, "@") && strings.Count(item, "@") == 1 {
			item = item[1:]
		}
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// SenderShaped reports whether the WHOLE keyword is a mailbox
// ("reports@vendor.example", "@vendor.example") or a domain name: two or more
// LDH labels whose last is alphabetic or a punycode label. "2.0", "v1.2.3"
// and anything with spaces are not.
func SenderShaped(keyword string) bool {
	k := strings.TrimSpace(keyword)
	if k == "" || strings.ContainsFunc(k, unicode.IsSpace) {
		return false
	}
	domain := k
	if i := strings.LastIndex(k, "@"); i >= 0 {
		domain = k[i+1:]
	}
	if domain == "" {
		return false
	}
	ascii := idnaDomain(domain)
	if !isASCII(ascii) {
		return false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !ldhLabelRE.MatchString(l) {
			return false
		}
	}
	return tldRE.MatchString(labels[len(labels)-1])
}

// MailboxMatches matches one sender filter item against a parsed mailbox: an
// item with "@" must be the whole mailbox; anything else is a DOMAIN, matched
// as the mailbox domain or a subdomain of it (so "ssp.example" matches
// reports@mail.ssp.example, never notssp.example or
// ssp.example.evil.example).
func MailboxMatches(needle, mailbox string) bool {
	mailbox = canonicalMailbox(mailbox)
	if strings.Contains(needle, "@") {
		return mailbox == canonicalMailbox(needle)
	}
	needle = idnaDomain(needle)
	domain := mailbox
	if i := strings.LastIndex(mailbox, "@"); i >= 0 {
		domain = mailbox[i+1:]
	}
	return domain != "" && needle != "" && (domain == needle || strings.HasSuffix(domain, "."+needle))
}

// IgnoredSenderEntries are the sender filter items that are neither a full
// mailbox nor a multi-label domain, which the authenticated match ignores.
func IgnoredSenderEntries(filter string) []string {
	var out []string
	for _, n := range senderNeedles(filter) {
		if !SenderShaped(n) {
			out = append(out, n)
		}
	}
	return out
}

// senderFilterMatches reports whether filter selects mail From fromHeader:
// the parsed From MAILBOX (never the display name) must match a usable
// filter item. With authOff it is the legacy substring match on the whole
// header.
func senderFilterMatches(filter, fromHeader string, authOff bool) bool {
	needles := senderNeedles(filter)
	if authOff {
		header := strings.ToLower(fromHeader)
		for _, n := range needles {
			if strings.Contains(header, n) {
				return true
			}
		}
		return false
	}
	mailbox := strings.ToLower(parseMailbox(fromHeader))
	if mailbox == "" {
		return false
	}
	for _, n := range needles {
		if SenderShaped(n) && MailboxMatches(n, mailbox) {
			return true
		}
	}
	return false
}
