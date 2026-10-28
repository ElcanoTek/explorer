// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"io"
	"strings"
	"testing"
)

// A report email as vendors send them: the download link in an HTML anchor
// whose href carries an HTML-escaped query separator and whose text is
// wrapped in markup.
const escapedHref = "https://reports.vendor.example/dl?id=1&amp;sig=abc"

func reportMail(body string) []byte {
	return []byte("Authentication-Results: " + passAuth + "\r\nFrom: <reports@vendor.example>\r\nTo: inbox@example.com\r\n" +
		"Subject: Daily report\r\nDate: " + agentDate + "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + body + "\r\n")
}

func TestURLHashIsTheArchiverHash(t *testing.T) {
	// hashlib.sha256(url.encode()).hexdigest() of the URL as extracted:
	// the &amp; stays escaped (ses_email_link_archiver.py's hash contract).
	if got := URLHash(escapedHref); got != "dec3b2355096902191aa1b6ca3554b331de5caee278f9661d480f2e713e6665b" {
		t.Fatalf("URLHash = %s", got)
	}
	links := downloadLinks("", `<p><a class="btn" href="`+escapedHref+`"><span>Download</span> <b>CSV</b></a></p>`)
	if len(links) != 1 || links[0].URL != escapedHref || links[0].FetchURL != "https://reports.vendor.example/dl?id=1&sig=abc" ||
		links[0].LinkText != "Download CSV" {
		t.Fatalf("links: %+v", links)
	}
}

func TestManifestKey(t *testing.T) {
	in := New(newFake(nil), agentSettings(t, nil))
	if k, ok := in.ManifestKey("emails/2026/06/01/abc123"); !ok || k != "emails/attachments/manifests/2026/06/01/abc123.json" {
		t.Fatalf("key %q %v", k, ok)
	}
	for _, key := range []string{"emails/raw/abc", "emails/2026/06/01/sub/abc", "other/2026/06/01/abc"} {
		if _, ok := in.ManifestKey(key); ok {
			t.Errorf("%s has no manifest", key)
		}
	}
}

func TestCachedLinksResolveThroughTheManifestOrTheHash(t *testing.T) {
	const email = agentDay + "msg1"
	cachedKey := "emails/attachments/by-url/" + URLHash(escapedHref) + "/report.csv"
	liveURL := "https://other.vendor.example/export?format=csv"
	hashOnlyURL := "https://third.vendor.example/files/weekly.xlsx"
	hashOnlyKey := "emails/attachments/by-url/" + URLHash(hashOnlyURL) + "/weekly.xlsx"
	store := newFake(map[string][]byte{
		email: reportMail(`<a href="` + escapedHref + `">CSV</a> <a href="` + liveURL + `">live</a> ` +
			`<a href="` + hashOnlyURL + `">xlsx</a>`),
		"emails/attachments/manifests/2026/06/01/msg1.json": []byte(`{"processed_at":"2026-06-01T12:05:00+00:00","archived":1,` +
			`"links":[{"url":"` + escapedHref + `","sha256":"` + URLHash(escapedHref) + `","status":"archived",` +
			`"archive_key":"` + cachedKey + `","filename":"report.csv","size":7},` +
			`{"url":"` + liveURL + `","status":"failed_http_404"}]}`),
		cachedKey:   []byte("a,b\n1,2"),
		hashOnlyKey: []byte("xlsx"),
	})
	in := New(store, agentSettings(t, nil))
	ctx := context.Background()

	e, err := in.ReadAgentEmail(ctx, email)
	if err != nil || e.Manifest == nil || len(e.Links) != 3 {
		t.Fatalf("email: %+v %v", e, err)
	}
	if !e.Links[0].HasCache || !e.Links[0].Cache.Cached() || e.Links[1].Cache.Status != "failed_http_404" || e.Links[2].HasCache {
		t.Fatalf("cache states: %+v", e.Links)
	}

	// Through the manifest, by either form of the URL.
	for _, u := range []string{escapedHref, "https://reports.vendor.example/dl?id=1&sig=abc"} {
		_, obj, found, err := in.FindCachedPayload(ctx, email, u)
		if err != nil || !found || obj == nil || obj.Key != cachedKey || obj.Filename != "report.csv" {
			t.Fatalf("%s: %+v %v %v", u, obj, found, err)
		}
	}
	// Not in the manifest, but cached under the hash contract.
	_, obj, found, err := in.FindCachedPayload(ctx, email, hashOnlyURL)
	if err != nil || !found || obj == nil || obj.Key != hashOnlyKey {
		t.Fatalf("hash fallback: %+v %v %v", obj, found, err)
	}
	// Failed to archive: the live link, uncached.
	link, obj, found, err := in.FindCachedPayload(ctx, email, liveURL)
	if err != nil || !found || obj != nil || link.FetchURL != liveURL {
		t.Fatalf("live: %+v %+v %v %v", link, obj, found, err)
	}
	// Not a link of this email.
	if _, _, found, err := in.FindCachedPayload(ctx, email, "https://evil.example/x.csv"); found || err != nil {
		t.Fatalf("foreign url found=%v err=%v", found, err)
	}

	st, err := in.OpenCached(ctx, cachedKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(st.Body)
	if string(data) != "a,b\n1,2" {
		t.Fatalf("payload %q", data)
	}
	if _, err := in.OpenCached(ctx, email); err == nil {
		t.Fatal("OpenCached must refuse keys outside the link cache")
	}
}

func TestAnEmailWithoutAManifestStillLists(t *testing.T) {
	store := newFake(map[string][]byte{agentDay + "m": reportMail(`<a href="https://vendor.example/r.csv">r</a>`)})
	in := New(store, agentSettings(t, nil))
	e, err := in.ReadAgentEmail(context.Background(), agentDay+"m")
	if err != nil || e.Manifest != nil || !e.ManifestExpectedButAbsent || len(e.Links) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestFuzzyBodySearchReadsHTMLOnlyBodiesAndCountsUncheckedMail(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "html":   reportMail("<p>Weekly pacing numbers</p>"),
		agentDay + "forged": []byte(strings.Replace(string(reportMail("<p>pacing</p>")), "Authentication-Results: "+passAuth+"\r\n", "", 1)),
	})
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	got, stats, err := in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"pacing"}, Body: true, From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 || got[0].S3Key != agentDay+"html" || stats.UnauthenticatedUnchecked != 1 {
		t.Fatalf("got %v stats %+v err %v", keys(got), stats, err)
	}
}

func TestAnUnnamedAttachmentIsAPayload(t *testing.T) {
	mail := "Authentication-Results: " + passAuth + "\r\nFrom: <a@vendor.example>\r\nSubject: R\r\nDate: " + agentDate +
		"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
		"--XX\r\nContent-Type: text/csv\r\nContent-Disposition: attachment\r\n\r\na,b\r\n--XX--\r\n"
	in := New(newFake(map[string][]byte{agentDay + "u": []byte(mail)}), agentSettings(t, nil))
	from, to := oneAgentDay()
	yes := true
	got, _, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10, HasPayload: &yes})
	if err != nil || len(got) != 1 || len(got[0].Attachments) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestFuzzyBodySearchReadsTheHTMLAlternativeToo(t *testing.T) {
	mail := "Authentication-Results: " + passAuth + "\r\nFrom: <a@vendor.example>\r\nSubject: R\r\nDate: " + agentDate +
		"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nsee html\r\n" +
		"--XX\r\nContent-Type: text/html\r\n\r\n<p>pacing</p>\r\n--XX--\r\n"
	in := New(newFake(map[string][]byte{agentDay + "m": []byte(mail)}), agentSettings(t, nil))
	from, to := oneAgentDay()
	got, _, err := in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"pacing"}, Body: true, From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", keys(got), err)
	}
}

func TestReportedAttachmentNamesResolve(t *testing.T) {
	mail := "From: <a@vendor.example>\r\nSubject: R\r\nDate: " + agentDate +
		"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
		"--XX\r\nContent-Type: text/csv\r\nContent-Disposition: attachment\r\n\r\na,b\r\n" +
		"--XX\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename=\"weekly   report.csv\"\r\n\r\nc,d\r\n--XX--\r\n"
	in := New(newFake(map[string][]byte{agentDay + "u": []byte(mail)}), agentSettings(t, nil))
	for name, want := range map[string]string{"unknown": "a,b", "weekly report.csv": "c,d"} {
		att, err := in.Attachment(context.Background(), agentDay+"u", name)
		if err != nil || strings.TrimSpace(string(att.Data)) != want {
			t.Fatalf("%s: %v %v", name, att, err)
		}
	}
}

func TestOnlyListedPrefixesAreCounted(t *testing.T) {
	in := New(newFake(map[string][]byte{agentDay + "m": reportMail("<p>x</p>")}), agentSettings(t, nil))
	from, to := oneAgentDay()
	_, stats, err := in.AgentSearch(context.Background(), AgentQuery{From: from.AddDate(0, 0, -9), To: to, MaxResults: 1})
	if err != nil || stats.Prefixes != 1 {
		t.Fatalf("prefixes %d %v", stats.Prefixes, err)
	}
}
