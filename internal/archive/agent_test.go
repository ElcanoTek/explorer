// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/config"
)

const (
	passAuth  = "amazonses.com; spf=pass smtp.mailfrom=vendor.example; dmarc=pass header.from=vendor.example"
	agentDay  = "emails/2026/06/01/"
	agentDate = "Mon, 01 Jun 2026 10:00:00 +0000"
)

type mailSpec struct {
	from, auth, subject, to, date, body string
	attachment                          string // filename of a CSV attachment
}

func buildMail(m mailSpec) []byte {
	if m.subject == "" {
		m.subject = "Daily report"
	}
	if m.to == "" {
		m.to = "inbox@example.com"
	}
	if m.date == "" {
		m.date = agentDate
	}
	if m.body == "" {
		m.body = "Hello."
	}
	var b strings.Builder
	if m.auth != "" {
		b.WriteString("Authentication-Results: " + m.auth + "\r\n")
	}
	b.WriteString("From: Reports <" + m.from + ">\r\nTo: " + m.to + "\r\nSubject: " + m.subject + "\r\nDate: " + m.date + "\r\n")
	if m.attachment == "" {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n" + m.body + "\r\n")
		return []byte(b.String())
	}
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n")
	b.WriteString("--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + m.body + "\r\n")
	b.WriteString("--XX\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename=\"" + m.attachment + "\"\r\n\r\na,b\r\n1,2\r\n")
	b.WriteString("--XX--\r\n")
	return []byte(b.String())
}

func agentSettings(t *testing.T, extra map[string]string) config.Settings {
	t.Helper()
	env := map[string]string{"EMAIL_S3_BUCKET": "test-bucket"}
	for k, v := range extra {
		env[k] = v
	}
	s, err := config.FromEnv(env)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func oneAgentDay() (time.Time, time.Time) {
	return day, day.Add(24*time.Hour - time.Microsecond)
}

func keys(ms []AgentMatch) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.S3Key
	}
	return out
}

func TestAuthenticatedSenderDomain(t *testing.T) {
	from := "Reports <reports@vendor.example>"
	cases := []struct {
		name    string
		results []string
		want    string
	}{
		{"dmarc pass", []string{passAuth}, "vendor.example"},
		{"other authserv-id is ignored", []string{"evil.example; dmarc=pass header.from=vendor.example"}, ""},
		{"only the topmost receiver header counts", []string{"amazonses.com; dmarc=fail header.from=vendor.example", passAuth}, ""},
		{"dmarc fail is final over spf pass", []string{"amazonses.com; spf=pass smtp.mailfrom=vendor.example; dmarc=fail header.from=vendor.example"}, ""},
		{"aligned spf without dmarc", []string{"amazonses.com; spf=pass smtp.mailfrom=vendor.example"}, "vendor.example"},
		{"spf for a subdomain is not aligned", []string{"amazonses.com; spf=pass smtp.mailfrom=bounce.vendor.example; dmarc=none"}, ""},
		{"dmarc pass for another domain", []string{"amazonses.com; dmarc=pass header.from=other.example"}, ""},
		{"quoted local part cannot inject a verdict", []string{`amazonses.com; spf=fail smtp.mailfrom="x;dmarc=pass;header.from=vendor.example"@attacker.example`}, ""},
		{"comment cannot inject a verdict", []string{"amazonses.com; spf=fail (dmarc=pass header.from=vendor.example) smtp.mailfrom=a@attacker.example"}, ""},
		{"properties in following items", []string{"amazonses.com; spf=pass (comment) client-ip=192.0.2.1; envelope-from=a@vendor.example; dmarc=none"}, "vendor.example"},
	}
	for _, tc := range cases {
		if got := AuthenticatedSenderDomain(tc.results, from, "amazonses.com"); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := AuthenticatedSenderDomain([]string{"amazonses.com; dmarc=pass header.from=xn--bcher-kva.example"},
		"reports@bücher.example", "amazonses.com"); got != "xn--bcher-kva.example" {
		t.Errorf("IDNA From: %q", got)
	}
}

func TestSenderShapedAndMailboxMatches(t *testing.T) {
	for k, want := range map[string]bool{
		"vendor.example": true, "reports@vendor.example": true, "@vendor.example": true, "bücher.example": true,
		"exchange": false, "2.0": false, "v1.2.3": false, "report @ 10am": false, "com": false, "": false,
	} {
		if got := SenderShaped(k); got != want {
			t.Errorf("SenderShaped(%q) = %v, want %v", k, got, want)
		}
	}
	for _, tc := range []struct {
		needle, mailbox string
		want            bool
	}{
		{"ssp.example", "reports@ssp.example", true},
		{"ssp.example", "reports@mail.ssp.example", true},
		{"ssp.example", "reports@notssp.example", false},
		{"ssp.example", "reports@ssp.example.evil.example", false},
		{"ssp.example", "ssp.example@attacker.example", false},
		{"reports@ssp.example", "Reports@SSP.example", true},
		{"reports@ssp.example", "other@ssp.example", false},
	} {
		if got := MailboxMatches(tc.needle, tc.mailbox); got != tc.want {
			t.Errorf("MailboxMatches(%q, %q) = %v", tc.needle, tc.mailbox, got)
		}
	}
}

func TestClassifyURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://reports.vendor.example/files/daily.csv":                         true,
		"https://vendor.example/export?format=csv":                               true,
		"https://cdn.vendor.example/banner.png":                                  false,
		"https://vendor.example/unsubscribe?u=1":                                 false,
		"https://bucket.s3.amazonaws.com/x?X-Amz-Signature=abc":                  true,
		"https://u1.ct.sendgrid.net/ls/click?upn=abc":                            true,
		"https://www.linkedin.com/company/report":                                false,
		"https://vendor.example/about":                                           false,
		"https://example.com/optout_report.csv":                                  true,
		"https://urldefense.proofpoint.com/v2/url?u=https-3A__cdn.example_r.csv": true,
	} {
		if _, _, got, _ := classifyURL(raw); got != want {
			t.Errorf("classifyURL(%q) download-likely = %v, want %v", raw, got, want)
		}
	}
	links := downloadLinks("See https://vendor.example/r.csv.\r\nand https://vendor.example/r.csv",
		`<a href="https://vendor.example/r.csv">CSV</a><a href="https://vendor.example/about">About</a>`)
	if len(links) != 1 || links[0].URL != "https://vendor.example/r.csv" || links[0].LinkText != "CSV" {
		t.Fatalf("links: %+v", links)
	}
}

func TestAgentSearchReturnsOnlyAuthenticatedSendersAndCountsTheRest(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "ok":     buildMail(mailSpec{from: "reports@vendor.example", auth: passAuth}),
		agentDay + "forged": buildMail(mailSpec{from: "reports@vendor.example"}),
		agentDay + "other":  buildMail(mailSpec{from: "news@other.example", auth: "amazonses.com; dmarc=pass header.from=other.example"}),
	})
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	got, stats, err := in.AgentSearch(context.Background(), AgentQuery{SenderContains: "vendor.example", From: from, To: to, MaxResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(got); len(k) != 1 || k[0] != agentDay+"ok" || !got[0].SenderAuthenticated {
		t.Fatalf("matches: %v", k)
	}
	if stats.UnauthenticatedSkipped != 1 || stats.UnauthenticatedUnchecked != 0 || stats.FullFetches != 0 {
		t.Fatalf("stats: %+v", stats)
	}

	// With a payload filter the forged one is left unopened and counted as unchecked.
	yes := true
	store.fullGets = 0
	got, stats, err = in.AgentSearch(context.Background(), AgentQuery{SenderContains: "vendor.example", From: from, To: to, MaxResults: 10, HasPayload: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || stats.UnauthenticatedUnchecked != 1 || stats.UnauthenticatedSkipped != 0 || store.fullGets != 1 {
		t.Fatalf("payload search: %v %+v fullGets=%d", keys(got), stats, store.fullGets)
	}

	// A bare name never matches a sender; the display name is never read.
	got, _, err = in.AgentSearch(context.Background(), AgentQuery{SenderContains: "Reports", From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 0 {
		t.Fatalf("display name matched: %v %v", keys(got), err)
	}

	// EMAIL_SENDER_AUTH=off is the old header substring match.
	off := New(store, agentSettings(t, map[string]string{"EMAIL_SENDER_AUTH": "off"}))
	got, _, err = off.AgentSearch(context.Background(), AgentQuery{SenderContains: "vendor.example", From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 2 {
		t.Fatalf("auth off: %v %v", keys(got), err)
	}
}

func TestAgentSearchPayloadFilter(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "attached": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth, attachment: "daily report.csv"}),
		agentDay + "linked":   buildMail(mailSpec{from: "a@vendor.example", auth: passAuth, body: "Get it: https://vendor.example/files/daily.csv"}),
		agentDay + "none":     buildMail(mailSpec{from: "a@vendor.example", auth: passAuth, body: "Nothing today, see https://vendor.example/about"}),
	})
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	yes, no := true, false
	got, _, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10, HasPayload: &yes})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]AgentMatch{}
	for _, m := range got {
		byKey[m.S3Key] = m
	}
	if len(got) != 2 || len(byKey[agentDay+"attached"].Attachments) != 1 || byKey[agentDay+"attached"].Attachments[0] != "daily report.csv" ||
		len(byKey[agentDay+"linked"].DownloadLinks) != 1 {
		t.Fatalf("has_payload=true: %+v", got)
	}
	got, _, err = in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10, HasPayload: &no})
	if err != nil || len(got) != 1 || got[0].S3Key != agentDay+"none" || !got[0].Opened {
		t.Fatalf("has_payload=false: %v %v", keys(got), err)
	}
}

func TestAgentSearchFailsLoudlyOnS3Errors(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "a": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
		agentDay + "b": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
	})
	store.failKey = agentDay + "b"
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	if _, _, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10}); err == nil {
		t.Fatal("an S3 error must fail the search")
	}
	if _, _, err := in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"daily"}, Subject: true, From: from, To: to, MaxResults: 10}); err == nil {
		t.Fatal("an S3 error must fail the fuzzy search")
	}
}

func TestAgentSearchSkipsEmptyObjectsAndTheLinkArchive(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "ok": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
		agentDay + "AMAZON_SES_SETUP_NOTIFICATION":       {},
		"emails/attachments/2026/06/01/ok/manifest.json": []byte(`{}`),
	})
	s := agentSettings(t, map[string]string{"EMAIL_S3_DATE_PREFIX_FORMAT": "emails/%Y/%m/%d/"})
	in := New(store, s)
	from, to := oneAgentDay()
	got, stats, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 || stats.ParseErrors != 1 {
		t.Fatalf("got %v stats %+v err %v", keys(got), stats, err)
	}
	// Root scan (no partitions): the link archive under the prefix is skipped.
	root := New(store, agentSettings(t, map[string]string{"EMAIL_S3_DATE_PREFIX_FORMAT": ""}))
	got, _, err = root.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 || got[0].S3Key != agentDay+"ok" {
		t.Fatalf("root scan: %v %v", keys(got), err)
	}
}

func TestADayPartitionIsAuthoritativeForItsDay(t *testing.T) {
	store := newFake(map[string][]byte{agentDay + "late": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth})})
	// Copied into its partition just after midnight.
	store.objects[agentDay+"late"] = fakeObj{data: store.objects[agentDay+"late"].data, modified: day.Add(24*time.Hour + time.Minute)}
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	got, _, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("partition object lost: %v %v", keys(got), err)
	}
}

func TestAWindowThatCutsADayShortChecksLastModified(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "morning": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
		agentDay + "evening": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
	})
	store.objects[agentDay+"morning"] = fakeObj{data: store.objects[agentDay+"morning"].data, modified: day.Add(9 * time.Hour)}
	store.objects[agentDay+"evening"] = fakeObj{data: store.objects[agentDay+"evening"].data, modified: day.Add(20 * time.Hour)}
	in := New(store, agentSettings(t, nil))
	got, _, err := in.AgentSearch(context.Background(), AgentQuery{From: day.Add(8 * time.Hour), To: day.Add(12 * time.Hour), MaxResults: 10})
	if err != nil || len(got) != 1 || got[0].S3Key != agentDay+"morning" {
		t.Fatalf("sub-day window: %v %v", keys(got), err)
	}
}

func TestWholePrefixModeScansEveryPage(t *testing.T) {
	store := newFake(map[string][]byte{
		"emails/a-old": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
		"emails/b-new": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth}),
	})
	store.pageSize = 1
	store.objects["emails/a-old"] = fakeObj{data: store.objects["emails/a-old"].data, modified: day.Add(time.Hour)}
	store.objects["emails/b-new"] = fakeObj{data: store.objects["emails/b-new"].data, modified: day.Add(10 * time.Hour)}
	in := New(store, agentSettings(t, map[string]string{"EMAIL_S3_DATE_PREFIX_FORMAT": ""}))
	from, to := oneAgentDay()
	got, _, err := in.AgentSearch(context.Background(), AgentQuery{From: from, To: to, MaxResults: 1})
	if err != nil || len(got) != 1 || got[0].S3Key != "emails/b-new" {
		t.Fatalf("newest match on a later page lost: %v %v", keys(got), err)
	}
}

func TestAgentSearchStopsAtTheLimitAfterAFullPartition(t *testing.T) {
	objects := map[string][]byte{}
	for _, d := range []string{"emails/2026/06/01/", "emails/2026/05/31/"} {
		for _, k := range []string{"a", "b", "c"} {
			objects[d+k] = buildMail(mailSpec{from: "a@vendor.example", auth: passAuth})
		}
	}
	store := newFake(objects)
	in := New(store, agentSettings(t, nil))
	got, stats, err := in.AgentSearch(context.Background(), AgentQuery{From: day.AddDate(0, 0, -1), To: day.Add(24*time.Hour - time.Microsecond), MaxResults: 2})
	if err != nil || len(got) != 2 || stats.Scanned != 3 {
		t.Fatalf("got %v stats %+v err %v", keys(got), stats, err)
	}
}

func TestAgentFuzzySenderBoundKeywords(t *testing.T) {
	store := newFake(map[string][]byte{
		agentDay + "vendor":   buildMail(mailSpec{from: "reports@vendor.example", auth: passAuth, subject: "Daily numbers"}),
		agentDay + "spoofish": buildMail(mailSpec{from: "x@evil.example", auth: "amazonses.com; dmarc=pass header.from=evil.example", subject: "vendor.example daily"}),
		agentDay + "forged":   buildMail(mailSpec{from: "reports@vendor.example", subject: "Daily numbers", body: "secret body"}),
	})
	in := New(store, agentSettings(t, nil))
	from, to := oneAgentDay()
	got, stats, err := in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"vendor.example"}, Subject: true, Sender: true, From: from, To: to, MaxResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(got); len(k) != 1 || k[0] != agentDay+"vendor" || stats.UnauthenticatedSkipped != 1 {
		t.Fatalf("sender-bound: %v %+v", k, stats)
	}
	store.fullGets = 0
	got, _, err = in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"secret"}, Body: true, From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 0 || store.fullGets != 2 {
		t.Fatalf("body search must not open the forged message: %v fullGets=%d %v", keys(got), store.fullGets, err)
	}
	got, _, err = in.AgentFuzzy(context.Background(), AgentFuzzyQuery{Keywords: []string{"daily", "numbers"}, Subject: true, MatchAll: true, From: from, To: to, MaxResults: 10})
	if err != nil || len(got) != 1 || got[0].MatchScore != 1 || len(got[0].MatchedKeywords) != 2 {
		t.Fatalf("match_all: %+v %v", got, err)
	}
}

func TestAgentSearchHonoursCancellation(t *testing.T) {
	store := newFake(map[string][]byte{agentDay + "a": buildMail(mailSpec{from: "a@vendor.example", auth: passAuth})})
	in := New(store, agentSettings(t, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	from, to := oneAgentDay()
	if _, _, err := in.AgentSearch(ctx, AgentQuery{From: from, To: to, MaxResults: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
