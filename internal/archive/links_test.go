// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/htmlsafe"
)

// testdata/html_text_urls.json is a copy of the archiver's shared cases
// (production-support ses-s3/scripts/tests/data/html_text_urls.json): the
// archive key is the SHA-256 of the URL as extracted, so both must agree.
func TestHTMLTextURLsMatchTheArchiversCases(t *testing.T) {
	raw, err := os.ReadFile("testdata/html_text_urls.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name string   `json:"name"`
			HTML string   `json:"html"`
			Want []string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range doc.Cases {
		got := extractHTMLTextURLs(c.HTML)
		if len(got) == 0 && len(c.Want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.Want) {
			t.Errorf("%s: got %q, want %q", c.Name, got, c.Want)
		}
	}
}

func TestBareHTMLURLsComeLastAndOnce(t *testing.T) {
	plain := "see https://vendor.example/r.csv?a=1&b=2"
	html := `<a href="https://vendor.example/anchor.csv">csv</a> https://vendor.example/anchor.csv ` +
		"https://vendor.example/r.csv?a=1&amp;b=2 https://vendor.example/new.csv"
	links := bodyURLs(plain, html)
	got := make([]string, 0, len(links))
	for _, l := range links {
		got = append(got, l.url)
	}
	want := []string{"https://vendor.example/r.csv?a=1&b=2", "https://vendor.example/anchor.csv",
		"https://vendor.example/new.csv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBareURLsInsideOutlookConditionalRegionsAreNotListed(t *testing.T) {
	// The renderer removes these regions (downlevel-revealed content
	// included), so a URL inside one is never shown.
	html := "<!--[if !mso]><!--><p>https://vendor.example/hidden.csv</p><!--<![endif]-->" +
		"<!--[if mso]><p>https://vendor.example/mso.csv</p><![endif]--><p>https://vendor.example/shown.csv</p>"
	links := bodyURLs("", html)
	if len(links) != 1 || links[0].url != "https://vendor.example/shown.csv" {
		t.Fatalf("links: %+v", links)
	}
}

func TestALongStrippedBlockDoesNotBringTextPastTheCutIntoTheScan(t *testing.T) {
	html := "<script>" + strings.Repeat("x", maxScanRunes) + "</script> https://vendor.example/report.csv"
	if links := bodyURLs("", html); len(links) != 0 {
		t.Fatalf("links: %+v", links)
	}
}

func TestAReferenceInRawTextIsNotAURLBoundary(t *testing.T) {
	if links := downloadLinks("", "<xmp>https://vendor.example/report.csv&lt;next</xmp>"); len(links) != 0 {
		t.Fatalf("links: %+v", links)
	}
}

func TestARegionOpenerInsideAStrippedScriptHidesNothing(t *testing.T) {
	// The renderer removes the script block first, so the opener inside it
	// never starts a region and the paragraph is shown.
	html := `<script>var x="<!--[if mso]>";</script><p>https://vendor.example/report.csv</p><![endif]-->`
	links := bodyURLs("", html)
	if len(links) != 1 || links[0].url != "https://vendor.example/report.csv" {
		t.Fatalf("links: %+v", links)
	}
	if !strings.Contains(htmlsafe.Sanitize(html), "https://vendor.example/report.csv") {
		t.Fatal("the renderer no longer shows the link; update this test")
	}
}

func TestAnOpenXStyleBareLinkIsADownloadLinkUnderItsExtractedForm(t *testing.T) {
	const extracted = "https://storage.googleapis.com/bq-full-download/x/report.csv.gz?X-Goog-Algorithm=GOOG4-RSA-SHA256" +
		"&amp;X-Goog-Expires=604800&amp;X-Goog-Signature=ab12"
	links := downloadLinks("", "<p>Your report is ready:<br>"+extracted+"</p>")
	if len(links) != 1 || links[0].URL != extracted || links[0].Filename != "report.csv.gz" ||
		links[0].FetchURL != "https://storage.googleapis.com/bq-full-download/x/report.csv.gz?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Expires=604800&X-Goog-Signature=ab12" {
		t.Fatalf("links: %+v", links)
	}
}

func TestABareHTMLURLWithoutFileEvidenceIsNotListed(t *testing.T) {
	for _, fallback := range []string{
		"https://get.vendor.example/magic?token=abc",
		"https://app.vendor.example/u/report-settings",
		"https://vendor.example/report/confirm.html",
	} {
		html := `<a href="https://t.example/c?upn=1">Open</a><p>Or paste into your browser: ` + fallback + `</p>`
		for _, l := range downloadLinks("", html) {
			if l.URL == fallback {
				t.Errorf("%s listed: %+v", fallback, l)
			}
		}
	}
	// The same URL in text/plain keeps its old rule.
	if links := downloadLinks("https://app.vendor.example/u/report-settings", ""); len(links) != 1 {
		t.Fatalf("plain: %+v", links)
	}
}

func TestAPlainURLEndsAtAUnicodeSpaceAsTheArchiversDoes(t *testing.T) {
	links := downloadLinks("get https://vendor.example/r.csv (7 days)", "")
	if len(links) != 1 || links[0].URL != "https://vendor.example/r.csv" {
		t.Fatalf("%+v", links)
	}
}

func TestFileEvidenceReadsTheExtensionAsTheArchiverDoes(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://v.example/r/report.csv/":          true,
		"https://v.example/r/report.csv;v=1":       true,
		"https://v.example/a;b/report.csv":         true,
		"https://v.example/r/confirm.html":         false,
		"https://v.example/r/logo.png":             false,
		"https://v.example/r/go?X-Amz-Signature=1": true,
	} {
		if got := hasFileEvidence(raw); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
}

func TestFileEvidenceIsJudgedOnTheDecodedRequest(t *testing.T) {
	sneaky := "https://get.vendor.example/magic&quest;token=abc&amp;next=/report.csv"
	for _, l := range downloadLinks("", "<p>Open "+sneaky+"</p>") {
		if l.URL == sneaky {
			t.Fatalf("listed: %+v", l)
		}
	}
}

func TestTheDedupeKeyReadsOnlyAmpersands(t *testing.T) {
	if got := dedupeKey("https://v.example/r?a=1&amp;b=2&#38;c=3&#x26;d&AMP;e"); got != "https://v.example/r?a=1&b=2&c=3&d&e" {
		t.Fatal(got)
	}
	if got := dedupeKey("https://v.example/r?x=a&#1;b"); got != "https://v.example/r?x=a&#1;b" {
		t.Fatal(got)
	}
	if got := dedupeKey("https://v.example/r?a=1&#38b=2&#x26next=3"); got != "https://v.example/r?a=1&b=2&next=3" {
		t.Fatal(got)
	}
	if got := dedupeKey("https://v.example/r?a=&#380&#x26f"); got != "https://v.example/r?a=&#380&#x26f" {
		t.Fatal(got)
	}
}

func TestABareLinkSpelledWithReferencesIsJudgedDecoded(t *testing.T) {
	const url = "https://vendor.example/data&period;zip"
	links := downloadLinks("", "<p>Get "+url+"</p>")
	if len(links) != 1 || links[0].URL != url || links[0].Filename != "data.zip" || links[0].FetchURL != "https://vendor.example/data.zip" {
		t.Fatalf("%+v", links)
	}
}

func TestForeignContentScanningIsLinearOnCraftedMarkup(t *testing.T) {
	// Many open HTML elements in an integration point, then many unmatched
	// end tags: each must be read in constant time, not by walking the stack.
	html := "<svg><desc>" + strings.Repeat("<x>", 60000) + strings.Repeat("</y>", 60000) +
		"</desc></svg> https://vendor.example/a.csv"
	start := time.Now()
	extractHTMLTextURLs(html)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestEachHTMLPartIsReadAsItsOwnDocument(t *testing.T) {
	// An unclosed <style> in one part does not hide the next part's text.
	links := bodyURLs("", "<p>Hello</p><style>", "<p>https://vendor.example/report.csv</p>")
	if len(links) != 1 || links[0].url != "https://vendor.example/report.csv" || !links[0].bare {
		t.Fatalf("links: %+v", links)
	}
}

func TestHTMLPiecesFollowTheScanCut(t *testing.T) {
	got := htmlPieces("ab\ncd\nef"[:4], []string{"ab", "cd", "ef"})
	if want := []string{"ab", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
