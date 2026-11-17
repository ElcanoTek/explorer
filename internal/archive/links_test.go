// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
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

func TestAnOpenXStyleBareLinkIsADownloadLinkUnderItsExtractedForm(t *testing.T) {
	const extracted = "https://storage.googleapis.com/bq-full-download/x/report.csv.gz?X-Goog-Algorithm=GOOG4-RSA-SHA256" +
		"&amp;X-Goog-Expires=604800&amp;X-Goog-Signature=ab12"
	links := downloadLinks("", "<p>Your report is ready:<br>"+extracted+"</p>")
	if len(links) != 1 || links[0].URL != extracted || links[0].Filename != "report.csv.gz" ||
		links[0].FetchURL != "https://storage.googleapis.com/bq-full-download/x/report.csv.gz?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Expires=604800&X-Goog-Signature=ab12" {
		t.Fatalf("links: %+v", links)
	}
}
