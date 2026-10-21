// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package htmlsafe

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type goldenCase struct {
	Input  string `json:"input"`
	Bleach string `json:"bleach"`
}

// testdata/sanitizer_golden.json was recorded from the bleach-based Python
// pipeline. Every case must stay neutralized, and output must match the
// recording exactly unless listed here with the reason it differs. The
// first group carries over the differences the Python nh3 pipeline already
// documented; the Go sanitizer reproduces nh3's output for them.
var intentionalDifferences = map[string]struct{ want, why string }{
	"entities_text": {
		"<p>Tom &amp; Jerry &lt;3 \"q\" 's' café &nbsp;x</p>",
		"character references are decoded and only what HTML needs is re-escaped; bleach echoed the sender's entities verbatim. Same rendering.",
	},
	"xss_script_unclosed": {
		"<p>x</p>",
		"the content of <script> is dropped as well as the tag; bleach left an unclosed script's body behind as text.",
	},
	"xss_svg_a": {
		"",
		"foreign (SVG) content is dropped wholesale; bleach kept an empty <a>.",
	},
	"xss_math": {
		"",
		"foreign (MathML) content is dropped wholesale; bleach kept a <table>.",
	},
	"xss_noscript": {
		`&lt;p title="<img src="x">"&gt;`,
		"<noscript> is raw text with scripting on, as in a browser; the <img> after it is real and loses its handler either way.",
	},
	"xss_template": {
		"",
		"<template> content is dropped; bleach hoisted the <img> out of it.",
	},
	"xss_textarea": {
		"&lt;img src=x onerror=alert(1)&gt;",
		"<textarea> content is text in HTML and stays escaped text; bleach re-parsed it into an <img>.",
	},
	"plain_quote_url": {
		`<a href="https://example.com/" rel="nofollow">https://example.com/</a>&quot;&gt;&lt;img src=x onerror=alert(1)&gt;`,
		"linkify stops a URL at an escaped quote or angle bracket; bleach carried the escaped markup into the href.",
	},
	// Go-only: the Go sanitizer drops every SVG/MathML element with its
	// content, where nh3 unwrapped a lone <math> root and kept its text.
	// Losing text from MathML is harmless; never unwrapping foreign
	// content is the simpler, safer rule.
	// Go-only: the HTML5 parser in golang.org/x/net/html keeps the
	// attributes of formatting elements (a, b, strong, …) sorted by name,
	// so they are re-emitted alphabetically. Attribute order has no
	// meaning in HTML; the values and the allow-list are unchanged.
	"link_target_rel": {
		`<a href="https://example.com" rel="noopener nofollow" target="_blank">ok</a>`,
		"formatting-element attributes are emitted in name order.",
	},
	"xss_math_href": {
		"",
		"foreign (MathML) content is dropped wholesale, text included.",
	},
}

var allowedTagSet = map[string]bool{}

func init() {
	for t := range allowedTags {
		allowedTagSet[t] = true
	}
}

var (
	testTagRE  = regexp.MustCompile(`<(/?)([a-zA-Z0-9]+)((?:\s+[^\s=>]+(?:="[^"]*")?)*)\s*/?>`)
	testAttrRE = regexp.MustCompile(`\s+([^\s=>]+)(?:="([^"]*)")?`)
	safeURL    = regexp.MustCompile(`(?i)^(?:https?:|mailto:|/|#|data:image/|cid:)`)
	anyScheme  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// assertNeutralized is the structural XSS check: only allow-listed tags,
// attributes and URLs survive.
func assertNeutralized(t *testing.T, markup string) {
	t.Helper()
	if rest := testTagRE.ReplaceAllString(markup, ""); strings.Contains(rest, "<") {
		t.Fatalf("unparsed markup survived: %q", markup)
	}
	for _, m := range testTagRE.FindAllStringSubmatch(markup, -1) {
		tag := strings.ToLower(m[2])
		if !allowedTagSet[tag] {
			t.Fatalf("tag %s survived: %q", tag, markup)
		}
		for _, a := range testAttrRE.FindAllStringSubmatch(m[3], -1) {
			name, value := strings.ToLower(a[1]), a[2]
			if strings.HasPrefix(name, "on") {
				t.Fatalf("handler survived: %q", markup)
			}
			switch name {
			case "href", "title", "target", "rel", "src", "alt", "width", "height", "class":
			default:
				t.Fatalf("attribute %s survived: %q", name, markup)
			}
			if (name == "href" || name == "src") && !safeURL.MatchString(value) && anyScheme.MatchString(value) {
				t.Fatalf("unsafe URL survived: %q", markup)
			}
			if name == "href" {
				lv := strings.ToLower(value)
				if strings.HasPrefix(lv, "data:") || strings.HasPrefix(lv, "cid:") {
					t.Fatalf("data/cid link survived: %q", markup)
				}
			}
		}
	}
}

func loadGolden(t *testing.T) map[string]map[string]goldenCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/sanitizer_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]goldenCase{}
	for _, section := range []string{"html", "plain"} {
		var cases map[string]goldenCase
		if err := json.Unmarshal(doc[section], &cases); err != nil {
			t.Fatal(err)
		}
		out[section] = cases
	}
	return out
}

func TestRenderMatchesRecording(t *testing.T) {
	golden := loadGolden(t)
	for _, section := range []string{"html", "plain"} {
		names := make([]string, 0, len(golden[section]))
		for n := range golden[section] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			c := golden[section][name]
			t.Run(section+"-"+name, func(t *testing.T) {
				var out string
				if section == "html" {
					out = RenderHTMLPreview(c.Input)
				} else {
					out = RenderPlainPreview(c.Input)
				}
				assertNeutralized(t, out)
				want := c.Bleach
				if d, ok := intentionalDifferences[name]; ok {
					want = d.want
				}
				if out != want {
					t.Fatalf("input %q\n got %q\nwant %q", c.Input, out, want)
				}
			})
		}
	}
}

func TestRecordingItselfIsNeutralized(t *testing.T) {
	for _, cases := range loadGolden(t) {
		for _, c := range cases {
			assertNeutralized(t, c.Bleach)
		}
	}
	for _, d := range intentionalDifferences {
		assertNeutralized(t, d.want)
	}
}

func TestDangerousLinkSchemesDropped(t *testing.T) {
	for _, href := range []string{
		"javascript:alert(1)", "da\tta:text/html,x", "\x01data:text/html,x",
		"c\nid:abc", "vbscript:x", "JAVASCRIPT:x",
	} {
		if out := RenderHTMLPreview(`<a href="` + href + `">x</a>`); out != "<a>x</a>" {
			t.Errorf("%q -> %q", href, out)
		}
	}
}

func TestSafeHrefsKept(t *testing.T) {
	for _, href := range []string{"https://example.com", "/attachment?x=1", "#top", "mailto:a@b.example"} {
		out := RenderHTMLPreview(`<a href="` + href + `">x</a>`)
		if !strings.Contains(out, `href="`+href+`"`) {
			t.Errorf("%q -> %q", href, out)
		}
	}
}

func TestDataAndCidImagesStillRender(t *testing.T) {
	in := `<img src="data:image/gif;base64,R0lGOD=="><img src="cid:logo">`
	if out := RenderHTMLPreview(in); out != in {
		t.Fatalf("got %q", out)
	}
}

func TestCutInsideATagIsClosedOrDropped(t *testing.T) {
	source := "<p>" + strings.Repeat("x", 30) + `</p><a href="https://example.com/long">y</a>`
	for limit := 30; limit < len(source)+5; limit++ {
		out := sanitizeLimit(source, limit)
		assertNeutralized(t, out)
		if strings.Count(out, "<a") != strings.Count(out, "</a>") {
			t.Fatalf("limit %d: unbalanced %q", limit, out)
		}
	}
}

func TestCSSStripCannotLeaveHalfATag(t *testing.T) {
	out := RenderHTMLPreview("p{<b>x}</b><p>body</p>")
	assertNeutralized(t, out)
	if strings.Contains(out, "</b>") && !strings.Contains(out, "<b>") {
		t.Fatalf("half a tag: %q", out)
	}
}

func TestSanitizerBasics(t *testing.T) {
	clean := Sanitize(`<p onclick="alert(1)">hi</p><script>alert(2)</script>`)
	if strings.Contains(clean, "<script") || strings.Contains(clean, "onclick") || !strings.Contains(clean, "hi") {
		t.Fatalf("got %q", clean)
	}
	clean = Sanitize(`<a href="data:text/html;base64,PHNjcmlwdD4=">bad</a><a href="https://example.com">ok</a>`)
	if strings.Contains(clean, "data:text/html") || !strings.Contains(clean, `href="https://example.com"`) {
		t.Fatalf("got %q", clean)
	}
	clean = Sanitize(`<img src="data:image/png;base64,iVBORw0KGgo=">`)
	if !strings.Contains(clean, `src="data:image/png;base64,iVBORw0KGgo="`) {
		t.Fatalf("got %q", clean)
	}
	clean = Sanitize("<style>.x{color:red}</style><p>body</p>")
	if strings.Contains(clean, "color:red") || !strings.Contains(clean, "body") {
		t.Fatalf("got %q", clean)
	}
}

func TestPrePassIsOneLeftToRightScan(t *testing.T) {
	// The style block closes first; the script close after it is plain text
	// to the pre-pass, then escaped text to the sanitizer.
	if got := Sanitize("<style><script></style>a</script><p>b</p>"); got != "a<p>b</p>" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("<SCRIPT type=x>alert(1)</script><p>ok</p>"); got != "<p>ok</p>" {
		t.Fatalf("got %q", got)
	}
}

func a(url string) string { return `<a href="` + url + `" rel="nofollow">` + url + `</a>` }

func TestLinkifyCases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://app.example.dev/x", "<p>" + a("https://app.example.dev/x") + "</p>"},
		{"config.yaml", "<p>config.yaml</p>"},
	}
	for _, c := range cases {
		if got := RenderHTMLPreview("<p>" + c.in + "</p>"); got != c.want {
			t.Errorf("%q -> %q, want %q", c.in, got, c.want)
		}
	}
	if strings.Contains(RenderHTMLPreview("<p>ftp://files.example.com/a</p>"), "<a") {
		t.Error("ftp linked")
	}
	if strings.Contains(RenderHTMLPreview("<p>ada@example.com</p>"), "<a") {
		t.Error("email linked")
	}
	in := `<a href="https://example.com" rel="NoFollow noopener">x</a>`
	if got := RenderHTMLPreview(in); got != in {
		t.Errorf("rel rewritten: %q", got)
	}
	in = `<a href="mailto:a@example.com">m</a><a title="t">n</a>`
	if got := RenderHTMLPreview(in); got != in {
		t.Errorf("mailto/hrefless changed: %q", got)
	}
	if got := RenderHTMLPreview(`<img alt="see https://example.com/a>b" src="https://img.example/a.png">`); strings.Contains(got, "<a") {
		t.Errorf("attribute linked: %q", got)
	}
}

func TestURLNeverLeavesTheHref(t *testing.T) {
	hrefRE := regexp.MustCompile(`href="([^"]*)"`)
	for _, payload := range []string{
		`https://example.com/a"onmouseover="x`,
		`https://example.com/a'onmouseover='x`,
		"https://example.com/a<img src=x>",
	} {
		escaped := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(payload)
		for _, out := range []string{RenderHTMLPreview("<p>" + escaped + "</p>"), RenderPlainPreview(payload)} {
			assertNeutralized(t, out)
			for _, m := range hrefRE.FindAllStringSubmatch(out, -1) {
				if strings.Contains(m[1], "onmouseover") || strings.Contains(m[1], "<") {
					t.Fatalf("href escaped its attribute: %q", out)
				}
			}
		}
	}
}

func TestLinkifyReviewCases(t *testing.T) {
	url := "https://example.com#token=abc"
	if got := RenderPlainPreview(url); got != a(url) {
		t.Errorf("fragment: %q", got)
	}
	url = "https://en.wikipedia.org/wiki/Function_(mathematics)"
	if got := RenderPlainPreview("see (" + url + ")."); got != "see ("+a(url)+")." {
		t.Errorf("parens: %q", got)
	}
	for _, u := range []string{
		"http://127.0.0.1/status", "http://localhost:8000/",
		"https://xn--80ak6aa92e.xn--p1ai/path", "http://[::1]:8080/a", "https://intranet",
	} {
		if got := RenderPlainPreview(u); got != a(u) {
			t.Errorf("%q -> %q", u, got)
		}
	}
	if got := RenderPlainPreview("xn--80ak6aa92e.xn--p1ai"); !strings.Contains(got, `href="http://xn--80ak6aa92e.xn--p1ai"`) {
		t.Errorf("punycode bare: %q", got)
	}
	for _, text := range []string{"localhost:8000", "127.0.0.1", "config.yaml"} {
		if strings.Contains(RenderPlainPreview(text), "<a") {
			t.Errorf("%q linked", text)
		}
	}
}

func TestHostileInputStaysLinear(t *testing.T) {
	r := strings.Repeat
	for _, text := range []string{
		"http://" + r("a.", 3000),
		"http://[" + r(":", 6000),
		"https://" + r("a-", 3000),
		"x" + r(")", 6000),
		"https://e.example/" + r("(", 3000) + r(")", 3000),
		r("xn--a.", 1000),
		"https://e.example/" + r(")]}", 2000),
		"https://e.example/" + r("[", 6000),
		"https://" + r("a@", 3000),
		"https://e.example/" + r(".;&amp;", 1000),
		r("https://e.example/a https://e.example/b ", 300),
		r("<script", 3000),
		r("(a.", 3000),
	} {
		start := time.Now()
		RenderPlainPreview(text)
		RenderHTMLPreview("<p>" + text + "</p>")
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%q... took %v", text[:20], d)
		}
	}
}

func al(url, href string) string { return `<a href="` + href + `" rel="nofollow">` + url + `</a>` }

func TestLinkifyTable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user@example.com/path", "https://user@example.com/path"},
		{"https://user:pass@example.com/path", "https://user:pass@example.com/path"},
		{"https://bank.example@evil.example/x", "https://bank.example@evil.example/x"},
		{"see https://user@example.com.", "see https://user@example.com."},
		{"[https://example.com/path]", "[" + a("https://example.com/path") + "]"},
		{"{https://example.com/path}", "{" + a("https://example.com/path") + "}"},
		{"(https://example.com/a_(b))", "(" + a("https://example.com/a_(b)") + ")"},
		{"[https://example.com/a[1]].", "[" + a("https://example.com/a[1]") + "]."},
		{"([https://example.com/x])", "([" + a("https://example.com/x") + "])"},
		{"https://example.com/{id}", a("https://example.com/{id}")},
		{"https://example.com/a.", a("https://example.com/a") + "."},
		{"https://example.com/a,", a("https://example.com/a") + ","},
		{"https://example.com/a!?", a("https://example.com/a") + "!?"},
		{"https://example.com/a;", a("https://example.com/a") + ";"},
		{"https://example.com/a:", a("https://example.com/a") + ":"},
		{"https://example.com/?a=1&b=2", a("https://example.com/?a=1&amp;b=2")},
		{"https://example.com#token=abc", a("https://example.com#token=abc")},
		{"(https://en.wikipedia.org/wiki/Function_(mathematics)).", "(" + a("https://en.wikipedia.org/wiki/Function_(mathematics)") + ")."},
		{"http://127.0.0.1/status", a("http://127.0.0.1/status")},
		{"http://localhost:8000/", a("http://localhost:8000/")},
		{"http://[::1]:8080/a", a("http://[::1]:8080/a")},
		{"https://xn--80ak6aa92e.xn--p1ai/", a("https://xn--80ak6aa92e.xn--p1ai/")},
		{"http://example.com:99999/", "http://example.com:99999/"},
		{"http://[not-ipv6]/", "http://[not-ipv6]/"},
		{"https://", "https://"},
		{"example.com/a.", al("example.com/a", "http://example.com/a") + "."},
		{"config.yaml", "config.yaml"},
		// Go-port additions: Unicode word characters and look-behind.
		{"café.example.com", al("café.example.com", "http://café.example.com")},
		{"a.b.-c.com x", al("a.b.-c.com", "http://a.b.-c.com") + " x"},
		{"x.example.com", al("x.example.com", "http://x.example.com")},
		{"-https://example.com", "-https://example.com"},
		{"see:https://example.com", "see:https://example.com"},
		{"&quot;https://example.com&quot;", "&amp;quot;https://example.com&amp;quot;"},
	}
	for _, c := range cases {
		out := RenderPlainPreview(c.in)
		assertNeutralized(t, out)
		if out != c.want {
			t.Errorf("%q\n got %q\nwant %q", c.in, out, c.want)
		}
	}
}

func TestStripLeadingCSSNoise(t *testing.T) {
	if got := StripLeadingCSSNoise("  .x{color:red} #y { margin:0 }\n p{a:b}  body"); got != "body" {
		t.Fatalf("got %q", got)
	}
	if got := StripLeadingCSSNoise("  hello"); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if got := StripLeadingCSSNoise("a{" + strings.Repeat("x", 801) + "} b"); !strings.HasPrefix(got, "a{") {
		t.Fatalf("over-long rule stripped: %q", got[:10])
	}
}

// TestLinkifyMatchesPythonCorpus replays inputs recorded from the Python
// app/linkify.py (testdata/linkify_differential.json): the Go scanner must
// make the same decision for every one.
func TestLinkifyMatchesPythonCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/linkify_differential.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			In     *string `json:"in"`
			Markup *string `json:"markup"`
			Out    string  `json:"out"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, c := range doc.Cases {
		var got, in string
		if c.In != nil {
			in = *c.In
			got = RenderPlainPreview(in)
		} else {
			in = *c.Markup
			got = Linkify(in)
		}
		if got != c.Out {
			failures++
			if failures <= 15 {
				t.Errorf("input %q\n got %q\nwant %q", in, got, c.Out)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d corpus cases differ", failures, len(doc.Cases))
	}
}
