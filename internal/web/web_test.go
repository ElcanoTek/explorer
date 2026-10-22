// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/centralauth"
	"github.com/ElcanoTek/explorer/internal/config"
)

func todayKey(name string) (string, time.Time) {
	now := time.Now().UTC()
	return "emails/" + now.Format("2006/01/02") + "/" + name, now
}

const sampleMessage = "From: Reports <reports@vendor.example>\r\nTo: archive@example.com\r\n" +
	"Subject: Northwind daily totals\r\nDate: Mon, 01 Jun 2026 12:00:00 +0000\r\n" +
	"Message-ID: <m1@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nTotals attached.\r\n"

// ---- Elcano mode -----------------------------------------------------------

func TestUnauthenticatedInboxRedirectsToAuth(t *testing.T) {
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"})
	resp := e.get("/?mode=view&x=a%26b")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "https://auth.example.com/?return_to=") {
		t.Fatalf("status %d location %q", resp.StatusCode, loc)
	}
	u, _ := url.Parse(loc)
	back := u.Query().Get("return_to")
	if !strings.HasSuffix(back, "/?mode=view&x=a%26b") {
		t.Fatalf("return_to lost the query: %q", back)
	}
}

func TestInboxRendersForSignedInUser(t *testing.T) {
	e := elcanoEnv(t)
	resp := e.get("/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, "Explorer") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestExpiredOrForeignCookieIsLoggedOut(t *testing.T) {
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"})
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, tok := range []string{
		mintElcano(e.priv, "alice@example.com", time.Now().Add(-time.Minute)),
		mintElcano(other, "alice@example.com", time.Now().Add(time.Hour)),
		"garbage",
	} {
		e.setCookie("elcano_auth", tok)
		if resp := e.get("/"); resp.StatusCode != http.StatusSeeOther {
			t.Errorf("cookie %q accepted: %d", tok, resp.StatusCode)
		}
	}
}

func TestViewModeRendersRows(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("msg1")
	e.store.put(key, sampleMessage, at)
	big, _ := todayKey("msg2")
	e.store.put(big, sampleMessage+strings.Repeat("x", 120000), at.Add(-time.Minute))
	resp := e.get("/?run_search=1&mode=view")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(resp.body, "Northwind daily totals") || !strings.Contains(resp.body, "Matches (2)") {
		t.Fatalf("rows missing:\n%s", resp.body)
	}
	if !strings.Contains(resp.body, `data-open-url="/email?s3_key=emails%2f`) {
		t.Fatalf("row link not query-escaped:\n%s", resp.body)
	}
	if strings.Count(resp.body, "inbox-row__clip") != 2 { // filter menu + one large row
		t.Fatalf("paperclip heuristic wrong: %d", strings.Count(resp.body, "inbox-row__clip"))
	}
}

func TestViewModePaginatesWithCursors(t *testing.T) {
	e := elcanoEnv(t)
	for i := 0; i < 5; i++ {
		key, at := todayKey("m" + string(rune('a'+i)))
		e.store.put(key, sampleMessage, at)
	}
	first := e.get("/?run_search=1&mode=view&max_results=2")
	if !strings.Contains(first.body, "Next page") || strings.Contains(first.body, "Previous page") {
		t.Fatalf("first page pager wrong:\n%s", first.body)
	}
	cursor := regexp.MustCompile(`name="cursor" value="([0-9a-f]+)"`).FindStringSubmatch(first.body)
	if cursor == nil {
		t.Fatal("no cursor on first page")
	}
	day := time.Now().Format("2006-01-02")
	second := e.get("/?run_search=1&mode=view&max_results=2&day=" + day + "&cursor=" + cursor[1] + "&cursor_stack=FIRST&page=2")
	if !strings.Contains(second.body, "Previous page") || !strings.Contains(second.body, "Page 2") {
		t.Fatalf("second page pager wrong:\n%s", second.body)
	}
	// Another browser cannot use this browser's cursor.
	other := elcanoEnv(t)
	other.srv.jobs = e.srv.jobs
	stolen := other.get("/?run_search=1&mode=view&max_results=2&day=" + day + "&cursor=" + cursor[1] + "&page=2")
	if !strings.Contains(stolen.body, "That previous page expired") {
		t.Fatal("cursor was usable by another browser")
	}
}

func TestInvalidInputShowsErrorNot500(t *testing.T) {
	e := elcanoEnv(t)
	for path, want := range map[string]string{
		"/?run_search=1&day=junk":                                                                     "Invalid date",
		"/?run_search=1&mode=exact&date_from=2026-13-01":                                              "Invalid date ranges",
		"/?run_search=1&mode=exact&max_results=900":                                                   "from 1 to 500",
		"/?run_search=1&mode=exact&date_from=2026-01-01&date_to=2026-06-01":                           "Keep it at or under 62 days",
		"/?run_search=1&mode=fuzzy&search_body=on&keywords=x&date_from=2026-01-01&date_to=2026-01-20": "uncheck Body",
	} {
		resp := e.get(path)
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, want) {
			t.Errorf("%s: status %d, missing %q", path, resp.StatusCode, want)
		}
	}
}

func TestExactSearchRunsAsBackgroundJob(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("msg1")
	e.store.put(key, sampleMessage, at)
	start := e.get("/?run_search=1&mode=exact&sender=vendor")
	loc := start.Header.Get("Location")
	if start.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "search_job=") {
		t.Fatalf("expected redirect to job, got %d %q", start.StatusCode, loc)
	}
	var page response
	for i := 0; i < 50; i++ {
		page = e.get(loc)
		if !strings.Contains(page.body, "Search in progress") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(page.body, "Northwind daily totals") || !strings.Contains(page.body, "Matches (1)") {
		t.Fatalf("job result missing:\n%s", page.body)
	}
	// A job id is bound to its search and its browser.
	changed := e.get(strings.Replace(loc, "sender=vendor", "sender=other", 1))
	if !strings.Contains(changed.body, "This search session expired") {
		t.Fatal("job reused for a different search")
	}
}

func TestCancelledSearchExplainsItself(t *testing.T) {
	e := elcanoEnv(t)
	owner := "owner"
	id := e.srv.jobs.start("sig", owner, time.Hour, func(ctx context.Context) ([]archiveRow, int, error) {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	})
	e.srv.jobs.requestCancel(id)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if j := e.srv.jobs.load(id, "sig", owner); j != nil && j.Status == jobCancelled {
			if j.CancelReason != "user" {
				t.Fatalf("reason %q", j.CancelReason)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job never cancelled")
}

func TestSearchTimeoutIsReportedAsTimeout(t *testing.T) {
	e := elcanoEnv(t)
	id := e.srv.jobs.start("sig", "o", 20*time.Millisecond, func(ctx context.Context) ([]archiveRow, int, error) {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if j := e.srv.jobs.load(id, "sig", "o"); j != nil && j.Status == jobCancelled {
			if j.CancelReason != "timeout" {
				t.Fatalf("reason %q", j.CancelReason)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job never timed out")
}

func TestOutOfScopeKeysAre404(t *testing.T) {
	e := elcanoEnv(t)
	for _, path := range []string{
		"/email?s3_key=secrets%2Fbackup.tar.gz",
		"/attachment?s3_key=secrets%2Fbackup.tar.gz&filename=x",
		"/email?s3_key=emails%2Fmissing",
		"/email?s3_key=emails%2F%01ctl",
	} {
		if resp := e.get(path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d", path, resp.StatusCode)
		}
	}
}

func TestEmailDetailRendersSanitizedBody(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("html")
	e.store.put(key, "From: \"Ada\" <ada@example.com>\r\nTo: b@example.com\r\nSubject: Hi\r\n"+
		"Content-Type: text/html\r\n\r\n<p onclick=\"x()\">Hello <script>alert(1)</script><a href=\"javascript:alert(1)\">x</a></p>", at)
	resp := e.get("/email?s3_key=" + url.QueryEscape(key))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, bad := range []string{"alert(1)", "onclick", "javascript:"} {
		if strings.Contains(resp.body, bad) {
			t.Errorf("unsafe %q survived:\n%s", bad, resp.body)
		}
	}
	if !strings.Contains(resp.body, "Hello") || !strings.Contains(resp.body, `message-card__avatar" aria-hidden="true">A<`) {
		t.Fatalf("body or sender missing:\n%s", resp.body)
	}
}

func TestAttachmentStreamsFromMemorySandboxed(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("att")
	e.store.put(key, "From: a@example.com\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"+
		"--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"+
		"--B\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=\"../../evil.html\"\r\n\r\n<script>alert(1)</script>\r\n--B--\r\n", at)
	resp := e.get("/attachment?s3_key=" + url.QueryEscape(key) + "&filename=" + url.QueryEscape("../../evil.html"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("active type served as %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename=evil.html` {
		t.Errorf("disposition %q", cd)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Errorf("csp %q", csp)
	}
	if missing := e.get("/attachment?s3_key=" + url.QueryEscape(key) + "&filename=nope.txt"); missing.StatusCode != http.StatusNotFound {
		t.Errorf("missing attachment: %d", missing.StatusCode)
	}
}

func TestElcanoLogoutRedirectsToAuthLogout(t *testing.T) {
	e := elcanoEnv(t)
	resp := e.post("/logout", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://auth.example.com/logout" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestCentralSessionCookieNotAcceptedInElcanoMode(t *testing.T) {
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"})
	e.setCookie("__Host-explorer_session", "copied")
	if resp := e.get("/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestHealthIsPublicWithClosedCSP(t *testing.T) {
	e := newEnv(t, map[string]string{"EXPLORER_AUTH_MODE": "elcano"})
	resp := e.get("/health")
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(resp.body) != `{"status":"ok"}` {
		t.Fatalf("health %d %q", resp.StatusCode, resp.body)
	}
	if resp.Header.Get("Content-Security-Policy") != cspNonPage {
		t.Fatalf("csp %q", resp.Header.Get("Content-Security-Policy"))
	}
	if static := e.get("/static/styles.css"); static.StatusCode != http.StatusOK {
		t.Fatalf("static %d", static.StatusCode)
	}
}

func TestUnknownAuthModeRefusesToStart(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := baseEnv(priv)
	env["EXPLORER_AUTH_MODE"] = "local"
	s, _ := config.FromEnv(env)
	if _, err := New(context.Background(), s, Options{Store: newFakeStore()}); err == nil {
		t.Fatal("started with an unknown auth mode")
	}
}

// ---- Central mode ----------------------------------------------------------

func TestProtectedRequestStartsLocalLogin(t *testing.T) {
	e := centralEnv(t)
	resp := e.get("/email?s3_key=emails%2Fone")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login?next=%2Femail%3Fs3_key%3Demails%252Fone" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLoginRedirectCarriesPKCEAndTransactionCookie(t *testing.T) {
	e := centralEnv(t)
	resp := e.get("/auth/login?next=%2F")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if loc.Host != strings.TrimPrefix(e.auth.ts.URL, "https://") || loc.Path != "/authorize" ||
		q.Get("response_type") != "code" || q.Get("client_id") != "explorer" ||
		q.Get("redirect_uri") != "https://explorer.example.com/auth/callback" || q.Get("scope") != "email" ||
		q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		t.Fatalf("authorize URL %s", loc)
	}
	if strings.Contains(loc.String(), "a-test-client-secret") {
		t.Fatal("client secret leaked into the redirect")
	}
	set := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	for _, want := range []string{"explorer_ui=", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(set, want) {
			t.Errorf("transaction cookie missing %q: %s", want, set)
		}
	}
	if strings.Contains(strings.ToLower(set), "domain=") {
		t.Errorf("cookie has a domain: %s", set)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("authorize redirect cacheable")
	}
}

func TestCallbackIssuesAppScopedCookie(t *testing.T) {
	e := centralEnv(t)
	resp := e.completeLogin("/?mode=view")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?mode=view" {
		t.Fatalf("status %d location %q: %s", resp.StatusCode, resp.Header.Get("Location"), resp.body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Error("callback cache/referrer headers missing")
	}
	set := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	for _, want := range []string{centralauth.CookieName + "=", "HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=86400"} {
		if !strings.Contains(set, want) {
			t.Errorf("session cookie missing %q: %s", want, set)
		}
	}
	if len(e.auth.codes) != 1 || e.auth.codes[0] != "one-time-code" {
		t.Fatalf("codes exchanged: %v", e.auth.codes)
	}
	if home := e.get("/"); home.StatusCode != http.StatusOK {
		t.Fatalf("signed-in home %d", home.StatusCode)
	}
}

func TestCallbackRejectsWrongStateWithoutExchanging(t *testing.T) {
	e := centralEnv(t)
	e.beginLogin("/")
	for _, state := range []string{"wrong-state", "état"} {
		resp := e.get("/auth/callback?code=stolen&state=" + url.QueryEscape(state))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("state %q: %d", state, resp.StatusCode)
		}
	}
	if len(e.auth.codes) != 0 {
		t.Fatalf("exchanged %v", e.auth.codes)
	}
}

func TestCallbackOutcomesArePagesNotJSON(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*testEnv)
		status int
		text   string
	}{
		{"unlisted", func(e *testEnv) { e.auth.email = "bob@example.com" }, http.StatusForbidden, "Explorer access needed"},
		{"outage", func(e *testEnv) { e.auth.tokenCode = http.StatusInternalServerError }, http.StatusBadGateway, "Unable to sign in"},
		{"rejected", func(e *testEnv) { e.auth.tokenCode = http.StatusBadRequest }, http.StatusBadRequest, "Sign-in expired"},
		{"forged", func(e *testEnv) { _, e.auth.signer, _ = ed25519.GenerateKey(rand.Reader) }, http.StatusBadGateway, "Unable to sign in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := centralEnv(t)
			tc.setup(e)
			resp := e.completeLogin("/")
			if resp.StatusCode != tc.status || !strings.Contains(resp.body, tc.text) ||
				!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || strings.Contains(resp.body, `"detail"`) {
				t.Fatalf("status %d:\n%s", resp.StatusCode, resp.body)
			}
			if e.cookie(centralauth.CookieName) != "" {
				t.Fatal("session cookie issued")
			}
		})
	}
}

func TestUnsafeNextIsNeverFollowed(t *testing.T) {
	for _, next := range []string{"https://evil.example/steal", `/\evil.example/steal`, "//evil.example"} {
		e := centralEnv(t)
		resp := e.completeLogin(next)
		if resp.Header.Get("Location") != "/" {
			t.Errorf("next %q → %q", next, resp.Header.Get("Location"))
		}
	}
}

func TestCentralRejectsElcanoAndForgedSessionCookies(t *testing.T) {
	e := centralEnv(t)
	e.setCookie("elcano_auth", "legacy.signed-token")
	e.setCookie(centralauth.CookieName, "old-local-session")
	resp := e.get("/")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/auth/login?next=") {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestCentralLogoutRequiresCSRFThenSignsOutEverywhere(t *testing.T) {
	e := centralEnv(t)
	e.completeLogin("/")
	raw := e.cookie(centralauth.CookieName)
	if raw == "" {
		t.Fatal("not signed in")
	}
	home := e.get("/")
	csrf := regexp.MustCompile(`name="csrf_token" value="([0-9a-f]+)"`).FindStringSubmatch(home.body)
	if csrf == nil || csrf[1] != centralauth.CSRFToken(raw) {
		t.Fatal("logout form lacks the session's CSRF token")
	}
	if resp := e.post("/logout", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", resp.StatusCode)
	}
	resp := e.post("/logout", url.Values{"csrf_token": {csrf[1]}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != e.auth.ts.URL+"/logout?client_id=explorer" {
		t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.central().store.GetIdentity(raw) != nil {
		t.Fatal("session survived logout")
	}
	if !strings.Contains(strings.Join(resp.Header.Values("Set-Cookie"), "\n"), centralauth.CookieName+"=; Path=/; Max-Age=0") {
		t.Fatalf("cookie not cleared: %v", resp.Header.Values("Set-Cookie"))
	}
}

func TestBackchannelLogoutRevokesSubjectIdempotently(t *testing.T) {
	e := centralEnv(t)
	e.completeLogin("/")
	raw := e.cookie(centralauth.CookieName)
	tok := e.logoutToken("account-123", "event-123")
	for i := 0; i < 2; i++ {
		if resp := e.post("/auth/backchannel-logout", url.Values{"logout_token": {tok}}); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delivery %d: %d %s", i, resp.StatusCode, resp.body)
		}
	}
	if e.central().store.GetIdentity(raw) != nil {
		t.Fatal("session survived back-channel logout")
	}
}

func TestSignedAccessEventsGrantThenRevoke(t *testing.T) {
	e := centralEnv(t)
	store := e.central().store
	if resp := e.post("/auth/backchannel-logout", url.Values{"access_token": {e.accessToken("grant", 1, "bob@example.com")}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant: %d %s", resp.StatusCode, resp.body)
	}
	if !store.IsAllowed("bob@example.com") {
		t.Fatal("grant not applied")
	}
	e.auth.email = "bob@example.com"
	if resp := e.completeLogin("/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bob login %d", resp.StatusCode)
	}
	raw := e.cookie(centralauth.CookieName)
	if resp := e.post("/auth/backchannel-logout", url.Values{"access_token": {e.accessToken("revoke", 2, "bob@example.com")}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if store.IsAllowed("bob@example.com") || store.GetIdentity(raw) != nil {
		t.Fatal("revoke not applied")
	}
	both := e.post("/auth/backchannel-logout", url.Values{
		"access_token": {e.accessToken("revoke", 3, "bob@example.com")}, "logout_token": {"also"},
	})
	if both.StatusCode != http.StatusBadRequest {
		t.Fatalf("ambiguous request: %d", both.StatusCode)
	}
}

func TestBackchannelRejectsOversizedAndMalformed(t *testing.T) {
	e := centralEnv(t)
	if resp := e.post("/auth/backchannel-logout", url.Values{"logout_token": {strings.Repeat("x", 20_001)}}); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", resp.StatusCode)
	}
	raw := e.accessToken("grant", 1, "bob@example.com")
	parts := strings.Split(raw, ".")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"access+jwt","alg":"EdDSA","kid":"é"}`))
	unsigned := header + "." + parts[1]
	forged := unsigned + "." + b64url(ed25519.Sign(e.auth.key, []byte(unsigned)))
	for _, field := range []string{"access_token", "logout_token"} {
		if resp := e.post("/auth/backchannel-logout", url.Values{field: {forged}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s with non-ASCII kid: %d", field, resp.StatusCode)
		}
	}
}

func TestCentralModeRefusesToStartWithoutKeyOrSecret(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := baseEnv(priv)
	base["EXPLORER_AUTH_MODE"] = "central"
	base["EXPLORER_ACCESS_DB"] = filepath.Join(t.TempDir(), "access.db")
	base["AUTH_ISSUER_URL"] = "https://auth.example.com"
	base["EXPLORER_PUBLIC_URL"] = "https://explorer.example.com"
	base["AUTH_CLIENT_SECRET"] = "a-test-client-secret-with-at-least-32-bytes"
	for name, mutate := range map[string]func(map[string]string){
		"no key":         func(m map[string]string) { m["AUTH_SIGNING_PUBKEY"] = "" },
		"short key":      func(m map[string]string) { m["AUTH_SIGNING_PUBKEY"] = "not-32-bytes" },
		"dev secret":     func(m map[string]string) { delete(m, "EXPLORER_SESSION_SECRET") },
		"insecure":       func(m map[string]string) { m["EXPLORER_UI_COOKIE_SECURE"] = "0" },
		"http issuer":    func(m map[string]string) { m["AUTH_ISSUER_URL"] = "http://auth.example.com" },
		"short secret":   func(m map[string]string) { m["AUTH_CLIENT_SECRET"] = "short" },
		"issuer w/ path": func(m map[string]string) { m["AUTH_ISSUER_URL"] = "https://auth.example.com/x" },
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		mutate(env)
		s, _ := config.FromEnv(env)
		if srv, err := New(context.Background(), s, Options{Store: newFakeStore()}); err == nil {
			_ = srv.Close()
			t.Errorf("%s: started", name)
		}
	}
}

func TestPagesCarryNonceCSPAndNoInlineHandlers(t *testing.T) {
	e := centralEnv(t)
	e.completeLogin("/")
	page := e.get("/")
	csp := page.Header.Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'self' 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("csp %q", csp)
	}
	for _, want := range []string{"default-src 'self'", "style-src 'self';", "img-src 'self' data: https:", "frame-ancestors 'none'",
		"object-src 'none'", "frame-src 'none'", "media-src 'none'", "worker-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("csp lacks %q", want)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("csp allows %q: %s", bad, csp)
		}
	}
	if strings.Contains(csp, "form-action") {
		t.Error("form-action would break Elcano logout")
	}
	body := page.body
	if strings.Contains(body, "<script>") || !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
		t.Error("inline scripts without the nonce")
	}
	if regexp.MustCompile(` on[a-z]+="`).MatchString(body) || strings.Contains(body, ` style="`) {
		t.Error("inline handlers or styles in the page")
	}
	if again := e.get("/"); again.Header.Get("Content-Security-Policy") == csp {
		t.Error("nonce reused across responses")
	}
}

func TestSignedOutPage(t *testing.T) {
	e := centralEnv(t)
	resp := e.get("/signed-out")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, e.auth.ts.URL+"/account") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e.completeLogin("/")
	if again := e.get("/signed-out"); again.StatusCode != http.StatusSeeOther {
		t.Fatalf("signed-in /signed-out: %d", again.StatusCode)
	}
}

// An empty {{define}} does not override a block in html/template, which once
// leaked the default intro onto pages that blank it.
func TestPagesThatBlankTheIntroKeepItBlank(t *testing.T) {
	e := elcanoEnv(t)
	if body := e.get("/").body; !strings.Contains(body, `<p class="page-header__intro"></p>`) {
		t.Fatal("inbox shows the default intro")
	}
	e2 := centralEnv(t)
	if body := e2.get("/signed-out").body; !strings.Contains(body, `<p class="page-header__intro"></p>`) {
		t.Fatal("signed-out page shows the default intro")
	}
}

func TestReviewRegressions(t *testing.T) {
	e := centralEnv(t)
	// Multipart bodies are accepted like the old Form() fields.
	body := "--X\r\nContent-Disposition: form-data; name=\"access_token\"\r\n\r\n" +
		e.accessToken("grant", 1, "carol@example.com") + "\r\n--X--\r\n"
	mreq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.ts.URL+"/auth/backchannel-logout", strings.NewReader(body))
	mreq.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	mresp, err := e.browser.Do(mreq)
	if err != nil {
		t.Fatal(err)
	}
	mresp.Body.Close()
	if mresp.StatusCode != http.StatusNoContent || !e.central().store.IsAllowed("carol@example.com") {
		t.Fatalf("multipart access event: %d", mresp.StatusCode)
	}
	// Static directories are not listed; HEAD never starts a search.
	if r := e.get("/static/js/"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("static dir listing: %d", r.StatusCode)
	}
	e.completeLogin("/")
	if r := e.do(http.MethodHead, "/?run_search=1&mode=exact&sender=x", nil); r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD search: %d", r.StatusCode)
	}
	// The UI cookie is refreshed on every page while it carries a search owner.
	e.get("/")
	if r := e.get("/"); !strings.Contains(strings.Join(r.Header.Values("Set-Cookie"), "\n"), uiCookieName+"=") {
		t.Fatal("UI cookie not refreshed")
	}
}

func TestBackchannelWithoutLengthIs411(t *testing.T) {
	e := centralEnv(t)
	u, _ := url.Parse(e.ts.URL)
	conn, err := tlsDial(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST /auth/backchannel-logout HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), " 411 ") {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestSemicolonQueryKeepsTheJobUsable(t *testing.T) {
	e := elcanoEnv(t)
	start := e.get("/?run_search=1&mode=exact&subject=a;b")
	loc := start.Header.Get("Location")
	if strings.Contains(loc, "&b=") || strings.Contains(loc, "subject=a") {
		t.Fatalf("redirect carries a pair the signature never saw: %q", loc)
	}
	if page := e.get(loc); strings.Contains(page.body, "This search session expired") {
		t.Fatal("job lost after redirect")
	}
}

// The date fields are Explorer's own (static/js/datepicker.js): every mode
// renders text inputs holding YYYY-MM-DD, each with its calendar button,
// loads only same-origin scripts, and nothing of flatpickr remains.
func TestDateFieldsUseTheInHousePicker(t *testing.T) {
	e := elcanoEnv(t)
	today := time.Now().UTC().Format(isoDate)
	field := regexp.MustCompile(`<input type="text" class="custom-datepicker" name="(day|date_from|date_to)" value="([^"]*)" placeholder="YYYY-MM-DD" required />\s*<button type="button" class="date-input-button" data-date-button aria-label="Choose date" aria-haspopup="dialog" aria-expanded="false">`)
	for mode, names := range map[string][]string{"view": {"day"}, "exact": {"date_from", "date_to"}, "fuzzy": {"date_from", "date_to"}} {
		body := e.get("/?mode=" + mode).body
		if strings.Contains(strings.ToLower(body), "flatpickr") {
			t.Errorf("%s: flatpickr still referenced", mode)
		}
		for _, src := range []string{"js/datepicker.js", "js/date-ranges.js", "js/inbox.js"} {
			if !strings.Contains(body, `<script src="`+assetURL(src)+`"`) {
				t.Errorf("%s: missing script %s", mode, src)
			}
		}
		inbox := strings.Index(body, assetURL("js/inbox.js"))
		if inbox < 0 || strings.Index(body, assetURL("js/datepicker.js")) > inbox ||
			strings.Index(body, assetURL("js/date-ranges.js")) > inbox {
			t.Errorf("%s: helpers must load before inbox.js", mode)
		}
		got := field.FindAllStringSubmatch(body, -1)
		if len(got) != len(names) {
			t.Fatalf("%s: %d date fields, want %d:\n%s", mode, len(got), len(names), body)
		}
		for i, m := range got {
			if m[1] != names[i] || m[2] != today {
				t.Errorf("%s: field %d = %s=%q, want %s=%q", mode, i, m[1], m[2], names[i], today)
			}
		}
	}

	// A submitted range comes back as the same ISO values, ordered.
	body := e.get("/?mode=exact&date_from=2026-03-09&date_to=2026-03-02").body
	if !strings.Contains(body, `name="date_from" value="2026-03-02"`) || !strings.Contains(body, `name="date_to" value="2026-03-09"`) {
		t.Errorf("range not echoed as ordered ISO dates")
	}

	for path, want := range map[string]int{
		"/static/js/datepicker.js":                   http.StatusOK,
		"/static/js/date-ranges.js":                  http.StatusOK,
		"/static/vendor/flatpickr/flatpickr.min.js":  http.StatusNotFound,
		"/static/vendor/flatpickr/flatpickr.min.css": http.StatusNotFound,
	} {
		resp := e.get(path)
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
		if want == http.StatusOK && !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") {
			t.Errorf("GET %s content type %q", path, resp.Header.Get("Content-Type"))
		}
	}
}

// inbox.js copies the first server-rendered range row rather than holding
// its own markup, so it never hard-codes a static URL (which would miss the
// version segment) or drifts from the date_input template.
func TestScriptsHoldNoUnversionedStaticURLs(t *testing.T) {
	for _, name := range []string{"inbox.js", "datepicker.js", "date-ranges.js", "base.js", "email.js"} {
		js, err := staticFS.ReadFile("static/js/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(js), "/static/") {
			t.Errorf("%s hard-codes a /static/ URL", name)
		}
	}
}

// Every static file a page references carries the current version as a path
// segment, the vendored Flag token sheet, fonts sheet, icon sprite and logos
// included, so a deploy never mixes cached old Flag files with new product
// CSS; the fonts fonts.css loads by relative URL inherit the segment. The
// current version is immutable for a year; anything else revalidates by ETag;
// misses never get a cache header.
func TestStaticAssetsAreVersionedAndCached(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("msg1")
	e.store.put(key, sampleMessage, at)
	v := assetVersion()
	if !isVersionSegment("v-" + v) {
		t.Fatalf("asset version %q", v)
	}
	prefix := "/static/v-" + v + "/"
	ref := regexp.MustCompile(`(?:src|href)="(/static/[^"#]*)`)
	seen := map[string]bool{}
	for _, path := range []string{"/?run_search=1&mode=view", "/?mode=exact", "/email?s3_key=" + url.QueryEscape(key), "/email?s3_key=nope"} {
		for _, m := range ref.FindAllStringSubmatch(e.get(path).body, -1) {
			if !strings.HasPrefix(m[1], prefix) || strings.Contains(m[1], "?") {
				t.Errorf("%s: unversioned static URL %s", path, m[1])
			}
			seen[strings.TrimPrefix(m[1], prefix)] = true
		}
	}
	for _, want := range []string{
		"design-system/tokens/design-tokens.css", "design-system/fonts/fonts.css",
		"design-system/icons/core-icons.svg", "design-system/logos/elcano-mark-primary.svg",
		"design-system/logos/explorer-favicon.svg", "styles.css", "js/datepicker.js",
	} {
		if !seen[want] {
			t.Errorf("pages never reference %s", want)
		}
	}

	// fonts.css names its fonts relatively, so they resolve under the
	// versioned prefix and every font it names exists there.
	css, err := staticFS.ReadFile("static/design-system/fonts/fonts.css")
	if err != nil {
		t.Fatal(err)
	}
	fonts := regexp.MustCompile(`url\("?\./([^")]+)"?\)`).FindAllStringSubmatch(string(css), -1)
	if len(fonts) == 0 {
		t.Fatal("fonts.css names no relative font URLs")
	}
	immutable := "public, max-age=31536000, immutable"
	for _, m := range fonts {
		resp := e.get(prefix + "design-system/fonts/" + m[1])
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != immutable {
			t.Errorf("font %s: %d %q", m[1], resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
	}

	tokens := "design-system/tokens/design-tokens.css"
	current := e.get(prefix + tokens)
	if current.StatusCode != http.StatusOK || current.Header.Get("Cache-Control") != immutable ||
		!strings.HasPrefix(current.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("versioned: %d %q %q", current.StatusCode, current.Header.Get("Cache-Control"), current.Header.Get("Content-Type"))
	}
	etag := current.Header.Get("ETag")
	if !regexp.MustCompile(`^"[0-9a-f]{24}"$`).MatchString(etag) {
		t.Fatalf("etag %q", etag)
	}
	stale := "/static/v-0123456789ab/" + tokens
	if v == "0123456789ab" {
		stale = "/static/v-ba9876543210/" + tokens
	}
	for _, path := range []string{"/static/" + tokens, stale, "/static/" + tokens + "?v=" + v} {
		resp := e.get(path)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("ETag") != etag {
			t.Errorf("%s: %d %q etag %q", path, resp.StatusCode, resp.Header.Get("Cache-Control"), resp.Header.Get("ETag"))
		}
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.ts.URL+"/static/"+tokens, nil)
	req.Header.Set("If-None-Match", etag)
	resp, err := e.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("revalidation: %d, want 304", resp.StatusCode)
	}
	for _, path := range []string{prefix + "nope.css", prefix + "design-system/", prefix + "design-system/fonts", "/static/v-" + v} {
		miss := e.get(path)
		if miss.StatusCode != http.StatusNotFound || miss.Header.Get("Cache-Control") != "" {
			t.Errorf("%s: %d %q", path, miss.StatusCode, miss.Header.Get("Cache-Control"))
		}
	}
}

// axe findings fixed alongside the date picker: one banner landmark (the
// page <header>), and result rows that are plain buttons in a labelled group
// (a <button> may not take role="listitem").
func TestLandmarksAndResultRoles(t *testing.T) {
	e := elcanoEnv(t)
	key, at := todayKey("msg1")
	e.store.put(key, sampleMessage, at)
	body := e.get("/?run_search=1&mode=view").body
	if strings.Contains(body, `role="banner"`) || strings.Count(body, "<header") != 1 {
		t.Error("expected exactly one banner landmark, the page <header>")
	}
	if !strings.Contains(body, `id="result-list" role="group" aria-label="Email results"`) {
		t.Error("result list is not a labelled group")
	}
	if strings.Contains(body, `role="listitem"`) || strings.Contains(body, `role="list"`) {
		t.Error("buttons must not carry list roles")
	}
	if !strings.Contains(body, `<button type="button" class="inbox-row" data-open-url="/email?s3_key=`) {
		t.Error("result row markup changed")
	}
}
