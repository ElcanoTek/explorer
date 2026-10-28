// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package api is programmatic Explorer: the archive searches Fleet's agents
// run, served as /api/v1 REST routes and shared with the MCP endpoint
// (internal/mcp), so the two cannot drift apart.
//
// Everything here authenticates with a scoped bearer token from
// internal/apitoken and never with a browser session, so the UI's cookie and
// CSRF rules and this surface cannot leak into each other.
//
// The three operations keep the contract of the Python tools they replace
// in the agent bundles (search_emails, search_emails_fuzzy,
// find_latest_report): the same argument names, the same result fields and
// warning codes, and the s3_key the bundles' remaining email tools take. See
// docs/API.md; it is what Fleet depends on, so response shapes, error codes
// and messages here must not drift.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/smithy-go"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/archive"
	"github.com/ElcanoTek/explorer/internal/config"
)

// Body is a JSON response body.
type Body = map[string]any

// Error is a failure with a stable code and a message written for the
// caller. REST answers with it as {"ok": false, "status": "error", "error",
// "code"}; MCP returns the same body as an isError tool result.
type Error struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
	Details   map[string]any
}

func (e *Error) Error() string { return e.Message }

// Body is the JSON error body. "status": "error" matches the Python tools'
// results, which agent prompts check.
func (e *Error) Body() Body {
	body := Body{"ok": false, "status": "error", "error": e.Message, "code": e.Code}
	if e.Retryable {
		body["retryable"] = true
	}
	for k, v := range e.Details {
		body[k] = v
	}
	return body
}

// InternalErrorBody is what a caller sees for an unexpected failure; the
// detail goes to the log only.
func InternalErrorBody() Body {
	return Body{"ok": false, "status": "error", "error": "Internal error", "code": "internal_error"}
}

func apiErr(status int, code, format string, args ...any) *Error {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	return &Error{Status: status, Code: code, Message: msg}
}

func invalidArg(format string, args ...any) *Error {
	return apiErr(http.StatusBadRequest, "invalid_argument", format, args...)
}

// API serves /api/v1 and implements the operations MCP shares. Safe for
// concurrent use.
type API struct {
	inbox    *archive.Inbox
	settings config.Settings
	tokens   *apitoken.Store
	log      *slog.Logger
	now      func() time.Time
}

// Deps are what the API needs from the running service.
type Deps struct {
	Inbox    *archive.Inbox
	Settings config.Settings
	Tokens   *apitoken.Store
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// New returns the API over deps.
func New(d Deps) *API {
	a := &API{inbox: d.Inbox, settings: d.Settings, tokens: d.Tokens, log: d.Logger, now: d.Now}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	return a
}

// Logger is the API's logger (MCP logs tool failures with it).
func (a *API) Logger() *slog.Logger { return a.log }

// Authenticate resolves the request's bearer token. A missing or unusable
// token is a 401 *Error; any other error is a storage failure.
func (a *API) Authenticate(r *http.Request) (*apitoken.Token, error) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "bearer") || strings.TrimSpace(raw) == "" {
		return nil, apiErr(http.StatusUnauthorized, "unauthorized",
			"Missing API token. Send 'Authorization: Bearer explorer_…' with a token from "+
				"`explorer token create` on the Explorer host.")
	}
	token, err := a.tokens.Verify(r.Context(), raw)
	if err != nil {
		var te *apitoken.TokenError
		if errors.As(err, &te) {
			return nil, apiErr(http.StatusUnauthorized, "unauthorized", "%s", te.Error())
		}
		return nil, err
	}
	return token, nil
}

// RequireScope refuses a token without scope with a 403 *Error.
func RequireScope(token *apitoken.Token, scope string) error {
	if token.Allows(scope) {
		return nil
	}
	return apiErr(http.StatusForbidden, "forbidden",
		"This token lacks the %s scope (it has: %s).", scope, strings.Join(token.Scopes, " "))
}

// cappedReader fails once more than limit bytes arrived, so a chunked body
// cannot make the server buffer an unbounded request.
type cappedReader struct {
	r       io.Reader
	limit   int64
	n       int64
	tripped bool
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.tripped {
		return 0, c.err()
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		c.tripped = true
		return n, c.err()
	}
	return n, err
}

func (c *cappedReader) err() *Error {
	return apiErr(http.StatusRequestEntityTooLarge, "too_large", "Request body exceeds %d bytes", c.limit)
}

// ReadBodyCapped returns the request body, refused with a 413 too_large
// *Error as soon as it passes limit.
func ReadBodyCapped(r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, apiErr(http.StatusRequestEntityTooLarge, "too_large", "Request body exceeds %d bytes", limit)
	}
	if r.Body == nil {
		return []byte{}, nil
	}
	body := &cappedReader{r: r.Body, limit: limit}
	data, err := io.ReadAll(body)
	if body.tripped {
		return nil, body.err()
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// PublicHost is the configured public URL's host (EXPLORER_PUBLIC_URL), for
// the MCP Origin check; "" when unset.
func (a *API) PublicHost() string {
	raw := strings.TrimSpace(a.settings.PublicURL)
	if raw == "" {
		return ""
	}
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		rest = raw
	}
	host, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(host)
}

// withDeadline bounds one call by EXPLORER_API_MAX_SECONDS.
func (a *API) withDeadline(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), time.Duration(a.settings.APIMaxSeconds)*time.Second)
}

// archiveError turns a failed archive read into an *Error the caller can
// act on: S3 trouble is retryable and names the S3 error code (never the
// request or credentials), a missing bucket is a configuration error, and a
// timeout says which limit it hit.
func (a *API) archiveError(op string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		e := apiErr(http.StatusGatewayTimeout, "timeout",
			"The search took longer than %ds and was stopped. Narrow the date window or the filters and retry.",
			a.settings.APIMaxSeconds)
		e.Retryable = true
		return e
	case errors.Is(err, context.Canceled):
		return apiErr(499, "cancelled", "The request was cancelled.")
	case errors.Is(err, archive.ErrBucketUnset):
		return apiErr(http.StatusServiceUnavailable, "not_configured",
			"This Explorer has no email archive configured (EMAIL_S3_BUCKET is unset).")
	}
	code := "unknown"
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code = apiError.ErrorCode()
	}
	a.log.Error("archive read failed", "op", op, "err", err)
	e := apiErr(http.StatusBadGateway, "archive_unavailable",
		"The email archive could not be read (S3 error %s), so the search did not complete. "+
			"Do not treat this as 'no matching email'; retry later.", code)
	e.Retryable = true
	return e
}
