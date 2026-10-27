// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/ElcanoTek/explorer/internal/apitoken"
)

// MaxBodyBytes caps one request: arguments are a handful of short strings.
const MaxBodyBytes = 64 * 1024

// Operation is one search operation, shared by REST and MCP.
type Operation struct {
	Name  string
	Scope string
	// Args are the accepted argument names, sorted.
	Args []string
	Run  func(a *API, r *http.Request, args map[string]any) (Body, error)
}

// Operations lists every operation, in catalog order.
var Operations = []Operation{
	{
		Name: "search_emails", Scope: apitoken.ScopeSearch,
		Args: []string{"date_from", "date_to", "has_payload", "include_body_preview", "max_results",
			"recipient_contains", "sender_contains", "subject_contains", "subject_keywords"},
		Run: (*API).SearchEmails,
	},
	{
		Name: "search_emails_fuzzy", Scope: apitoken.ScopeSearch,
		Args: []string{"date_from", "date_to", "keywords", "match_all", "max_results", "search_fields"},
		Run:  (*API).SearchEmailsFuzzy,
	},
	{
		Name: "find_latest_report", Scope: apitoken.ScopeSearch,
		Args: []string{"lookback_days", "max_candidates", "on_or_before", "recipient_contains",
			"require_payload", "sender_contains", "subject_contains", "subject_keywords"},
		Run: (*API).FindLatestReport,
	},
}

// FindOperation returns the named operation, or nil.
func FindOperation(name string) *Operation {
	for i := range Operations {
		if Operations[i].Name == name {
			return &Operations[i]
		}
	}
	return nil
}

// CheckArgNames refuses argument names op does not accept.
func (op *Operation) CheckArgNames(args map[string]any) error {
	var unknown []string
	for name := range args {
		if !slices.Contains(op.Args, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return invalidArg("Unknown argument(s): %s", strings.Join(unknown, ", "))
}

// Call runs op for token with panics turned into errors.
func (a *API) Call(r *http.Request, token *apitoken.Token, op *Operation, args map[string]any) (body Body, err error) {
	defer func() {
		if p := recover(); p != nil {
			a.log.Error("api operation panicked", "op", op.Name, "panic", p)
			body, err = nil, errors.New("internal error")
		}
	}()
	if err := RequireScope(token, op.Scope); err != nil {
		return nil, err
	}
	if err := op.CheckArgNames(args); err != nil {
		return nil, err
	}
	return op.Run(a, r, args)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// WriteError answers err as JSON: an *Error with its status and body,
// anything else as a logged 500.
func (a *API) WriteError(w http.ResponseWriter, err error) {
	var e *Error
	if errors.As(err, &e) {
		if e.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="explorer"`)
		}
		writeJSON(w, e.Status, e.Body())
		return
	}
	a.log.Error("api request failed", "err", err)
	writeJSON(w, http.StatusInternalServerError, InternalErrorBody())
}

// Routes serves POST /api/v1/<operation> with a JSON object of arguments,
// and GET /api/v1/ listing the operations the token may call.
func (a *API) Routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := a.Authenticate(r)
		if err != nil {
			a.WriteError(w, err)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/")
		if name == "" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				a.WriteError(w, apiErr(http.StatusMethodNotAllowed, "method_not_allowed", "Use GET"))
				return
			}
			ops := []Body{}
			for _, op := range Operations {
				if token.Allows(op.Scope) {
					ops = append(ops, Body{"name": op.Name, "path": "/api/v1/" + op.Name, "arguments": op.Args})
				}
			}
			writeJSON(w, http.StatusOK, Body{"ok": true, "operations": ops})
			return
		}
		op := FindOperation(name)
		if op == nil || !token.Allows(op.Scope) {
			a.WriteError(w, apiErr(http.StatusNotFound, "not_found", "No such operation: %s", name))
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			a.WriteError(w, apiErr(http.StatusMethodNotAllowed, "method_not_allowed", "Use POST with a JSON object of arguments"))
			return
		}
		raw, err := ReadBodyCapped(r, MaxBodyBytes)
		if err != nil {
			a.WriteError(w, err)
			return
		}
		args := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			trimmed := bytes.TrimLeft(raw, " \t\r\n")
			if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(raw, &args) != nil {
				a.WriteError(w, invalidArg("The request body must be a JSON object of arguments"))
				return
			}
		}
		body, err := a.Call(r, token, op, args)
		if err != nil {
			a.WriteError(w, err)
			return
		}
		out := Body{"ok": true}
		for k, v := range body {
			out[k] = v
		}
		writeJSON(w, http.StatusOK, out)
	})
}
