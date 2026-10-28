// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

// Package mcp is Explorer as an MCP server: POST /mcp (Streamable HTTP,
// stateless, JSON), the same transport as Lens's.
//
// This is how Fleet (or any MCP host) searches the email archive. Every tool
// is a thin adapter over an internal/api operation, so the REST API and MCP
// cannot drift apart, and both authenticate with the same scoped bearer
// token (`explorer token create`).
//
// Transport scope, deliberately small:
//
//   - Stateless. No Mcp-Session-Id is issued, every POST stands alone, and
//     responses are plain application/json (the spec allows a server to
//     answer with JSON instead of an SSE stream). GET and DELETE return 405
//     because there is no server-initiated stream or session to end.
//   - One JSON-RPC message per POST. Batches were removed from the protocol
//     in 2025-06-18 and are refused.
//   - Tools only (tools/list, tools/call), plus initialize and ping.
//     tools/list shows a token only the tools its scopes allow, and
//     tools/call re-checks the scope, so hiding is never the only gate.
//
// The tool names, schemas, descriptions and server instructions live in
// tools.json: hosts and models key on that text, so it changes only
// deliberately.
package mcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/ElcanoTek/explorer/internal/api"
	"github.com/ElcanoTek/explorer/internal/apitoken"
)

//go:embed tools.json
var toolsJSON []byte

type toolDef struct {
	Name        string          `json:"name"`
	Scope       string          `json:"scope"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations"`

	properties []string
	required   []string
	op         *api.Operation
}

type definitions struct {
	Instructions string          `json:"instructions"`
	ServerInfo   json.RawMessage `json:"serverInfo"`
	// ProtocolVersions are the Streamable HTTP revisions, newest first. A
	// client asking for one of these gets it back; anything else gets the
	// newest. 2024-11-05 is absent: it used the old HTTP+SSE transport,
	// which this server does not implement.
	ProtocolVersions []string  `json:"protocolVersions"`
	Tools            []toolDef `json:"tools"`
}

var defs = loadDefinitions()

// loadDefinitions parses tools.json and binds each tool to its operation;
// a tool without an operation, or whose schema and operation disagree on
// the argument names or scope, is a build-time mistake.
func loadDefinitions() definitions {
	var d definitions
	if err := json.Unmarshal(toolsJSON, &d); err != nil {
		panic("mcp: tools.json: " + err.Error())
	}
	for i := range d.Tools {
		t := &d.Tools[i]
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		}
		if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
			panic("mcp: tools.json: " + err.Error())
		}
		for name := range schema.Properties {
			t.properties = append(t.properties, name)
		}
		sort.Strings(t.properties)
		t.required = schema.Required
		t.op = api.FindOperation(t.Name)
		if t.op == nil || t.op.Scope != t.Scope || !slices.Equal(t.op.Args, t.properties) {
			panic("mcp: tools.json: tool " + t.Name + " does not match its api operation")
		}
	}
	return d
}

// SupportedProtocolVersions lists the protocol revisions served, newest first.
func SupportedProtocolVersions() []string { return slices.Clone(defs.ProtocolVersions) }

// ToolNames lists every tool, in listing order.
func ToolNames() []string {
	names := make([]string, len(defs.Tools))
	for i, t := range defs.Tools {
		names[i] = t.Name
	}
	return names
}

// MaxBodyBytes caps one request (the arguments are a handful of strings).
const MaxBodyBytes = api.MaxBodyBytes

// Server is the /mcp endpoint.
type Server struct {
	api *api.API
	// MaxBodyBytes caps a request body (default MaxBodyBytes).
	MaxBodyBytes int64
}

// New returns the /mcp handler over a. Mount it with mux.Handle("/mcp", s).
func New(a *api.API) *Server {
	return &Server{api: a, MaxBodyBytes: MaxBodyBytes}
}

func findTool(name string) *toolDef {
	for i := range defs.Tools {
		if defs.Tools[i].Name == name {
			return &defs.Tools[i]
		}
	}
	return nil
}

type listedTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations"`
}

func toolListing(token *apitoken.Token) []listedTool {
	out := []listedTool{}
	for _, t := range defs.Tools {
		if token.Allows(t.Scope) {
			out = append(out, listedTool{t.Name, t.Title, t.Description, t.InputSchema, t.Annotations})
		}
	}
	return out
}

// checkRequired makes the structural check a host might skip; the API
// validates names and values.
func checkRequired(tool *toolDef, args map[string]any) error {
	var missing []string
	for _, name := range tool.required {
		if v, ok := args[name]; !ok || v == nil || v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return &api.Error{Status: http.StatusBadRequest, Code: "invalid_argument",
			Message: "Missing required argument(s): " + strings.Join(missing, ", ")}
	}
	return nil
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func textResult(body api.Body, isError bool) (map[string]any, error) {
	text, err := encodeJSON(body)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		// Hosts such as Fleet pass only text content to the model, so the
		// text carries the whole structured result.
		"content":           []any{map[string]any{"type": "text", "text": string(text)}},
		"structuredContent": json.RawMessage(text),
		"isError":           isError,
	}, nil
}

type rpcError struct {
	code    int
	message string
}

func (e *rpcError) Error() string { return e.message }

func describe(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func (s *Server) callTool(r *http.Request, token *apitoken.Token, params map[string]any) (map[string]any, error) {
	var tool *toolDef
	if name, isString := params["name"].(string); isString {
		tool = findTool(name)
	}
	if tool == nil || !token.Allows(tool.Scope) {
		return nil, &rpcError{-32602, "Unknown tool: " + describe(params["name"])}
	}
	rawArgs := params["arguments"]
	if rawArgs == nil {
		rawArgs = map[string]any{}
	}
	args, ok := rawArgs.(map[string]any)
	if !ok {
		return nil, &rpcError{-32602, "arguments must be an object"}
	}
	body, err := s.runTool(r, token, tool, args)
	if err != nil {
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			return textResult(apiErr.Body(), true)
		}
		// Report, never leak an internal error's detail to the caller.
		s.api.Logger().Error(fmt.Sprintf("MCP tool %s failed: %v", tool.Name, err))
		return textResult(api.InternalErrorBody(), true)
	}
	out := api.Body{"ok": true}
	for k, v := range body {
		out[k] = v
	}
	return textResult(out, false)
}

func (s *Server) runTool(r *http.Request, token *apitoken.Token, tool *toolDef, args map[string]any) (api.Body, error) {
	if err := tool.op.CheckArgNames(args); err != nil {
		return nil, err
	}
	if err := checkRequired(tool, args); err != nil {
		return nil, err
	}
	return s.api.Call(r, token, tool.op, args)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	raw, err := encodeJSON(body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, status int) {
	if id == nil {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{
		"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message},
	})
}

// originAllowed is the spec's DNS-rebinding guard: a browser Origin must be
// this host (the request's, or EXPLORER_PUBLIC_URL's). Server-to-server
// callers (Fleet) send none.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	got := strings.ToLower(u.Host)
	return got == strings.ToLower(r.Host) || (s.api.PublicHost() != "" && got == s.api.PublicHost())
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// ServeHTTP implements POST /mcp.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Stateless JSON server: no SSE stream to open and no session to end.
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.originAllowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "Origin not allowed"})
		return
	}
	token, err := s.api.Authenticate(r)
	if err != nil {
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="explorer"`)
			writeJSON(w, http.StatusUnauthorized, apiErr.Body())
			return
		}
		s.api.Logger().Error("MCP token lookup failed: " + err.Error())
		writeJSON(w, http.StatusInternalServerError, api.InternalErrorBody())
		return
	}

	raw, err := api.ReadBodyCapped(r, s.MaxBodyBytes)
	if err != nil {
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			writeRPCError(w, nil, -32600, "Request too large", http.StatusRequestEntityTooLarge)
		} else {
			writeRPCError(w, nil, -32700, "Parse error", http.StatusBadRequest)
		}
		return
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		writeRPCError(w, nil, -32700, "Parse error", http.StatusBadRequest)
		return
	}
	if _, isBatch := decoded.([]any); isBatch {
		writeRPCError(w, nil, -32600, "Batch requests are not supported", http.StatusBadRequest)
		return
	}
	var message map[string]json.RawMessage
	var version string
	if !isJSONObject(raw) || json.Unmarshal(raw, &message) != nil ||
		json.Unmarshal(message["jsonrpc"], &version) != nil || version != "2.0" {
		writeRPCError(w, nil, -32600, "Invalid Request", http.StatusBadRequest)
		return
	}
	id, hasID := message["id"]
	if !hasID {
		// Notifications (initialized, cancelled, …) and stray responses need
		// no reply.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var method string
	if json.Unmarshal(message["method"], &method) != nil {
		writeRPCError(w, id, -32600, "Invalid Request", http.StatusBadRequest)
		return
	}
	// Only an absent or null params means "none"; [] / false / 0 are invalid.
	params := map[string]any{}
	if rawParams, ok := message["params"]; ok && string(bytes.TrimSpace(rawParams)) != "null" {
		if !isJSONObject(rawParams) || json.Unmarshal(rawParams, &params) != nil {
			writeRPCError(w, id, -32602, "params must be an object", http.StatusOK)
			return
		}
	}

	var result any
	switch method {
	case "initialize":
		version := defs.ProtocolVersions[0]
		if requested, ok := params["protocolVersion"].(string); ok && slices.Contains(defs.ProtocolVersions, requested) {
			version = requested
		}
		result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      defs.ServerInfo,
			"instructions":    defs.Instructions,
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": toolListing(token)}
	case "tools/call":
		out, err := s.callTool(r, token, params)
		if err != nil {
			var rpc *rpcError
			if errors.As(err, &rpc) {
				writeRPCError(w, id, rpc.code, rpc.message, http.StatusOK)
				return
			}
			s.api.Logger().Error("MCP tools/call failed: " + err.Error())
			writeRPCError(w, id, -32603, "Internal error", http.StatusOK)
			return
		}
		result = out
	default:
		writeRPCError(w, id, -32601, "Method not found: "+method, http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
