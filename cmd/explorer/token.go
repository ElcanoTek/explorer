// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ElcanoTek/explorer/internal/apitoken"
	"github.com/ElcanoTek/explorer/internal/config"
)

//nolint:gosec // G101: help text that mentions tokens, not a credential.
const tokenUsage = `usage:
  explorer token create --label NAME [--json]
                                    mint an email:search token for /mcp and /api/v1
                                    (shown once; Explorer stores only its hash)
  explorer token list               show tokens (never their secrets)
  explorer token revoke ID          revoke a token by id
`

func tokenCommand(argv []string) int {
	appDir := accessAppDir()
	if code, handed := handOffToServiceUser(appDir, "token", argv); handed {
		return code
	}
	settings, _, err := config.Load(appDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	store := apitoken.NewStore(settings.APITokenDB)
	defer func() { _ = store.Close() }()
	return runToken(context.Background(), argv, os.Stdout, os.Stderr, store, settings.PublicURL)
}

func tokenUsageError(stderr io.Writer, msg string) int {
	fmt.Fprint(stderr, tokenUsage)
	fmt.Fprintf(stderr, "error: %s\n", msg)
	return 2
}

// runToken executes one parsed token subcommand: 0 on success, 1 on an
// operational error, 2 on a usage error.
func runToken(ctx context.Context, argv []string, stdout, stderr io.Writer, store *apitoken.Store, publicURL string) int {
	if len(argv) == 0 {
		return tokenUsageError(stderr, "a subcommand is required")
	}
	command, rest := argv[0], argv[1:]
	switch command {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, tokenUsage)
		return 0
	case "create":
		label, asJSON, hasLabel := "", false, false
		for len(rest) > 0 {
			arg := rest[0]
			rest = rest[1:]
			name, value, hasValue := strings.Cut(arg, "=")
			switch name {
			case "-h", "--help":
				fmt.Fprint(stdout, tokenUsage)
				return 0
			case "--json":
				if hasValue {
					return tokenUsageError(stderr, "--json takes no value")
				}
				asJSON = true
			case "--label":
				if !hasValue {
					if len(rest) == 0 {
						return tokenUsageError(stderr, "--label needs a value")
					}
					value, rest = rest[0], rest[1:]
				}
				label, hasLabel = value, true
			default:
				return tokenUsageError(stderr, "unrecognized argument: "+arg)
			}
		}
		if !hasLabel {
			return tokenUsageError(stderr, "--label is required")
		}
		token, raw, err := store.Create(ctx, label, apitoken.Scopes)
		if err != nil {
			return tokenOperational(stderr, err)
		}
		if asJSON {
			out, _ := json.Marshal(map[string]any{"id": token.ID, "label": token.Label, "scopes": token.Scopes, "token": raw})
			fmt.Fprintln(stdout, string(out))
			return 0
		}
		fmt.Fprintf(stdout, "Created token %d (%s) with scopes: %s\n", token.ID, token.Label, strings.Join(token.Scopes, " "))
		fmt.Fprint(stdout, "Copy it now; Explorer stores only its hash and cannot show it again:\n\n")
		fmt.Fprintf(stdout, "  %s\n\n", raw)
		base := strings.TrimRight(strings.TrimSpace(publicURL), "/")
		if base == "" {
			base = "https://<this host>"
		}
		fmt.Fprintln(stdout, "For Fleet, set in its .env:")
		fmt.Fprintf(stdout, "  EXPLORER_MCP_URL=%s/mcp\n", base)
		fmt.Fprintln(stdout, "  EXPLORER_API_TOKEN=<the token above>")
		return 0
	case "list":
		if len(rest) > 0 {
			return tokenUsageError(stderr, "list takes no arguments")
		}
		tokens, err := store.List(ctx)
		if err != nil {
			return tokenOperational(stderr, err)
		}
		if len(tokens) == 0 {
			fmt.Fprintln(stdout, "No API tokens. Create one with: explorer token create --label NAME")
			return 0
		}
		fmt.Fprintf(stdout, "%4s  %-8s  %-18s  %-14s  %-25s  LABEL\n", "ID", "STATE", "PREFIX", "SCOPES", "LAST USED")
		for _, t := range tokens {
			state := "active"
			if t.RevokedAt != "" {
				state = "revoked"
			}
			lastUsed := t.LastUsedAt
			if lastUsed == "" {
				lastUsed = "never"
			}
			fmt.Fprintf(stdout, "%4d  %-8s  %-18s  %-14s  %-25s  %s\n",
				t.ID, state, t.Prefix+"…", strings.Join(t.Scopes, " "), lastUsed, t.Label)
		}
		return 0
	case "revoke":
		if len(rest) != 1 {
			return tokenUsageError(stderr, "revoke takes exactly one token id")
		}
		id, err := strconv.ParseInt(strings.TrimSpace(rest[0]), 10, 64)
		if err != nil {
			return tokenUsageError(stderr, fmt.Sprintf("invalid token id %q", rest[0]))
		}
		revoked, err := store.Revoke(ctx, id)
		if err != nil {
			return tokenOperational(stderr, err)
		}
		if !revoked {
			fmt.Fprintf(stderr, "error: no active token with id %d\n", id)
			return 1
		}
		fmt.Fprintf(stdout, "Revoked token %d.\n", id)
		return 0
	default:
		return tokenUsageError(stderr, fmt.Sprintf("unknown subcommand %q", command))
	}
}

func tokenOperational(stderr io.Writer, err error) int {
	var verr *apitoken.ValidationError
	if errors.As(err, &verr) {
		fmt.Fprintf(stderr, "error: %s\n", verr.Error())
	} else {
		fmt.Fprintf(stderr, "error: %v\n", err)
	}
	return 1
}
