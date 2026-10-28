// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/ElcanoTek/explorer/internal/centralauth"
	"github.com/ElcanoTek/explorer/internal/config"
)

const accessUsage = `usage:
  explorer access grant EMAIL       allow a central account to use Explorer
  explorer access list [--all]      list allowed (or all known) emails
  explorer access revoke EMAIL      deny access and revoke Explorer sessions
  explorer access backup [PATH]     consistent copy of the access database
                                    (default /var/backups/explorer/access-<UTC time>.db)
`

// accessAppDir is the installed application directory the access list
// belongs to: EXPLORER_APP_DIR or APP_DIR when set, /opt/explorer when it is
// installed, else the working directory (a development checkout).
func accessAppDir() string {
	for _, k := range []string{"EXPLORER_APP_DIR", "APP_DIR"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if st, err := os.Stat("/opt/explorer"); err == nil && st.IsDir() {
		return "/opt/explorer"
	}
	return config.AppDir()
}

func accessCommand(argv []string) int {
	return runAccess(argv, os.Stdout, os.Stderr)
}

func runAccess(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("explorer access", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, accessUsage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	argv = pinRelativePaths(argv, args, db)
	appDir := accessAppDir()
	if code, handed := handOffToServiceUser(appDir, "access", argv); handed {
		return code
	}
	settings, _, err := config.Load(appDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if settings.AuthMode != "central" {
		fmt.Fprintln(stderr, "error: access commands require EXPLORER_AUTH_MODE=central")
		return 1
	}
	path := settings.AccessDB
	if *db != "" {
		path = *db
	}

	command, rest := args[0], args[1:]
	listFlags := flag.NewFlagSet("explorer access list", flag.ContinueOnError)
	listFlags.SetOutput(stderr)
	all := listFlags.Bool("all", false, "include previously revoked emails")
	switch command {
	case "grant", "revoke":
		if len(rest) != 1 {
			fs.Usage()
			return 2
		}
	case "list":
		if err := listFlags.Parse(rest); err != nil || listFlags.NArg() != 0 {
			fs.Usage()
			return 2
		}
	case "backup":
		if len(rest) > 1 {
			fs.Usage()
			return 2
		}
	default:
		fs.Usage()
		return 2
	}

	store, err := centralauth.OpenStore(path,
		time.Duration(settings.SessionIdleSeconds)*time.Second, time.Duration(settings.SessionAbsoluteSeconds)*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	return execAccess(store, command, rest, *all, stdout, stderr)
}

// pinRelativePaths makes the backup destination and --db absolute (in both
// argv and the parsed values): the hand-off to the service user runs from "/".
func pinRelativePaths(argv, args []string, db *string) []string {
	// The hand-off below runs from "/", so pin relative paths now: the
	// backup destination and --db.
	argv = append([]string{}, argv...)
	if args[0] == "backup" && len(args) == 2 && !filepath.IsAbs(args[1]) {
		if abs, err := filepath.Abs(args[1]); err == nil {
			argv[len(argv)-1] = abs
			args[1] = abs
		}
	}
	if *db != "" && !filepath.IsAbs(*db) {
		if abs, err := filepath.Abs(*db); err == nil {
			for i, a := range argv {
				switch {
				case (a == "-db" || a == "--db") && i+1 < len(argv):
					argv[i+1] = abs
				case strings.HasPrefix(a, "-db=") || strings.HasPrefix(a, "--db="):
					argv[i] = "--db=" + abs
				}
			}
			*db = abs
		}
	}
	return argv
}

// execAccess runs one parsed access subcommand against the open store.
func execAccess(store *centralauth.Store, command string, rest []string, all bool, stdout, stderr io.Writer) int {
	switch command {
	case "grant":
		entry, err := store.GrantAccess(rest[0])
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Granted Explorer access: %s\n", entry.Email)
	case "revoke":
		email, err := centralauth.NormalizeEmail(rest[0])
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		revoked, err := store.RevokeAccess(email)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if !revoked {
			fmt.Fprintln(stderr, "error: Email is not currently allowed")
			return 1
		}
		fmt.Fprintf(stdout, "Revoked Explorer access and sessions: %s\n", email)
	case "list":
		entries, err := store.ListAccess(all)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Fprintln(stdout, "No emails have Explorer access.")
		}
		for _, e := range entries {
			status := "allowed"
			if !e.Enabled {
				status = "revoked"
			}
			fmt.Fprintf(stdout, "%s\t%s\n", e.Email, status)
		}
	case "backup":
		dest := "/var/backups/explorer/access-" + time.Now().UTC().Format("20060102T150405Z") + ".db"
		if len(rest) == 1 {
			dest = rest[0]
		}
		if err := store.Backup(context.Background(), dest); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, dest)
	}
	return 0
}

// handOffToServiceUser re-runs `explorer VERB argv...` as the explorer
// service account on an installed box: the database directory is private to
// it, and files SQLite creates (the WAL) must stay owned by it.
func handOffToServiceUser(appDir, verb string, argv []string) (int, bool) {
	if os.Getenv("EXPLORER_ACCESS_NO_HANDOFF") == "1" {
		return 0, false
	}
	svc, err := user.Lookup("explorer")
	if err != nil {
		return 0, false
	}
	if fmt.Sprint(os.Getuid()) == svc.Uid {
		return 0, false
	}
	bin := appDir + "/bin/explorer"
	if _, err := os.Stat(bin); err != nil {
		return 0, false
	}
	args := make([]string, 0, 8+len(argv))
	args = append(args, "-u", "explorer", "--", "env", "EXPLORER_APP_DIR="+appDir,
		"EXPLORER_ACCESS_NO_HANDOFF=1", bin, verb)
	args = append(args, argv...)
	cmd := exec.CommandContext(context.Background(), "sudo", args...) //nolint:gosec // G204: fixed sudo invocation of the root-owned installed binary.
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), true
		}
		fmt.Fprintf(os.Stderr, "error: could not run as the explorer user: %v\n", strings.TrimSpace(err.Error()))
		return 1, true
	}
	return 0, true
}
