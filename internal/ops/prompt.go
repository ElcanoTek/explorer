// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// prompter asks the installer's questions. A value already supplied (by the
// existing .env or the environment) is never asked for, which is what lets
// scripted installs pre-answer every prompt through EXPLORER_* variables.
type prompter struct {
	u              *ui
	in             *bufio.Reader
	fd             int // terminal descriptor for hidden input, or -1
	nonInteractive bool
}

// newPrompter reads answers from the terminal: like the shell installer's
// `exec </dev/tty`, a piped stdin (curl | bash) does not swallow them.
func newPrompter(u *ui, nonInteractive bool) *prompter {
	var in io.Reader = os.Stdin
	fd := -1
	stdinTTY := term.IsTerminal(int(os.Stdin.Fd()))
	stdoutTTY := term.IsTerminal(int(os.Stdout.Fd()))
	switch {
	case stdinTTY:
		fd = int(os.Stdin.Fd())
	case stdoutTTY:
		if tty, err := os.Open("/dev/tty"); err == nil {
			in = tty
			fd = int(tty.Fd())
		}
	}
	return &prompter{u: u, in: bufio.NewReader(in), fd: fd, nonInteractive: nonInteractive}
}

func (pr *prompter) ask(label string) string {
	fmt.Fprintf(pr.u.errw, "%s %s ", pr.u.paint("\033[0;36m", "?"), label)
	line, _ := pr.in.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// value returns current when it is non-empty; otherwise asks, offering def.
// Non-interactive runs take def, and fail when def is empty unless
// allowBlank.
func (pr *prompter) value(current, varname, label, def string, allowBlank bool) (string, error) {
	if current != "" {
		return current, nil
	}
	if pr.nonInteractive {
		if def == "" && !allowBlank {
			return "", fmt.Errorf("non-interactive + missing: set %s", varname)
		}
		return def, nil
	}
	q := label + ":"
	if def != "" {
		q = label + " " + pr.u.dim("["+def+"]") + ":"
	}
	answer := pr.ask(q)
	if answer == "" {
		answer = def
	}
	return answer, nil
}

// secret asks for a required value without echoing it.
func (pr *prompter) secret(current, varname, label string, required bool) (string, error) {
	if current != "" {
		return current, nil
	}
	if pr.nonInteractive {
		if required {
			return "", fmt.Errorf("non-interactive + missing: set %s", varname)
		}
		return "", nil
	}
	fmt.Fprintf(pr.u.errw, "%s %s: ", pr.u.paint("\033[0;36m", "?"), label)
	var answer string
	if pr.fd >= 0 {
		raw, err := term.ReadPassword(pr.fd)
		if err != nil {
			return "", err
		}
		answer = string(raw)
	} else {
		line, _ := pr.in.ReadString('\n')
		answer = strings.TrimRight(line, "\r\n")
	}
	fmt.Fprintln(pr.u.errw)
	if answer == "" && required {
		return "", errors.New(varname + " is required")
	}
	return answer, nil
}

func yes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}
