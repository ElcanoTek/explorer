// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// Cmd is one external command. Env nil inherits the process environment.
type Cmd struct {
	Name    string
	Args    []string
	Dir     string
	Env     []string
	Stdin   io.Reader
	Timeout time.Duration
}

// Result is a finished command. Code is 127 when the command could not be
// started or timed out: "this tool could not answer", never a verdict.
type Result struct {
	Code   int
	Stdout string
	Stderr string
}

// Runner runs external commands. Tests substitute a fake so systemctl,
// dnf, git and friends never touch the host.
type Runner interface {
	// Run captures output.
	Run(ctx context.Context, c Cmd) Result
	// Interactive connects the command to this process's terminal and
	// returns its exit code.
	Interactive(ctx context.Context, c Cmd) int
	// LookPath reports whether a command is installed.
	LookPath(name string) (string, bool)
}

type execRunner struct{}

var lookPath = exec.LookPath

func (execRunner) LookPath(name string) (string, bool) {
	p, err := lookPath(name)
	return p, err == nil
}

func (execRunner) command(ctx context.Context, c Cmd) (*exec.Cmd, context.CancelFunc) {
	cancel := context.CancelFunc(func() {})
	if c.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
	}
	cmd := exec.CommandContext(ctx, c.Name, c.Args...) //nolint:gosec // G204: fixed system commands with installer-built arguments.
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	cmd.WaitDelay = 5 * time.Second
	return cmd, cancel
}

func (r execRunner) Run(ctx context.Context, c Cmd) Result {
	cmd, cancel := r.command(ctx, c)
	defer cancel()
	var out, errb bytes.Buffer
	cmd.Stdin = c.Stdin
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.ExitCode() >= 0 && ctx.Err() == nil:
		res.Code = ee.ExitCode()
	default:
		res.Code = 127
	}
	return res
}

func (r execRunner) Interactive(ctx context.Context, c Cmd) int {
	cmd, cancel := r.command(ctx, c)
	defer cancel()
	cmd.Stdin = os.Stdin
	if c.Stdin != nil {
		cmd.Stdin = c.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode()
	default:
		return 127
	}
}
