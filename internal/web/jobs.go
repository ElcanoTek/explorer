// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ElcanoTek/explorer/internal/archive"
)

// Long searches run in the background so a page can poll them, show an
// elapsed counter and offer Cancel. Jobs and view cursors live in memory
// only, scoped to the browser that started them and dropped after 15 idle
// minutes.
const (
	searchJobTTL  = 15 * time.Minute
	viewCursorTTL = 15 * time.Minute
)

type jobStatus string

const (
	jobRunning    jobStatus = "running"
	jobCancelling jobStatus = "cancelling"
	jobCancelled  jobStatus = "cancelled"
	jobDone       jobStatus = "done"
	jobError      jobStatus = "error"
)

// searchJob is a snapshot; the live copy is only touched under jobStore.mu.
type searchJob struct {
	Signature    string
	OwnerID      string
	Status       jobStatus
	CancelReason string
	Rows         []archive.Row
	Scanned      int
	Err          string
	StartedAt    time.Time
	CompletedAt  time.Time
	expiresAt    time.Time
	cancel       context.CancelCauseFunc
}

type viewCursor struct {
	state     *archive.CursorState
	signature string
	ownerID   string
	expiresAt time.Time
}

// errUserCancel and errTimeout are the causes a job context is cancelled
// with, which become the "user" / "timeout" reasons the page explains.
var (
	errUserCancel = errors.New("search cancelled by user")
	errTimeout    = errors.New("search timed out")
)

type jobStore struct {
	mu      sync.Mutex
	jobs    map[string]*searchJob
	cursors map[string]*viewCursor
	now     func() time.Time
}

func newJobStore(now func() time.Time) *jobStore {
	return &jobStore{jobs: map[string]*searchJob{}, cursors: map[string]*viewCursor{}, now: now}
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *jobStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, j := range s.jobs {
		if !j.expiresAt.After(now) {
			if j.cancel != nil {
				j.cancel(errUserCancel)
			}
			delete(s.jobs, id)
		}
	}
	for id, c := range s.cursors {
		if !c.expiresAt.After(now) {
			delete(s.cursors, id)
		}
	}
}

// start registers a job and runs fn in the background with a context that
// ends on Cancel or after maxRuntime.
func (s *jobStore) start(signature, owner string, maxRuntime time.Duration,
	fn func(ctx context.Context) ([]archive.Row, int, error),
) string {
	id := newID()
	ctx, cancel := context.WithCancelCause(context.Background())
	ctx, stopTimer := context.WithTimeoutCause(ctx, maxRuntime, errTimeout)
	now := s.now()
	s.mu.Lock()
	s.jobs[id] = &searchJob{
		Signature: signature, OwnerID: owner, Status: jobRunning,
		StartedAt: now, expiresAt: now.Add(searchJobTTL), cancel: cancel,
	}
	s.mu.Unlock()
	go func() {
		defer stopTimer()
		defer cancel(nil)
		rows, scanned, err := fn(ctx)
		s.mu.Lock()
		defer s.mu.Unlock()
		j, ok := s.jobs[id]
		if !ok {
			return
		}
		j.CompletedAt = s.now()
		j.expiresAt = j.CompletedAt.Add(searchJobTTL)
		cause := context.Cause(ctx)
		switch {
		case ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, errUserCancel) || errors.Is(err, errTimeout)):
			j.Status = jobCancelled
			j.Rows, j.Scanned = nil, 0
			if errors.Is(cause, errTimeout) {
				j.CancelReason = "timeout"
			} else if j.CancelReason == "" {
				j.CancelReason = "user"
			}
		case err != nil:
			j.Status, j.Err = jobError, err.Error()
		default:
			j.Status, j.Rows, j.Scanned = jobDone, rows, scanned
		}
		j.cancel = nil
	}()
	return id
}

// load returns a snapshot of the job when it exists, is live, matches the
// search signature and belongs to owner.
func (s *jobStore) load(id, signature, owner string) *searchJob {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil
	}
	if !j.expiresAt.After(s.now()) {
		delete(s.jobs, id)
		return nil
	}
	if j.Signature != signature || j.OwnerID != owner {
		return nil
	}
	j.expiresAt = s.now().Add(searchJobTTL)
	snap := *j
	snap.cancel = nil
	return &snap
}

// requestCancel asks a running job to stop.
func (s *jobStore) requestCancel(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || (j.Status != jobRunning && j.Status != jobCancelling) {
		return
	}
	j.Status, j.CancelReason = jobCancelling, "user"
	if j.cancel != nil {
		j.cancel(errUserCancel)
	}
}

func (s *jobStore) stashCursor(state *archive.CursorState, signature, owner string) string {
	id := newID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[id] = &viewCursor{state: state, signature: signature, ownerID: owner, expiresAt: s.now().Add(viewCursorTTL)}
	return id
}

func (s *jobStore) loadCursor(id, signature, owner string) *archive.CursorState {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cursors[id]
	if !ok {
		return nil
	}
	if !c.expiresAt.After(s.now()) {
		delete(s.cursors, id)
		return nil
	}
	if c.signature != signature || c.ownerID != owner {
		return nil
	}
	return c.state
}

func viewSignature(windows []dateWindow, pageSize int) string {
	parts := make([]string, len(windows))
	for i, w := range windows {
		parts[i] = w.From + ".." + w.To
	}
	return strings.Join(parts, "|") + "::" + itoa(pageSize)
}
