// @spec system-kensa-executor
//
// AC traceability (this file):
//   AC-03  TestRun_PerHostConcurrencyGuard_SecondCallReturnsErrHostBusy
//          TestRun_DifferentHosts_RunInParallel
//          TestRun_GuardReleasedOnReturn
//   AC-09  TestRun_NoCredential_NoScanStarted_NoGuardConsumed

package kensa

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeCredentialBridge is a CredentialBridge that records every call
// and blocks on Resolve until the caller closes its release channel.
// Used to deterministically drive concurrency tests.
type fakeCredentialBridge struct {
	resolveCalls int64

	// Synchronization: holdResolve, when non-nil, makes Resolve block
	// until something is sent to it. Tests use this to start a Run and
	// hold it in the credential-resolve phase so a second Run can
	// race for the concurrency guard.
	holdResolve chan struct{}

	// errorFor overrides the credential return for a specific hostID
	// (e.g. ErrNoCredential).
	errorFor map[uuid.UUID]error

	// mu protects errorFor.
	mu sync.Mutex
}

func (f *fakeCredentialBridge) Resolve(ctx context.Context, hostID uuid.UUID) ([]byte, func(), error) {
	atomic.AddInt64(&f.resolveCalls, 1)

	f.mu.Lock()
	overrideErr, hasOverride := f.errorFor[hostID]
	f.mu.Unlock()
	if hasOverride {
		return nil, func() {}, overrideErr
	}

	if f.holdResolve != nil {
		select {
		case <-f.holdResolve:
		case <-ctx.Done():
			return nil, func() {}, ctx.Err()
		}
	}
	// Return a fake (non-secret) byte slice and a no-op wipe.
	return []byte("not-a-real-key"), func() {}, nil
}

// fakeAuditEmitter is a no-op AuditEmitter that records calls.
type fakeAuditEmitter struct {
	mu    sync.Mutex
	calls []auditCall
}

type auditCall struct {
	Code   string
	HostID uuid.UUID
	Detail map[string]any
}

func (f *fakeAuditEmitter) Emit(ctx context.Context, code string, hostID uuid.UUID, detail map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, auditCall{Code: code, HostID: hostID, Detail: detail})
}

func (f *fakeAuditEmitter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// @ac AC-03
// AC-03: two concurrent Run calls for the same hostID — the second
// returns ErrHostBusy immediately, WITHOUT invoking the credential
// resolver. This is the per-host concurrency guard.
func TestRun_PerHostConcurrencyGuard_SecondCallReturnsErrHostBusy(t *testing.T) {
	t.Run("system-kensa-executor/AC-03", func(t *testing.T) {
		bridge := &fakeCredentialBridge{
			holdResolve: make(chan struct{}),
			errorFor:    make(map[uuid.UUID]error),
		}
		emit := &fakeAuditEmitter{}
		exec := NewExecutor(bridge, emit)

		hostID := uuid.New()

		// First Run goroutine: blocks in credential resolve.
		started := make(chan struct{})
		firstDone := make(chan struct{})
		go func() {
			defer close(firstDone)
			// Signal that we're about to call Run so the second can
			// race in.
			close(started)
			_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")
		}()
		<-started

		// Give the first goroutine a moment to register on the guard.
		// 50ms is plenty for the LoadOrStore in Run's first line.
		time.Sleep(50 * time.Millisecond)

		// Second Run for the SAME hostID — should immediately return
		// ErrHostBusy. The credential resolver is NOT called for this
		// attempt (resolveCalls increments only from the first goroutine).
		callsBefore := atomic.LoadInt64(&bridge.resolveCalls)
		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")
		callsAfter := atomic.LoadInt64(&bridge.resolveCalls)

		if !errors.Is(err, ErrHostBusy) {
			t.Errorf("second Run err = %v, want ErrHostBusy", err)
		}
		if callsAfter != callsBefore {
			t.Errorf("credential resolver called %d → %d for the second Run; AC-03 requires zero resolver calls when the guard rejects",
				callsBefore, callsAfter)
		}

		// Release the first goroutine.
		close(bridge.holdResolve)
		<-firstDone
	})
}

// @ac AC-03
// AC-03: two concurrent Run calls for DIFFERENT hostIDs both proceed
// in parallel. Verifies the guard is per-host, not global.
func TestRun_DifferentHosts_RunInParallel(t *testing.T) {
	t.Run("system-kensa-executor/AC-03", func(t *testing.T) {
		bridge := &fakeCredentialBridge{
			holdResolve: make(chan struct{}),
			errorFor:    make(map[uuid.UUID]error),
		}
		emit := &fakeAuditEmitter{}
		exec := NewExecutor(bridge, emit)

		hostA := uuid.New()
		hostB := uuid.New()

		go func() {
			_, _ = exec.Run(context.Background(), hostA, "cis-rhel9-v2.0.0")
		}()
		go func() {
			_, _ = exec.Run(context.Background(), hostB, "cis-rhel9-v2.0.0")
		}()

		// Both goroutines block in credential resolve. Wait until the
		// resolver has been called twice (one per host).
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if atomic.LoadInt64(&bridge.resolveCalls) == 2 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if got := atomic.LoadInt64(&bridge.resolveCalls); got != 2 {
			t.Errorf("resolveCalls = %d after 2s, want 2 (different-host parallelism broken)", got)
		}

		// Cleanup: closing the hold channel releases both blocked
		// goroutines; closing once is enough since they both receive
		// on it concurrently.
		close(bridge.holdResolve)
		// Wait briefly for goroutines to exit.
		time.Sleep(50 * time.Millisecond)
	})
}

// @ac AC-03
// AC-03 (slot release): after Run returns (success OR error), the
// concurrency-guard slot is released. A subsequent Run for the same
// hostID succeeds.
func TestRun_GuardReleasedOnReturn(t *testing.T) {
	t.Run("system-kensa-executor/AC-03", func(t *testing.T) {
		bridge := &fakeCredentialBridge{
			errorFor: make(map[uuid.UUID]error),
		}
		emit := &fakeAuditEmitter{}
		exec := NewExecutor(bridge, emit)

		hostID := uuid.New()

		// First Run: completes (returns an error because the scan path
		// isn't wired yet; that's fine for guard-release testing).
		_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")

		if exec.inFlightCount() != 0 {
			t.Errorf("inFlightCount = %d after Run returned, want 0 (guard slot leaked)", exec.inFlightCount())
		}

		// Second Run for the same hostID: should NOT get ErrHostBusy.
		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")
		if errors.Is(err, ErrHostBusy) {
			t.Error("second Run got ErrHostBusy; guard slot was not released after the first Run")
		}
	})
}

// @ac AC-09
// AC-09: when the credential bridge returns ErrNoCredential, Run
// returns ErrNoCredential WITHOUT emitting scan.started, WITHOUT opening
// an SSH session, AND without consuming a concurrency-guard slot (so
// a subsequent Run for the same hostID proceeds normally).
func TestRun_NoCredential_NoScanStarted_NoGuardConsumed(t *testing.T) {
	t.Run("system-kensa-executor/AC-09", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{
			errorFor: map[uuid.UUID]error{hostID: ErrNoCredential},
		}
		emit := &fakeAuditEmitter{}
		exec := NewExecutor(bridge, emit)

		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("err = %v, want ErrNoCredential", err)
		}

		// No scan.started emission.
		if emit.callCount() != 0 {
			t.Errorf("emitted %d audit events on no-credential path, want 0", emit.callCount())
		}

		// Guard slot released: a subsequent Run can proceed (it'll
		// also hit ErrNoCredential since the bridge still says so, but
		// won't get ErrHostBusy).
		_, err = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0")
		if errors.Is(err, ErrHostBusy) {
			t.Error("second Run got ErrHostBusy; the no-credential path leaked a guard slot")
		}
	})
}
