// @spec system-kensa-executor
//
// AC traceability (this file):
//   AC-03  TestRun_PerHostConcurrencyGuard_SecondCallReturnsErrHostBusy
//          TestRun_DifferentHosts_RunInParallel
//          TestRun_GuardReleasedOnReturn
//   AC-05  TestRun_SuccessfulCredentialResolve_EmitsScanStarted
//   AC-07  TestRun_CredentialWipeCalledOnEveryReturnPath
//   AC-08  TestRun_100ParallelDistinctHosts_RaceClean
//   AC-09  TestRun_NoCredential_NoScanStarted_NoGuardConsumed
//   AC-13  TestReportHostKeyUnknown_EmitsScanFailedWithHostKeyReason
//   AC-14  TestReportEvidenceOversize_EmitsScanFailedWithRuleID
//   AC-15  TestRun_DecryptionFailure_EmitsScanFailedAndNoScanStarted

package kensa

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// fakeCredentialBridge is a CredentialBridge that records every call,
// optionally blocks on Resolve, and tracks whether Wipe was invoked.
// Used to deterministically drive concurrency, audit, and AC-07 tests.
type fakeCredentialBridge struct {
	resolveCalls int64
	wipeCalls    int64

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
	// Return a fake (non-secret) byte slice and a wipe that records
	// it was called. Spec AC-07.
	return []byte("not-a-real-key"), func() {
		atomic.AddInt64(&f.wipeCalls, 1)
	}, nil
}

// fakeEmitFunc returns an EmitFunc that appends calls to *calls under
// the protection of *mu. Tests inspect calls afterwards.
func fakeEmitFunc(mu *sync.Mutex, calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}
}

// emitCall is a captured audit emission used by tests.
type emitCall struct {
	Code  audit.Code
	Event audit.Event
}

// emitCallCount returns the number of emissions captured under mu.
func emitCallCount(mu *sync.Mutex, calls *[]emitCall) int {
	mu.Lock()
	defer mu.Unlock()
	return len(*calls)
}

// findCallsByCode returns all emissions matching code.
func findCallsByCode(mu *sync.Mutex, calls *[]emitCall, code audit.Code) []emitCall {
	mu.Lock()
	defer mu.Unlock()
	var out []emitCall
	for _, c := range *calls {
		if c.Code == code {
			out = append(out, c)
		}
	}
	return out
}

// detailMap decodes a captured emission's Detail JSON.
func detailMap(t *testing.T, c emitCall) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(c.Event.Detail, &m); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	return m
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
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		hostID := uuid.New()

		// First Run goroutine: blocks in credential resolve.
		started := make(chan struct{})
		firstDone := make(chan struct{})
		go func() {
			defer close(firstDone)
			close(started)
			_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		}()
		<-started

		// Give the first goroutine a moment to register on the guard.
		time.Sleep(50 * time.Millisecond)

		callsBefore := atomic.LoadInt64(&bridge.resolveCalls)
		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
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
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		hostA := uuid.New()
		hostB := uuid.New()

		go func() {
			_, _ = exec.Run(context.Background(), hostA, "cis-rhel9-v2.0.0", "1.0.0")
		}()
		go func() {
			_, _ = exec.Run(context.Background(), hostB, "cis-rhel9-v2.0.0", "1.0.0")
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

		close(bridge.holdResolve)
		time.Sleep(50 * time.Millisecond)
	})
}

// @ac AC-03
// AC-03 (slot release): after Run returns (success OR error), the
// concurrency-guard slot is released.
func TestRun_GuardReleasedOnReturn(t *testing.T) {
	t.Run("system-kensa-executor/AC-03", func(t *testing.T) {
		bridge := &fakeCredentialBridge{
			errorFor: make(map[uuid.UUID]error),
		}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		hostID := uuid.New()
		_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")

		if exec.inFlightCount() != 0 {
			t.Errorf("inFlightCount = %d after Run returned, want 0 (guard slot leaked)", exec.inFlightCount())
		}

		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
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
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if !errors.Is(err, ErrNoCredential) {
			t.Errorf("err = %v, want ErrNoCredential", err)
		}

		if emitCallCount(&mu, &calls) != 0 {
			t.Errorf("emitted %d audit events on no-credential path, want 0", emitCallCount(&mu, &calls))
		}

		_, err = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if errors.Is(err, ErrHostBusy) {
			t.Error("second Run got ErrHostBusy; the no-credential path leaked a guard slot")
		}
	})
}

// @ac AC-05
// AC-05 (first half): when credential resolve succeeds, Run emits
// exactly one scan.started carrying host_id, framework_id, and
// policy_version. The completed half lands when the scan path is wired.
func TestRun_SuccessfulCredentialResolve_EmitsScanStarted(t *testing.T) {
	t.Run("system-kensa-executor/AC-05", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{
			errorFor: make(map[uuid.UUID]error),
		}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.7.0")

		started := findCallsByCode(&mu, &calls, audit.ScanStarted)
		if len(started) != 1 {
			t.Fatalf("scan.started count = %d, want exactly 1", len(started))
		}

		detail := detailMap(t, started[0])
		if detail["host_id"] != hostID.String() {
			t.Errorf("Detail.host_id = %q, want %q", detail["host_id"], hostID.String())
		}
		if detail["framework_id"] != "cis-rhel9-v2.0.0" {
			t.Errorf("Detail.framework_id = %q, want %q", detail["framework_id"], "cis-rhel9-v2.0.0")
		}
		if detail["policy_version"] != "1.7.0" {
			t.Errorf("Detail.policy_version = %q, want %q", detail["policy_version"], "1.7.0")
		}
	})
}

// @ac AC-07
// AC-07: on every return path after a successful credential resolve,
// the wipe function is called. Verified by counting wipeCalls on the
// fake bridge.
func TestRun_CredentialWipeCalledOnEveryReturnPath(t *testing.T) {
	t.Run("system-kensa-executor/AC-07", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{
			errorFor: make(map[uuid.UUID]error),
		}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		// Run returns an error because the scan path isn't wired yet,
		// but the credential resolve succeeded so wipe MUST have been
		// called exactly once.
		_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")

		if got := atomic.LoadInt64(&bridge.wipeCalls); got != 1 {
			t.Errorf("wipeCalls = %d after one Run, want 1 (AC-07: every return path zeros the credential)", got)
		}

		// Run again — wipe should fire a second time.
		_, _ = exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if got := atomic.LoadInt64(&bridge.wipeCalls); got != 2 {
			t.Errorf("wipeCalls after two Runs = %d, want 2", got)
		}
	})
}

// @ac AC-08
// AC-08: 100 parallel Runs against 100 distinct hosts complete without
// data races. Under -race the test fails on the first detected race.
// The Runs themselves return errors (scan path unwired), but the
// concurrency-guard sync.Map, the audit emission path, and the
// credential resolver's calls must all be race-free.
func TestRun_100ParallelDistinctHosts_RaceClean(t *testing.T) {
	t.Run("system-kensa-executor/AC-08", func(t *testing.T) {
		bridge := &fakeCredentialBridge{
			errorFor: make(map[uuid.UUID]error),
		}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		const N = 100
		hosts := make([]uuid.UUID, N)
		for i := range hosts {
			hosts[i] = uuid.New()
		}

		var wg sync.WaitGroup
		for _, h := range hosts {
			wg.Add(1)
			go func(host uuid.UUID) {
				defer wg.Done()
				_, _ = exec.Run(context.Background(), host, "cis-rhel9-v2.0.0", "1.0.0")
			}(h)
		}
		wg.Wait()

		// All N hosts went through credential resolve.
		if got := atomic.LoadInt64(&bridge.resolveCalls); got != N {
			t.Errorf("resolveCalls = %d, want %d", got, N)
		}
		// All N had their credential wiped.
		if got := atomic.LoadInt64(&bridge.wipeCalls); got != N {
			t.Errorf("wipeCalls = %d, want %d", got, N)
		}
		// All N emitted scan.started.
		if got := len(findCallsByCode(&mu, &calls, audit.ScanStarted)); got != N {
			t.Errorf("scan.started emissions = %d, want %d", got, N)
		}
		// No leftover in-flight entries.
		if got := exec.inFlightCount(); got != 0 {
			t.Errorf("inFlightCount after parallel Runs = %d, want 0", got)
		}
	})
}

// @ac AC-13
// AC-13: reportHostKeyUnknown emits scan.failed with detail.reason =
// "host_key_unknown" and returns ErrHostKeyUnknown. Models the SSH
// dial path's failure-before-authentication on require_known policy.
func TestReportHostKeyUnknown_EmitsScanFailedWithHostKeyReason(t *testing.T) {
	t.Run("system-kensa-executor/AC-13", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		err := exec.reportHostKeyUnknown(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if !errors.Is(err, ErrHostKeyUnknown) {
			t.Errorf("err = %v, want ErrHostKeyUnknown", err)
		}

		failed := findCallsByCode(&mu, &calls, audit.ScanFailed)
		if len(failed) != 1 {
			t.Fatalf("scan.failed count = %d, want 1", len(failed))
		}
		detail := detailMap(t, failed[0])
		if detail["reason"] != string(ReasonHostKeyUnknown) {
			t.Errorf("Detail.reason = %q, want %q", detail["reason"], ReasonHostKeyUnknown)
		}
		if detail["host_id"] != hostID.String() {
			t.Errorf("Detail.host_id = %q, want %q", detail["host_id"], hostID.String())
		}
	})
}

// @ac AC-14
// AC-14: reportEvidenceOversize emits scan.failed with detail.reason =
// "evidence_oversize" AND detail.rule_id naming the offending rule.
// Tested as a pure function; the integration with the scan-result
// processing pipeline lands in the next chunk.
func TestReportEvidenceOversize_EmitsScanFailedWithRuleID(t *testing.T) {
	t.Run("system-kensa-executor/AC-14", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		err := exec.reportEvidenceOversize(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0", "sshd-disable-root-login")
		if !errors.Is(err, ErrEvidenceOversize) {
			t.Errorf("err = %v, want ErrEvidenceOversize", err)
		}

		failed := findCallsByCode(&mu, &calls, audit.ScanFailed)
		if len(failed) != 1 {
			t.Fatalf("scan.failed count = %d, want 1", len(failed))
		}
		detail := detailMap(t, failed[0])
		if detail["reason"] != string(ReasonEvidenceOversize) {
			t.Errorf("Detail.reason = %q, want %q", detail["reason"], ReasonEvidenceOversize)
		}
		if detail["rule_id"] != "sshd-disable-root-login" {
			t.Errorf("Detail.rule_id = %q, want %q", detail["rule_id"], "sshd-disable-root-login")
		}
	})
}

// @ac AC-15
// AC-15: a credential decryption failure (any non-ErrNoCredential
// error from the bridge) emits exactly one scan.failed with
// reason="credential_decryption_failed" and returns
// ErrCredentialDecryption. No scan.started is emitted.
func TestRun_DecryptionFailure_EmitsScanFailedAndNoScanStarted(t *testing.T) {
	t.Run("system-kensa-executor/AC-15", func(t *testing.T) {
		hostID := uuid.New()
		bridge := &fakeCredentialBridge{
			// Any non-ErrNoCredential error is treated as decryption fail.
			errorFor: map[uuid.UUID]error{hostID: errors.New("AES-GCM open: authentication failed")},
		}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		_, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if !errors.Is(err, ErrCredentialDecryption) {
			t.Errorf("err = %v, want ErrCredentialDecryption", err)
		}

		// Zero scan.started emissions on the decryption-failure path.
		if got := len(findCallsByCode(&mu, &calls, audit.ScanStarted)); got != 0 {
			t.Errorf("scan.started count = %d on decryption-failure path, want 0", got)
		}

		// Exactly one scan.failed with the right reason.
		failed := findCallsByCode(&mu, &calls, audit.ScanFailed)
		if len(failed) != 1 {
			t.Fatalf("scan.failed count = %d, want 1", len(failed))
		}
		detail := detailMap(t, failed[0])
		if detail["reason"] != string(ReasonCredentialDecryptionFailed) {
			t.Errorf("Detail.reason = %q, want %q", detail["reason"], ReasonCredentialDecryptionFailed)
		}
	})
}

// @ac AC-06
// AC-06: reportKensaError emits scan.failed with detail.reason="kensa_error"
// and returns ErrKensaInternal. Models any non-classified Kensa-side
// failure (SSH refused, framework unsupported, planner error). The
// specific failure-classification logic (mapping Kensa.Scan errors to
// FailureReason) lands when the live integration code is wired.
func TestReportKensaError_EmitsScanFailedWithKensaErrorReason(t *testing.T) {
	t.Run("system-kensa-executor/AC-06", func(t *testing.T) {
		hostID := uuid.New()

		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		err := exec.reportKensaError(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.0.0")
		if !errors.Is(err, ErrKensaInternal) {
			t.Errorf("err = %v, want ErrKensaInternal", err)
		}

		failed := findCallsByCode(&mu, &calls, audit.ScanFailed)
		if len(failed) != 1 {
			t.Fatalf("scan.failed count = %d, want 1", len(failed))
		}
		detail := detailMap(t, failed[0])
		if detail["reason"] != string(ReasonKensaError) {
			t.Errorf("Detail.reason = %q, want %q", detail["reason"], ReasonKensaError)
		}
		if detail["host_id"] != hostID.String() {
			t.Errorf("Detail.host_id = %q, want %q", detail["host_id"], hostID.String())
		}
	})
}

// @ac AC-04
// AC-04: a context with a deadline causes Run to return ctx.Err()
// before the underlying scan completes. The injected ScanFunc blocks
// until ctx.Done() to simulate a long-running Kensa.Scan; the test
// asserts Run propagates ctx.Err() and emits NO scan.completed.
func TestRun_ContextDeadline_PropagatesAsCtxErr(t *testing.T) {
	t.Run("system-kensa-executor/AC-04", func(t *testing.T) {
		hostID := uuid.New()
		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		// scanFunc blocks until ctx.Done() and returns ctx.Err().
		// Models Kensa.Scan honoring its context contract.
		blocking := func(ctx context.Context, _ uuid.UUID, _, _ string, _ []byte) (*KensaResult, FailureReason, error) {
			<-ctx.Done()
			return nil, "", ctx.Err()
		}
		exec = exec.WithScanFunc(blocking)

		// 100ms deadline, per the spec's example value in AC-04.
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := exec.Run(ctx, hostID, "cis-rhel9-v2.0.0", "1.0.0")
		elapsed := time.Since(start)

		// Run must return the ctx error verbatim (errors.Is recognizes
		// DeadlineExceeded as the cause of context.Canceled-or-Timeout).
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded", err)
		}

		// Hard upper bound on elapsed time — proves the scan wasn't
		// allowed to run to completion.
		if elapsed > 500*time.Millisecond {
			t.Errorf("Run took %v, expected to return within ~100ms after ctx deadline", elapsed)
		}

		// scan.started should have fired (we got past credential resolve).
		// scan.completed and scan.failed must NOT have fired.
		if got := len(findCallsByCode(&mu, &calls, audit.ScanStarted)); got != 1 {
			t.Errorf("scan.started count = %d, want 1", got)
		}
		if got := len(findCallsByCode(&mu, &calls, audit.ScanCompleted)); got != 0 {
			t.Errorf("scan.completed count = %d on cancellation, want 0", got)
		}
		if got := len(findCallsByCode(&mu, &calls, audit.ScanFailed)); got != 0 {
			t.Errorf("scan.failed count = %d on cancellation, want 0 (cancellation is not a failure)", got)
		}

		// Credential was still wiped (defer runs on every return path).
		if got := atomic.LoadInt64(&bridge.wipeCalls); got != 1 {
			t.Errorf("wipeCalls = %d after cancellation, want 1 (AC-07 still applies)", got)
		}
	})
}

// @ac AC-04
// AC-04 (already-cancelled ctx): if ctx is already cancelled when
// Run is called, Run propagates ctx.Err() promptly without doing
// any work that could outlive the cancellation.
func TestRun_AlreadyCancelledCtx_ReturnsImmediately(t *testing.T) {
	t.Run("system-kensa-executor/AC-04", func(t *testing.T) {
		hostID := uuid.New()
		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		blocking := func(ctx context.Context, _ uuid.UUID, _, _ string, _ []byte) (*KensaResult, FailureReason, error) {
			<-ctx.Done()
			return nil, "", ctx.Err()
		}
		exec = exec.WithScanFunc(blocking)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel BEFORE calling Run

		start := time.Now()
		_, err := exec.Run(ctx, hostID, "cis-rhel9-v2.0.0", "1.0.0")
		elapsed := time.Since(start)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if elapsed > 200*time.Millisecond {
			t.Errorf("Run took %v on already-cancelled ctx, want fast return", elapsed)
		}
	})
}

// @ac AC-05
// AC-05 (second half): a successful scan emits exactly one scan.completed
// after Kensa returns. Detail carries policy_version + the per-status
// counts derived from the result.
func TestRun_SuccessfulScan_EmitsScanCompleted(t *testing.T) {
	t.Run("system-kensa-executor/AC-05", func(t *testing.T) {
		hostID := uuid.New()
		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		// Successful scan returning a typed result.
		successful := func(ctx context.Context, h uuid.UUID, fw, pv string, _ []byte) (*KensaResult, FailureReason, error) {
			return &KensaResult{
				HostID:        h,
				FrameworkID:   fw,
				PolicyVersion: pv,
				Outcomes: []RuleOutcome{
					{RuleID: "sshd-disable-root", Status: StatusPass},
					{RuleID: "sshd-strong-ciphers", Status: StatusFail},
					{RuleID: "selinux-enforcing", Status: StatusSkipped},
				},
			}, "", nil
		}
		exec = exec.WithScanFunc(successful)

		result, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.7.0")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if result == nil {
			t.Fatal("Run returned nil result on success")
		}

		completed := findCallsByCode(&mu, &calls, audit.ScanCompleted)
		if len(completed) != 1 {
			t.Fatalf("scan.completed count = %d, want 1", len(completed))
		}
	})
}

// @ac AC-01
// AC-01: a successful Run returns a non-nil *KensaResult populated
// with rule outcomes, per-rule evidence, and framework_refs.
// Tested structurally via the injected ScanFunc; the contract is that
// whatever the live Kensa.Scan call produces, Run hands back unchanged.
// The live-Kensa wiring is a separate production-wiring concern (the
// scanFunc field is the seam): exercising it would require an in-process
// SSH server + Kensa's Default infrastructure, which the spec's "executor
// invokes Kensa" responsibility tests structurally here.
func TestRun_PopulatedKensaResult_AllFieldsFlowThrough(t *testing.T) {
	t.Run("system-kensa-executor/AC-01", func(t *testing.T) {
		hostID := uuid.New()
		bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
		var mu sync.Mutex
		var calls []emitCall
		exec := NewExecutor(bridge, fakeEmitFunc(&mu, &calls))

		// Build a result with every field populated: 3 rules with mixed
		// status, evidence bytes, and a framework reference per rule.
		// The spec calls out outcomes + evidence + framework_refs
		// explicitly — the test fails if Run silently drops any of them.
		expected := &KensaResult{
			HostID:        hostID,
			FrameworkID:   "cis-rhel9-v2.0.0",
			PolicyVersion: "1.7.0",
			StartedAt:     time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
			CompletedAt:   time.Date(2026, 5, 28, 10, 0, 5, 0, time.UTC),
			Outcomes: []RuleOutcome{
				{
					RuleID:        "sshd-disable-root",
					Status:        StatusPass,
					Severity:      "high",
					Evidence:      []byte(`{"command":"sshd -T","stdout":"permitrootlogin no"}`),
					FrameworkRefs: map[string]string{"cis_rhel9_v2": "5.2.7"},
				},
				{
					RuleID:        "sshd-strong-ciphers",
					Status:        StatusFail,
					Severity:      "medium",
					Evidence:      []byte(`{"command":"sshd -T","stdout":"ciphers aes128-cbc"}`),
					FrameworkRefs: map[string]string{"cis_rhel9_v2": "5.2.13"},
				},
				{
					RuleID:        "selinux-enforcing",
					Status:        StatusSkipped,
					SkipReason:    "host_capability_missing:selinux",
					FrameworkRefs: map[string]string{"cis_rhel9_v2": "1.6.1.2"},
				},
			},
		}

		exec = exec.WithScanFunc(func(ctx context.Context, h uuid.UUID, fw, pv string, _ []byte) (*KensaResult, FailureReason, error) {
			return expected, "", nil
		})

		got, err := exec.Run(context.Background(), hostID, "cis-rhel9-v2.0.0", "1.7.0")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got == nil {
			t.Fatal("Run returned nil *KensaResult; AC-01 requires non-nil on success")
		}

		// Spec-named requirements: outcomes, evidence, framework_refs.
		if len(got.Outcomes) != len(expected.Outcomes) {
			t.Errorf("Outcomes length = %d, want %d", len(got.Outcomes), len(expected.Outcomes))
		}

		for i, w := range expected.Outcomes {
			if i >= len(got.Outcomes) {
				break
			}
			g := got.Outcomes[i]
			if g.RuleID != w.RuleID {
				t.Errorf("Outcomes[%d].RuleID = %q, want %q", i, g.RuleID, w.RuleID)
			}
			if g.Status != w.Status {
				t.Errorf("Outcomes[%d].Status = %q, want %q", i, g.Status, w.Status)
			}
			// Evidence: spec requirement.
			if string(g.Evidence) != string(w.Evidence) {
				t.Errorf("Outcomes[%d].Evidence not preserved through Run", i)
			}
			// FrameworkRefs: spec requirement.
			if len(g.FrameworkRefs) != len(w.FrameworkRefs) {
				t.Errorf("Outcomes[%d].FrameworkRefs length = %d, want %d",
					i, len(g.FrameworkRefs), len(w.FrameworkRefs))
			}
			for k, wv := range w.FrameworkRefs {
				if g.FrameworkRefs[k] != wv {
					t.Errorf("Outcomes[%d].FrameworkRefs[%q] = %q, want %q",
						i, k, g.FrameworkRefs[k], wv)
				}
			}
		}

		// FrameworkID must match the request.
		if got.FrameworkID != "cis-rhel9-v2.0.0" {
			t.Errorf("FrameworkID = %q, want %q", got.FrameworkID, "cis-rhel9-v2.0.0")
		}
		// PolicyVersion preserved (the job-payload snapshot).
		if got.PolicyVersion != "1.7.0" {
			t.Errorf("PolicyVersion = %q, want %q", got.PolicyVersion, "1.7.0")
		}
	})
}
