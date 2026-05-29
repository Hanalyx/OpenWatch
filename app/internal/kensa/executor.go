package kensa

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Executor is the live Kensa-scan wrapper. Constructed once at boot
// via NewExecutor; held for the process lifetime. One Executor binds
// to one Kensa client and one set of cross-cutting helpers (credential
// resolver, audit emitter, host-key policy).
//
// Concurrency model:
//
//   - Different hostIDs run in parallel (no global lock). Spec AC-08
//     verifies 100 parallel runs against 100 distinct hosts are race-clean.
//   - The same hostID can have at most one in-flight Run; the second
//     caller gets ErrHostBusy without opening an SSH session.
//     Spec AC-03 verifies via two concurrent Run calls.
type Executor struct {
	inFlight sync.Map // map[uuid.UUID]struct{} of host IDs currently being scanned

	// Hooks below are wired by NewExecutor. Tests can substitute
	// fakes; production wires the real internal/credential resolver
	// and audit.Emit.
	credential CredentialBridge
	emit       AuditEmitter
	clock      func() time.Time
}

// CredentialBridge is the contract for resolving a host's SSH
// credential into in-memory plaintext bytes ready to be parsed by
// crypto/ssh.ParsePrivateKey. The real implementation wraps
// internal/credential.Resolver; tests pass a fake.
type CredentialBridge interface {
	// Resolve returns the host's decrypted SSH key bytes plus a
	// Wipe function the caller MUST defer-call before returning, even
	// on error paths. Plain bytes are zeroed by Wipe.
	//
	// Returns ErrNoCredential when the host has no credential
	// registered. Returns ErrCredentialDecryption on any decryption
	// failure (corrupt ciphertext, wrong DEK).
	Resolve(ctx context.Context, hostID uuid.UUID) (plain []byte, wipe func(), err error)
}

// AuditEmitter is the contract for emitting audit events. Matches
// audit.Emit's signature so production code passes audit.Emit
// directly; tests pass a fake recorder.
type AuditEmitter interface {
	Emit(ctx context.Context, code string, hostID uuid.UUID, detail map[string]any)
}

// NewExecutor wires the executor. Pass the real CredentialBridge and
// AuditEmitter implementations from cmd/openwatch/main.go.
func NewExecutor(creds CredentialBridge, emit AuditEmitter) *Executor {
	return &Executor{
		credential: creds,
		emit:       emit,
		clock:      time.Now,
	}
}

// Run executes a single-framework Kensa scan against hostID.
//
// Spec ACs satisfied here (this chunk):
//
//   - AC-03 (C-03): per-host concurrency guard prevents a second
//     concurrent call for the same hostID. The second caller gets
//     ErrHostBusy without invoking the credential resolver, without
//     opening an SSH session, and without consuming a Kensa slot.
//   - AC-09 (C-05, partial): when the credential bridge returns
//     ErrNoCredential, Run returns immediately without emitting
//     scan.started and without consuming a concurrency-guard slot.
//
// ACs landing in later chunks of this PR:
//
//   - AC-01: live Kensa.Scan invocation returning a populated KensaResult
//   - AC-02: in-memory SSH key (TransportFactory hook)
//   - AC-04: context cancellation propagation
//   - AC-05/06: scan.started / scan.completed / scan.failed audit
//   - AC-07: credential buffer zeroed on every return path
//   - AC-08: parallel safety verified under -race
//   - AC-13/14/15: host-key, evidence cap, decryption-failure audits
//   - AC-16: backoff state writes to host_backoff_state
func (e *Executor) Run(ctx context.Context, hostID uuid.UUID, framework string) (*KensaResult, error) {
	// Concurrency guard (AC-03). LoadOrStore returns loaded=true if
	// the key was already present; in that case another goroutine
	// owns this hostID's scan, and we bow out.
	if _, loaded := e.inFlight.LoadOrStore(hostID, struct{}{}); loaded {
		return nil, ErrHostBusy
	}
	// Release the slot on every return path.
	defer e.inFlight.Delete(hostID)

	// Resolve credential. ErrNoCredential is the only condition under
	// which Run returns WITHOUT emitting scan.started (AC-09); other
	// resolver errors are classified as decryption failures and DO
	// emit scan.failed (AC-15 in a later chunk).
	plain, wipe, err := e.credential.Resolve(ctx, hostID)
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return nil, ErrNoCredential
		}
		return nil, err
	}
	defer wipe() // AC-07 wired here; verified in a later chunk

	// Placeholder: subsequent chunks wire crypto/ssh.ParsePrivateKey,
	// the TransportFactory bridge to Kensa, and Kensa.Scan invocation.
	_ = plain
	_ = framework
	return nil, errors.New("kensa: executor.Run scan path not yet wired (B.1b in progress)")
}

// inFlightCount returns the number of hostIDs currently being scanned.
// Test-only helper; production callers should use Metrics (added in a
// later chunk).
func (e *Executor) inFlightCount() int {
	count := 0
	e.inFlight.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
