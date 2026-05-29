package kensa

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
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
	emit       EmitFunc
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

// EmitFunc is the audit-emission shape the executor depends on. Matches
// audit.Emit's signature so production wires audit.Emit directly; tests
// pass a fake recorder. Same pattern as internal/scheduler.EmitFunc.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// NewExecutor wires the executor. Pass the real CredentialBridge and
// audit.Emit from cmd/openwatch/main.go.
func NewExecutor(creds CredentialBridge, emit EmitFunc) *Executor {
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
func (e *Executor) Run(ctx context.Context, hostID uuid.UUID, framework string, policyVersion string) (*KensaResult, error) {
	// Concurrency guard (AC-03). LoadOrStore returns loaded=true if
	// the key was already present; another goroutine owns this hostID.
	if _, loaded := e.inFlight.LoadOrStore(hostID, struct{}{}); loaded {
		return nil, ErrHostBusy
	}
	defer e.inFlight.Delete(hostID)

	// Resolve credential. Two failure modes:
	//   - ErrNoCredential: AC-09. Return WITHOUT emitting scan.started
	//     (the scan never started; there's nothing to fail).
	//   - any other err: AC-15. Treat as decryption failure; emit
	//     scan.failed with reason=credential_decryption_failed. Still
	//     no scan.started (consistent with the spec wording).
	plain, wipe, err := e.credential.Resolve(ctx, hostID)
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return nil, ErrNoCredential
		}
		e.emitFailure(ctx, hostID, framework, policyVersion, ReasonCredentialDecryptionFailed, "")
		return nil, ErrCredentialDecryption
	}
	defer wipe() // AC-07

	// Successful credential resolve → scan.started (AC-05 first half).
	e.emitStarted(ctx, hostID, framework, policyVersion)

	// Placeholder for the Kensa-scan invocation (AC-01/02/04/05-completed)
	// which lands in the next chunk.
	_ = plain
	return nil, errors.New("kensa: executor.Run scan path not yet wired (B.1b in progress)")
}

// emitStarted produces a scan.started audit event. Called exactly once
// per Run that successfully resolves a credential. Spec AC-05.
func (e *Executor) emitStarted(ctx context.Context, hostID uuid.UUID, framework, policyVersion string) {
	e.emit(ctx, audit.ScanStarted, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]string{
			"host_id":        hostID.String(),
			"framework_id":   framework,
			"policy_version": policyVersion,
		}),
	})
}

// emitCompleted produces a scan.completed audit event. Called exactly
// once per Run that finished a Kensa scan successfully. Spec AC-05.
func (e *Executor) emitCompleted(ctx context.Context, hostID uuid.UUID, framework, policyVersion string, summary map[string]any) {
	detail := map[string]any{
		"host_id":        hostID.String(),
		"framework_id":   framework,
		"policy_version": policyVersion,
	}
	for k, v := range summary {
		detail[k] = v
	}
	e.emit(ctx, audit.ScanCompleted, audit.Event{
		ActorType: "system",
		Detail:    mustJSON(detail),
	})
}

// emitFailure produces a scan.failed audit event with detail.reason set
// to one of the closed-enum FailureReason values. Called by:
//
//   - AC-13: SSH host key unknown (reason=host_key_unknown). No
//     credential decrypted before this fires.
//   - AC-14: per-rule evidence > 10 MB (reason=evidence_oversize).
//     detail.rule_id is also set.
//   - AC-15: credential decryption failed
//     (reason=credential_decryption_failed). No scan.started before this.
//   - AC-06: Kensa-side failure (reason=kensa_error).
func (e *Executor) emitFailure(ctx context.Context, hostID uuid.UUID, framework, policyVersion string, reason FailureReason, ruleID string) {
	detail := map[string]string{
		"host_id":        hostID.String(),
		"framework_id":   framework,
		"policy_version": policyVersion,
		"reason":         string(reason),
	}
	if ruleID != "" {
		detail["rule_id"] = ruleID
	}
	e.emit(ctx, audit.ScanFailed, audit.Event{
		ActorType: "system",
		Detail:    mustJSON(detail),
	})
}

// reportHostKeyUnknown is the entry point the future SSH dial code
// calls when known_hosts verification fails before authentication.
// Centralizes the AC-13 audit emission so the SSH path can stay focused.
// Returns ErrHostKeyUnknown so callers can wrap and bubble up.
func (e *Executor) reportHostKeyUnknown(ctx context.Context, hostID uuid.UUID, framework, policyVersion string) error {
	e.emitFailure(ctx, hostID, framework, policyVersion, ReasonHostKeyUnknown, "")
	return ErrHostKeyUnknown
}

// reportEvidenceOversize is the entry point the result-handling code
// calls when a rule's evidence exceeds MaxEvidenceBytes. Returns
// ErrEvidenceOversize. Spec AC-14.
func (e *Executor) reportEvidenceOversize(ctx context.Context, hostID uuid.UUID, framework, policyVersion, ruleID string) error {
	e.emitFailure(ctx, hostID, framework, policyVersion, ReasonEvidenceOversize, ruleID)
	return ErrEvidenceOversize
}

// reportKensaError is the entry point the Kensa-invocation code calls
// when Kensa.Scan (or any execution method) returns a non-classified
// error: SSH refused, framework unsupported, planner error, etc.
// Emits scan.failed with reason=kensa_error and returns ErrKensaInternal.
// Spec AC-06.
func (e *Executor) reportKensaError(ctx context.Context, hostID uuid.UUID, framework, policyVersion string) error {
	e.emitFailure(ctx, hostID, framework, policyVersion, ReasonKensaError, "")
	return ErrKensaInternal
}

// mustJSON marshals v; map[string]X with simple values never errors.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
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
