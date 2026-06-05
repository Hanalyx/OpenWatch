// @spec system-scheduler
//
// AC traceability (this file):
//   AC-14  TestRevocationList_HasMatchesAddedFingerprints
//          TestRevocationList_EmptyDoesNotRevoke
//          TestRevocationList_NilSafe
//          TestValidateReload_AcceptsUnrevokedKey
//          TestValidateReload_RejectsRevokedKey_EmitsAudit
//          TestValidateReload_DoesNotEmitOnAccept

package scheduler

import (
	"context"
	"testing"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// @ac AC-14
// AC-14: NewRevocationList records every fingerprint passed in; Has
// returns true for those and false for anything else.
func TestRevocationList_HasMatchesAddedFingerprints(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		rl := NewRevocationList("fp-A", "fp-B", "fp-C")

		if !rl.Has("fp-A") || !rl.Has("fp-B") || !rl.Has("fp-C") {
			t.Errorf("Has returned false for known revoked fingerprint")
		}
		if rl.Has("fp-fresh") {
			t.Errorf("Has returned true for an un-revoked fingerprint")
		}
		if rl.Size() != 3 {
			t.Errorf("Size = %d, want 3", rl.Size())
		}
	})
}

// @ac AC-14
// AC-14: an empty RevocationList revokes nothing.
func TestRevocationList_EmptyDoesNotRevoke(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		rl := NewRevocationList()
		if rl.Has("any-fingerprint") {
			t.Error("empty revocation list returned Has=true")
		}
		if rl.Size() != 0 {
			t.Errorf("empty list Size = %d, want 0", rl.Size())
		}
	})
}

// @ac AC-14
// AC-14: nil receiver is safe (treats as empty).
func TestRevocationList_NilSafe(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		var rl *RevocationList // nil
		if rl.Has("anything") {
			t.Error("nil receiver Has returned true")
		}
		if rl.Size() != 0 {
			t.Errorf("nil receiver Size = %d, want 0", rl.Size())
		}
	})
}

// @ac AC-14
// AC-14: ValidateReload returns PolicyLoadOK when the signing key's
// fingerprint is NOT on the revocation list. No audit event is emitted.
func TestValidateReload_AcceptsUnrevokedKey(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		var calls []emitCall
		s := &Service{emit: fakeEmitter(&calls)}
		rl := NewRevocationList("revoked-fp-1", "revoked-fp-2")

		got := s.ValidateReload(context.Background(), "current-active-fp", "1.0.0", rl)

		if got != PolicyLoadOK {
			t.Errorf("ValidateReload = %q, want %q", got, PolicyLoadOK)
		}
		if len(calls) != 0 {
			t.Errorf("emitted %d events for un-revoked key, want 0: %+v", len(calls), calls)
		}
	})
}

// @ac AC-14
// AC-14: ValidateReload returns PolicyLoadRevokedKey when the signing
// key fingerprint matches an entry on the revocation list. Emits
// scheduler.policy.revoked_key.rejected with detail.key_fingerprint and
// detail.policy_version.
func TestValidateReload_RejectsRevokedKey_EmitsAudit(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		var calls []emitCall
		s := &Service{emit: fakeEmitter(&calls)}
		rl := NewRevocationList("revoked-fp", "other-revoked-fp")

		got := s.ValidateReload(context.Background(), "revoked-fp", "1.0.5", rl)

		if got != PolicyLoadRevokedKey {
			t.Errorf("ValidateReload = %q, want %q", got, PolicyLoadRevokedKey)
		}
		if len(calls) != 1 {
			t.Fatalf("emitted %d events, want exactly 1: %+v", len(calls), calls)
		}
		c := calls[0]
		if c.Code != audit.SchedulerPolicyRevokedKeyRejected {
			t.Errorf("Code = %q, want %q", c.Code, audit.SchedulerPolicyRevokedKeyRejected)
		}
		if c.Event.ActorType != "system" {
			t.Errorf("ActorType = %q, want %q", c.Event.ActorType, "system")
		}

		var detail map[string]string
		if err := decodeDetailJSON(c.Event.Detail, &detail); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if detail["key_fingerprint"] != "revoked-fp" {
			t.Errorf("Detail.key_fingerprint = %q, want %q", detail["key_fingerprint"], "revoked-fp")
		}
		if detail["policy_version"] != "1.0.5" {
			t.Errorf("Detail.policy_version = %q, want %q", detail["policy_version"], "1.0.5")
		}
	})
}

// @ac AC-14
// AC-14: explicit no-emit check on the accept path. Guards against an
// over-eager future implementation that might emit on every check.
func TestValidateReload_DoesNotEmitOnAccept(t *testing.T) {
	t.Run("system-scheduler/AC-14", func(t *testing.T) {
		var calls []emitCall
		s := &Service{emit: fakeEmitter(&calls)}
		rl := NewRevocationList() // empty

		_ = s.ValidateReload(context.Background(), "any-fp", "1.0.0", rl)

		if len(calls) != 0 {
			t.Errorf("emit count = %d, want 0 on the accept path", len(calls))
		}
	})
}
