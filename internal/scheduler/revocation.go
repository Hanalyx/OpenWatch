package scheduler

import (
	"context"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// RevocationList is an in-memory set of revoked Ed25519 signing-key
// fingerprints. Loaded at boot from a separate revocation file (path
// from config), and consulted whenever a policy is loaded or reloaded.
//
// Spec ACs: a policy whose signing key fingerprint is in this list is
// rejected even if the Ed25519 signature is mathematically valid (AC-14).
type RevocationList struct {
	revoked map[string]struct{}
}

// NewRevocationList returns a list seeded with the given fingerprints.
// Empty or nil arguments produce an empty list (no fingerprint is ever
// revoked, valid signatures always accepted).
func NewRevocationList(fingerprints ...string) *RevocationList {
	rl := &RevocationList{revoked: make(map[string]struct{}, len(fingerprints))}
	for _, fp := range fingerprints {
		if fp != "" {
			rl.revoked[fp] = struct{}{}
		}
	}
	return rl
}

// Has reports whether fingerprint fp is on the revocation list.
func (r *RevocationList) Has(fp string) bool {
	if r == nil {
		return false
	}
	_, ok := r.revoked[fp]
	return ok
}

// Size returns the number of revoked fingerprints in the list.
func (r *RevocationList) Size() int {
	if r == nil {
		return 0
	}
	return len(r.revoked)
}

// ValidateReload checks whether a runtime policy reload is acceptable
// given the signing key's fingerprint and the active revocation list.
//
// Spec ACs satisfied here:
//
//   - AC-14 (C-10): a policy signed by a revoked key is rejected even
//     when the Ed25519 signature itself is mathematically valid; the
//     scheduler.policy.revoked_key.rejected audit event is emitted with
//     the key fingerprint and attempted policy version. The previous
//     valid policy stays active (the caller does NOT swap state on a
//     rejection return).
//
// Returns PolicyLoadOK when accepted; PolicyLoadRevokedKey when the
// fingerprint is on the revocation list (with audit side-effect).
func (s *Service) ValidateReload(ctx context.Context, signingKeyFingerprint string, attemptedVersion string, revoked *RevocationList) PolicyLoadError {
	if revoked.Has(signingKeyFingerprint) {
		s.emit(ctx, audit.SchedulerPolicyRevokedKeyRejected, audit.Event{
			ActorType: "system",
			Detail: mustJSON(map[string]string{
				"key_fingerprint": signingKeyFingerprint,
				"policy_version":  attemptedVersion,
			}),
		})
		return PolicyLoadRevokedKey
	}
	return PolicyLoadOK
}
