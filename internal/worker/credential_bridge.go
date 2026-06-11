// Credential bridge: adapts internal/credential.Service to the
// kensa.CredentialBridge interface the executor expects.
//
// kensa.CredentialBridge.Resolve returns (plain []byte, wipe func(), err).
// credential.Service.Resolve returns (*Credential, err) with PrivateKey
// as a decrypted plaintext string. We copy the SSH private key into a
// byte slice the caller can wipe; the original *Credential is dropped
// for GC after the copy.
//
// Spec: system-worker-subcommand W4 boot wiring. AC-16 source-inspection
// asserts cmdWorker constructs the executor with a real bridge (not
// nil and not an in-memory test stub).

package worker

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/kensa"
)

// CredentialBridge wraps credential.Service to satisfy
// kensa.CredentialBridge. Constructor takes the live service; Resolve
// is invoked per scan by the executor.
type CredentialBridge struct {
	svc *credential.Service
}

// NewCredentialBridge constructs a bridge backed by the live credential
// service. The same instance is shared across all scan jobs in the
// worker process.
func NewCredentialBridge(svc *credential.Service) *CredentialBridge {
	return &CredentialBridge{svc: svc}
}

// Resolve fetches the host's credential (host-scoped first, system
// default fallback), extracts the SSH private key as a byte slice the
// executor can pass to Kensa, and returns a wipe function that zeros
// the slice on completion of the scan.
//
// Returns kensa.ErrNoCredential when the underlying service reports
// no credential is available — the executor maps this to a short-circuit
// return without emitting scan.started (per kensa AC-09).
//
// Returns kensa.ErrCredentialDecryption on any other resolve error;
// the executor maps this to scan.failed with reason
// credential_decryption_failed.
func (b *CredentialBridge) Resolve(ctx context.Context, hostID uuid.UUID) ([]byte, func(), error) {
	cred, err := b.svc.Resolve(ctx, hostID)
	if err != nil {
		// credential.Service returns its own ErrNoCredential sentinel.
		// kensa exposes its own; map between them.
		if err == credential.ErrNoCredential {
			return nil, nil, kensa.ErrNoCredential
		}
		return nil, nil, kensa.ErrCredentialDecryption
	}

	plain := []byte(cred.PrivateKey)
	wipe := func() {
		for i := range plain {
			plain[i] = 0
		}
	}
	return plain, wipe, nil
}
