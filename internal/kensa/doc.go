// Package kensa wraps the Kensa Go module to run a single-framework
// compliance scan against a single host. It is the only package in
// OpenWatch that imports github.com/Hanalyx/kensa.
//
// Spec: specs/system/kensa-executor.spec.yaml (status: approved)
//
// Architectural choices:
//
//   - Kensa is a pure measurement engine. This wrapper bridges
//     OpenWatch's credential store (internal/credential) to Kensa's SSH
//     session, runs the scan, captures the structured result, and hands
//     it to the transaction log writer. Persistence is NOT this
//     package's responsibility.
//
//   - SSH private keys are loaded into memory via crypto/ssh.ParsePrivateKey
//     and passed to Kensa via a custom TransportFactory. The Kensa
//     HostConfig.KeyPath field — which requires a path on disk — is
//     never populated by this wrapper. Spec AC-02 verifies via
//     syscall tracing that no SSH key bytes ever hit /tmp or any disk
//     path during executor.Run.
//
//   - Decrypted credential plaintext is zeroed via a deferred Wipe()
//     before executor.Run returns, on every code path (success, error,
//     ctx cancel). Spec AC-07.
//
//   - A per-host concurrency guard (sync.Map of in-flight host IDs)
//     prevents two concurrent scans against the same host. The second
//     caller gets ErrHostBusy immediately, without opening an SSH
//     session. Spec AC-03.
//
//   - No engine-abstraction interface is defined in this package. Kensa
//     is invoked directly via *kensa.Kensa. Spec AC-12 source-inspects
//     to confirm no type `ScanEngine interface` (or similar) is declared.
//
// Kensa version pin: github.com/Hanalyx/kensa v0.3.2 (matches the
// version recorded in the spec's context block; AC-10 verifies the
// match between this comment, the spec, and go.mod).
package kensa
