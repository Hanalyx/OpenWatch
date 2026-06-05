// Package discovery owns the one-shot SSH OS-fingerprint flow that
// captures os_family, os_version, kernel, architecture, hostname / FQDN,
// SELinux + AppArmor + firewall posture, and a hardware summary for
// each host on first contact + on-demand.
//
// Spec: app/specs/system/host-discovery.spec.yaml (status: approved).
//
// Architectural notes:
//
//   - Credential-aware boundary. Unlike internal/liveness — which
//     deliberately holds NO credential material and only opens a plain
//     TCP banner read — the discovery package IS credential-aware. It
//     imports internal/credential and golang.org/x/crypto/ssh, resolves
//     the host's stored auth, and runs an SSH session to execute its
//     probe commands. Spec C-11 + AC-15 source-inspect to guarantee
//     this boundary is documented (so a future reader does not move
//     credential-free probes here by accident).
//
//   - One SSH session per Discover. The probe is a closed set of
//     commands batched on a single session. Spec C-10 + AC-06 enforce
//     exactly one ssh.Dial per Discover call.
//
//   - Sudo failure is partial success. Firewall introspection requires
//     root on some distros. If sudo is unavailable for the host
//     credential, the firewall fields stay empty and the rest of the
//     fingerprint persists. Spec C-03 + AC-05.
//
//   - One transaction for two writes. host_system_info UPSERT + the
//     denormalized hosts.os_* columns are persisted within a single
//     BEGIN / COMMIT so list-page filters and the wide row never
//     disagree. Spec C-02 + AC-07.
//
//   - UPSERT-only on host_system_info (no history). A second Discover
//     UPDATEs the existing row keyed by host_id. Time-series of changes
//     belongs to the future host_intelligence_events Phase 3 spec, not
//     here. Spec C-08 + AC-14.
//
//   - Eventbus + audit on success. Discover publishes
//     eventbus.HostDiscovered and emits audit.HostDiscoveryCompleted
//     exactly once per successful run. Failures emit neither. Spec
//     C-06 / C-07 / AC-11 / AC-12.
package discovery
