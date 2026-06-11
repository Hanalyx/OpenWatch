// Multi-layer probe — short-circuit chain of ICMP ping → TCP/SSH banner
// → opaque privilege check. The first failing layer decides the state
// band:
//
//	ping fail        → down       (host off the network)
//	ssh fail         → critical   (daemon down, firewall, port mismatch)
//	privilege fail   → degraded   (sudo broken — useful for ops but not
//	                               for compliance scans)
//	everything OK    → online
//
// The chain is short-circuited because there's no point trying SSH
// against an unpingable host or sudo against a closed SSH port — those
// probes will just time out and waste fleet capacity.
//
// Credential isolation (system-liveness-loop C-07 / AC-14): this
// package MUST NOT import internal/credential or golang.org/x/crypto/ssh.
// The privilege layer is an injected PrivilegeProbeFunc that owns its
// own credential decryption + SSH dial — keeps the liveness loop free
// of the DEK and of SSH-key parsing.

package liveness

import (
	"context"
	"time"
)

// PrivilegeProbeFunc runs the sudo / elevated-command check for a host.
// Implementations live OUTSIDE the liveness package because the check
// needs the DEK + the credential package — both forbidden here.
//
// Return shape:
//   - attempted=false  → the implementation chose not to attempt (e.g.
//     no credential available); the multi-layer result records no
//     privilege outcome and the state machine leaves the host above
//     'degraded' on this axis.
//   - attempted=true, ok=true  → sudo -n succeeded.
//   - attempted=true, ok=false → sudo failed; err describes why.
type PrivilegeProbeFunc func(ctx context.Context, hostID HostID, addr string, timeout time.Duration) (attempted, ok bool, err error)

// HostID is the credential-resolver's host identifier. Kept untyped to
// avoid an import cycle with the host package; callers convert from
// uuid.UUID at the call site.
type HostID string

// MultiLayerProbe orchestrates the chain. pinger may be nil — in which
// case the ping layer is skipped and SSH alone decides
// reachable/unreachable (matches the v1.2.x single-layer behavior).
// privilegeProbe may be nil — the privilege layer is skipped and the
// host stays in critical / down / online (whichever the lower layers
// chose).
type MultiLayerProbe struct {
	pinger         *Pinger
	privilegeProbe PrivilegeProbeFunc
	timeout        time.Duration
}

// NewMultiLayerProbe wires the three layers. timeout is the per-layer
// budget; the whole chain costs at most 3 × timeout in the worst case
// (privilege layer dwarfs the others on a healthy connection).
func NewMultiLayerProbe(pinger *Pinger, privilegeProbe PrivilegeProbeFunc, timeout time.Duration) *MultiLayerProbe {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	return &MultiLayerProbe{
		pinger:         pinger,
		privilegeProbe: privilegeProbe,
		timeout:        timeout,
	}
}

// Probe runs the chain for a single host. ip is the resolved IPv4 (no
// CIDR suffix); addr is "ip:port" for the SSH layer. hostID is what the
// credential resolver consumes.
func (p *MultiLayerProbe) Probe(ctx context.Context, hostID HostID, ip string, addr string) MultiLayerResult {
	start := time.Now()
	var out MultiLayerResult

	// Layer 1 — ICMP ping. Optional when the pinger is nil (e.g. ICMP
	// not permitted at boot). In that case we let SSH be the authority.
	if p.pinger != nil {
		pr := p.pinger.Ping(ctx, ip, p.timeout)
		out.PingOK = pr.OK
		out.PingRTT = pr.RTT
		out.PingErr = pr.Error
		if !pr.OK {
			out.FirstFailedLayer = LayerPing
			out.TotalRTT = time.Since(start)
			return out
		}
	} else {
		// No pinger — treat ping as OK so the chain progresses to SSH.
		// The state machine sees PingOK=true with PingRTT=0 and won't
		// credit a "ping succeeded" history row.
		out.PingOK = true
	}

	// Layer 2 — TCP / SSH banner.
	out.SSHAttempted = true
	sshRes := Probe(ctx, addr, p.timeout) // legacy single-layer banner probe
	out.SSHOK = sshRes.Reachable
	out.SSHRTT = sshRes.ResponseTime
	out.SSHBanner = sshRes.Banner
	out.SSHErr = sshRes.Error
	if !sshRes.Reachable {
		out.FirstFailedLayer = LayerSSH
		out.TotalRTT = time.Since(start)
		return out
	}

	// Layer 3 — opaque privilege check. The probe function decides
	// whether the host has a credential and whether sudo -n works.
	if p.privilegeProbe != nil {
		attempted, ok, perr := p.privilegeProbe(ctx, hostID, addr, p.timeout)
		out.PrivilegeAttempted = attempted
		out.PrivilegeOK = ok
		out.PrivilegeErr = perr
		if attempted && !ok {
			out.FirstFailedLayer = LayerPrivilege
		}
	}

	out.TotalRTT = time.Since(start)
	return out
}
