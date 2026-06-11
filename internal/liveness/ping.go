// ICMP ping primitive. One Echo Request / Echo Reply round-trip, no
// retries — the caller decides how often to probe and whether to
// average across multiple packets.
//
// Two open modes are supported:
//
//   - Privileged "ip4:icmp" (SOCK_RAW with IPPROTO_ICMP) — requires
//     CAP_NET_RAW or root. Set by RPM/DEB postinstall with setcap.
//   - Unprivileged "udp4" (SOCK_DGRAM with IPPROTO_ICMP) — requires
//     the host kernel's net.ipv4.ping_group_range to include the gid
//     the openwatch process runs as. Linux kernel >= 3.0.
//
// PingerOpen probes both at construction time so the cost is paid once
// at boot, not per probe. The chosen mode is logged so operators can
// confirm which path is active.

package liveness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingMode names the open-socket strategy the Pinger ended up using.
type PingMode string

const (
	// PingModePrivileged uses SOCK_RAW + IPPROTO_ICMP. Needs CAP_NET_RAW.
	PingModePrivileged PingMode = "raw"
	// PingModeUnprivileged uses SOCK_DGRAM + IPPROTO_ICMP. Needs the
	// kernel's ping_group_range sysctl to include our gid.
	PingModeUnprivileged PingMode = "dgram"
)

// ErrICMPNotPermitted is returned by NewPinger when neither the raw nor
// the unprivileged ICMP socket can be opened. The error's underlying
// cause is wrapped — typically "operation not permitted" (no
// CAP_NET_RAW) for the raw path and "permission denied" (sysctl
// missing) for the unprivileged path.
var ErrICMPNotPermitted = errors.New("liveness: ICMP socket not permitted (need CAP_NET_RAW or ping_group_range sysctl)")

// Pinger holds an open ICMP socket and serializes Echo Request / Reply
// round-trips against it. One Pinger per process is enough — concurrent
// callers serialize through Ping(). The wire identifier is the PID so
// replies from other processes don't get confused with ours.
type Pinger struct {
	conn *icmp.PacketConn
	mode PingMode
	id   int
}

// NewPinger opens an ICMP socket. Tries the privileged path first
// (matches the system `ping` binary's permission model), then the
// unprivileged path. Returns ErrICMPNotPermitted wrapping the last
// error if both fail.
func NewPinger() (*Pinger, error) {
	if conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return &Pinger{conn: conn, mode: PingModePrivileged, id: os.Getpid() & 0xffff}, nil
	} else if conn2, err2 := icmp.ListenPacket("udp4", "0.0.0.0"); err2 == nil {
		return &Pinger{conn: conn2, mode: PingModeUnprivileged, id: os.Getpid() & 0xffff}, nil
	} else {
		return nil, fmt.Errorf("%w: raw=%v dgram=%v", ErrICMPNotPermitted, err, err2)
	}
}

// Mode returns which socket strategy this Pinger is using. Surface for
// boot logging.
func (p *Pinger) Mode() PingMode { return p.mode }

// Close releases the ICMP socket. Safe to call multiple times.
func (p *Pinger) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

// PingResult is the outcome of one Echo Request / Echo Reply round-trip.
type PingResult struct {
	// OK is true when a matching ICMP Echo Reply arrived within the
	// timeout. A "destination unreachable" / "time exceeded" reply also
	// produces OK=false with the relevant Error.
	OK bool

	// RTT is the wall-clock time from write to read. Always populated;
	// zero only on impossible-input errors.
	RTT time.Duration

	// Error classifies the failure. nil on OK. Fixed strings the state
	// machine consumes:
	//   - "icmp_timeout"          : no reply within timeout
	//   - "destination_unreachable": ICMP type 3 reply
	//   - "icmp_error"            : other write/read failure
	Error error
}

// Ping sends one Echo Request to ipv4Addr and waits up to timeout for
// the matching reply. ipv4Addr MUST be a literal IPv4 address (no
// hostname resolution — callers resolve up front). The seq number is
// derived from a monotonic counter shared across all calls on this
// Pinger so concurrent Pings don't collide.
func (p *Pinger) Ping(ctx context.Context, ipv4Addr string, timeout time.Duration) PingResult {
	start := time.Now()
	if p == nil || p.conn == nil {
		return PingResult{Error: errors.New("liveness: nil Pinger")}
	}
	ip := net.ParseIP(ipv4Addr)
	if ip == nil || ip.To4() == nil {
		return PingResult{Error: fmt.Errorf("liveness: not an IPv4 address: %s", ipv4Addr)}
	}

	// Build the request. For udp4 (unprivileged) mode, x/net/icmp uses
	// the kernel-assigned id — supplying ours is ignored but harmless.
	seq := nextPingSeq()
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  seq,
			Data: []byte("openwatch-liveness"),
		},
	}
	buf, err := msg.Marshal(nil)
	if err != nil {
		return PingResult{Error: fmt.Errorf("icmp marshal: %w", err)}
	}

	// In udp4 mode the destination address MUST be a *net.UDPAddr; in
	// ip4:icmp mode it MUST be a *net.IPAddr. The mode chose one; pick
	// the matching shape.
	var dst net.Addr
	if p.mode == PingModeUnprivileged {
		dst = &net.UDPAddr{IP: ip}
	} else {
		dst = &net.IPAddr{IP: ip}
	}

	deadline := start.Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.conn.SetDeadline(deadline); err != nil {
		return PingResult{Error: fmt.Errorf("set deadline: %w", err), RTT: time.Since(start)}
	}
	if _, err := p.conn.WriteTo(buf, dst); err != nil {
		return PingResult{Error: fmt.Errorf("icmp write: %w", err), RTT: time.Since(start)}
	}

	reply := make([]byte, 1500)
	for {
		n, peer, err := p.conn.ReadFrom(reply)
		if err != nil {
			if isTimeoutError(err) {
				return PingResult{Error: errors.New("icmp_timeout"), RTT: time.Since(start)}
			}
			return PingResult{Error: fmt.Errorf("icmp read: %w", err), RTT: time.Since(start)}
		}
		// Ignore replies not from our target.
		if !sameIP(peer, ip) {
			continue
		}
		parsed, err := icmp.ParseMessage(1 /* IPv4 ICMP */, reply[:n])
		if err != nil {
			return PingResult{Error: fmt.Errorf("icmp parse: %w", err), RTT: time.Since(start)}
		}
		switch parsed.Type {
		case ipv4.ICMPTypeEchoReply:
			if echo, ok := parsed.Body.(*icmp.Echo); ok {
				// Privileged mode lets us match id+seq exactly. In
				// unprivileged (udp4) mode the kernel rewrites the id
				// to its own per-socket id, so we only match seq.
				if p.mode == PingModePrivileged && echo.ID != p.id {
					continue
				}
				if echo.Seq != seq {
					continue
				}
				return PingResult{OK: true, RTT: time.Since(start)}
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			return PingResult{Error: errors.New("destination_unreachable"), RTT: time.Since(start)}
		case ipv4.ICMPTypeTimeExceeded:
			return PingResult{Error: errors.New("time_exceeded"), RTT: time.Since(start)}
		}
		// Unrelated message (e.g. another Echo Request on the wire).
		// Loop until deadline or a matching reply.
	}
}

// sameIP returns true when peer's IP equals ip. peer may be *net.IPAddr
// (raw mode) or *net.UDPAddr (dgram mode).
func sameIP(peer net.Addr, ip net.IP) bool {
	switch a := peer.(type) {
	case *net.IPAddr:
		return a.IP.Equal(ip)
	case *net.UDPAddr:
		return a.IP.Equal(ip)
	}
	return false
}

// nextPingSeq returns a monotonically increasing 16-bit sequence number
// shared by every Pinger in the process. 16-bit wrap is harmless —
// concurrent in-flight probes per target are bounded by the Service's
// per-host inFlight gate so a wrap-collision needs more in-flight
// probes than the gate allows.
var pingSeqCounter uint32

func nextPingSeq() int {
	pingSeqCounter++
	return int(pingSeqCounter & 0xffff)
}
