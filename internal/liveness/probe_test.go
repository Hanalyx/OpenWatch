// @spec system-liveness-loop
//
// AC traceability (this file):
//   AC-01  TestProbe_CompletesWithinTimeout
//   AC-02  TestProbe_TCPRefused_ReturnsError
//          TestProbe_Timeout_ReturnsTimeoutError
//   AC-03  TestProbe_SSHBanner_ReturnsReachable
//   AC-04  TestProbe_NonSSHBanner_ReturnsUnreachable

package liveness

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// startFakeBannerServer starts a TCP listener that sends bannerToSend
// on connect, then closes. Returns the addr ("127.0.0.1:port") and a
// stop func.
func startFakeBannerServer(t *testing.T, bannerToSend []byte) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				if bannerToSend != nil {
					_, _ = c.Write(bannerToSend)
				}
			}(conn)
		}
	}()

	stop := func() {
		_ = l.Close()
		<-done
	}
	return l.Addr().String(), stop
}

// @ac AC-01
// AC-01: Probe respects the timeout budget. Even against a black-hole
// destination, it returns within the deadline.
func TestProbe_CompletesWithinTimeout(t *testing.T) {
	t.Run("system-liveness-loop/AC-01", func(t *testing.T) {
		// 192.0.2.0/24 is the TEST-NET-1 reserved range — guaranteed
		// to be unrouted, so dial times out rather than refused.
		addr := "192.0.2.123:22"

		budget := 500 * time.Millisecond
		start := time.Now()
		res := Probe(context.Background(), addr, budget)
		elapsed := time.Since(start)

		if elapsed > budget+200*time.Millisecond {
			t.Errorf("Probe took %v, budget %v (overshoot exceeds tolerance)", elapsed, budget)
		}
		if res.Reachable {
			t.Error("Probe returned Reachable=true against TEST-NET-1 unrouted address")
		}
		if res.Error == nil {
			t.Error("Probe returned nil error against unroutable address")
		}
	})
}

// @ac AC-02
// AC-02: TCP-refused (no listener on port) is a clean failure with the
// "connection refused" classification.
func TestProbe_TCPRefused_ReturnsError(t *testing.T) {
	t.Run("system-liveness-loop/AC-02", func(t *testing.T) {
		// Bind a listener, close it immediately, capture the port.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()

		// Brief delay so the OS notices the port is free.
		time.Sleep(50 * time.Millisecond)

		res := Probe(context.Background(), addr, 2*time.Second)
		if res.Reachable {
			t.Error("Probe returned Reachable=true against closed port")
		}
		if res.Error == nil {
			t.Fatal("expected error against closed port")
		}
		errStr := strings.ToLower(res.Error.Error())
		if !strings.Contains(errStr, "refused") && !strings.Contains(errStr, "timeout") {
			t.Errorf("unexpected error string: %q (want 'refused' or 'timeout')", res.Error)
		}
		if got := res.LastErrorType(); got != "connection_refused" && got != "tcp_timeout" && got != "tcp_error" {
			t.Errorf("LastErrorType = %q, want connection_refused / tcp_timeout / tcp_error", got)
		}
	})
}

// @ac AC-02
// AC-02 (timeout): a server that accepts but never sends a banner
// triggers the read deadline.
func TestProbe_Timeout_ReturnsTimeoutError(t *testing.T) {
	t.Run("system-liveness-loop/AC-02", func(t *testing.T) {
		// Server that accepts and blocks (no banner sent).
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })

		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without sending anything.
			time.Sleep(2 * time.Second)
			_ = conn.Close()
		}()

		// 300ms budget — way less than the server's 2s hold.
		res := Probe(context.Background(), l.Addr().String(), 300*time.Millisecond)
		if res.Reachable {
			t.Error("Reachable=true against a black-hole-after-accept server")
		}
		if res.Error == nil {
			t.Error("expected an error from the read-deadline timeout")
		}
		<-done
	})
}

// @ac AC-03
// AC-03: a server sending "SSH-2.0-OpenSSH..." → Reachable=true with
// BannerSeen=true and ResponseTime > 0.
func TestProbe_SSHBanner_ReturnsReachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-03", func(t *testing.T) {
		addr, stop := startFakeBannerServer(t, []byte("SSH-2.0-OpenSSH_9.7\r\n"))
		t.Cleanup(stop)

		res := Probe(context.Background(), addr, 2*time.Second)
		if !res.Reachable {
			t.Errorf("Reachable=false against SSH-banner server (err: %v)", res.Error)
		}
		if !res.BannerSeen {
			t.Error("BannerSeen=false; expected true")
		}
		if res.ResponseTime <= 0 {
			t.Errorf("ResponseTime = %v, want > 0", res.ResponseTime)
		}
	})
}

// @ac AC-04
// AC-04: an HTTP-shaped banner on port 22 produces Reachable=false
// (with BannerSeen=true).
func TestProbe_NonSSHBanner_ReturnsUnreachable(t *testing.T) {
	t.Run("system-liveness-loop/AC-04", func(t *testing.T) {
		addr, stop := startFakeBannerServer(t, []byte("HTTP/1.1 200 OK\r\n"))
		t.Cleanup(stop)

		res := Probe(context.Background(), addr, 2*time.Second)
		if res.Reachable {
			t.Error("Reachable=true against HTTP banner; AC-04 broken")
		}
		if !res.BannerSeen {
			t.Error("BannerSeen=false despite server sending a banner")
		}
		if res.Error == nil {
			t.Error("expected non-nil Error for non-SSH banner")
		}
		if got := res.LastErrorType(); got != "banner_mismatch" {
			t.Errorf("LastErrorType = %q, want banner_mismatch", got)
		}
	})
}

// Compile-time confirmation that Probe matches the ProbeFunc seam.
var _ ProbeFunc = Probe

// Silence unused-import lints for testing helpers.
var _ = errors.Is
