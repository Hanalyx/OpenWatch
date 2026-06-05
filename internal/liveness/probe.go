package liveness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Probe opens a TCP connection to addr (e.g. "192.0.2.10:22"), reads up
// to MaxBannerBytes of the server's banner, classifies the result as
// reachable/unreachable based on whether the banner begins with "SSH-",
// and returns a ProbeResult.
//
// Spec ACs satisfied here:
//
//   - AC-01 (C-01, C-02, C-07): probe completes within timeout, returns
//     typed ProbeResult, never touches credentials.
//   - AC-02: TCP-refused / TCP-timeout produce Reachable=false with an
//     error classifiable via ProbeResult.LastErrorType().
//   - AC-03: an "SSH-2.0-..." banner produces Reachable=true.
//   - AC-04: a non-SSH banner (e.g. an HTTP server on port 22) produces
//     Reachable=false with BannerSeen=true.
//
// timeout is the WHOLE-probe budget; the dial and banner-read share it.
// ctx cancellation interrupts the probe before timeout if the caller
// goes away.
func Probe(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
	start := time.Now()

	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	// Combine caller's ctx with the timeout so whichever fires first wins.
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	if err != nil {
		return ProbeResult{
			Reachable:    false,
			ResponseTime: time.Since(start),
			Error:        err,
		}
	}
	defer func() { _ = conn.Close() }()

	// Set a read deadline that consumes the remaining timeout budget.
	deadline := start.Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return ProbeResult{
			Reachable:    false,
			ResponseTime: time.Since(start),
			Error:        err,
		}
	}

	buf := make([]byte, MaxBannerBytes)
	n, readErr := conn.Read(buf)
	elapsed := time.Since(start)

	// A connect-success with no banner returned (n=0) is unreachable —
	// the host accepts TCP but isn't speaking SSH (load balancer, fake
	// open port, etc.).
	if n == 0 {
		errMsg := "no banner read"
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			errMsg = readErr.Error()
		}
		return ProbeResult{
			Reachable:    false,
			ResponseTime: elapsed,
			BannerSeen:   false,
			Error:        errors.New(errMsg),
		}
	}

	banner := buf[:n]
	bannerStr := string(banner)

	if !strings.HasPrefix(bannerStr, "SSH-") {
		// A banner WAS returned but it isn't SSH. AC-04: not reachable
		// for our purposes (an HTTP server on port 22 is misuse).
		return ProbeResult{
			Reachable:    false,
			ResponseTime: elapsed,
			BannerSeen:   true,
			Banner:       cloneBytes(banner),
			Error:        fmt.Errorf("non-SSH banner: %q", truncate(bannerStr, 32)),
		}
	}

	return ProbeResult{
		Reachable:    true,
		ResponseTime: elapsed,
		BannerSeen:   true,
		Banner:       cloneBytes(banner),
		Error:        nil,
	}
}

// cloneBytes copies b so the caller can hold onto it after the probe's
// buf scope ends.
func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// truncate returns at most n bytes of s, with an ellipsis appended on
// truncation.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
