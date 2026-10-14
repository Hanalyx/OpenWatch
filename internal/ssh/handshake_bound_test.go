// @spec system-ssh-connectivity

package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// silentPeer returns the client end of an in-memory connection whose
// server end never sends an SSH banner. drain makes the server end read
// and discard; otherwise it never reads, so even the client's first write
// blocks.
func silentPeer(t *testing.T, drain bool) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	if drain {
		go func() { _, _ = io.Copy(io.Discard, server) }()
	}
	return client
}

// boundedDial runs fn and fails the test if it has not returned within
// limit, or returned something other than ErrDialTimeout.
func boundedDial(t *testing.T, name string, limit time.Duration, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrDialTimeout) {
			t.Errorf("%s: error %v, want ErrDialTimeout", name, err)
		}
	case <-time.After(limit):
		t.Fatalf("%s: still blocked after %s", name, time.Since(start))
	}
}

// @ac AC-23
// AC-23: the SSH handshake is bounded by the context and the dial timeout,
// and the bound is removed once the handshake succeeds.
func TestDial_HandshakeIsBounded(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-23", func(t *testing.T) {
		cred := passwordCred("test-only")
		const limit = 2 * time.Second

		for _, drain := range []bool{false, true} {
			name := map[bool]string{false: "peer not reading", true: "peer reading, never answering"}[drain]

			// ctx deadline shorter than the dial timeout.
			saved := netDial
			conn := silentPeer(t, drain)
			netDial = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			boundedDial(t, name+", ctx deadline", limit, func() error {
				c, err := Dial(ctx, "test.invalid", 22, cred, DialOptions{Mode: ModeTOFU})
				if c != nil {
					_ = c.Close()
				}
				return err
			})
			cancel()

			// Dial timeout shorter than any ctx deadline.
			conn = silentPeer(t, drain)
			netDial = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			boundedDial(t, name+", dial timeout", limit, func() error {
				_, err := Dial(context.Background(), "test.invalid", 22, cred,
					DialOptions{Mode: ModeTOFU, Timeout: 100 * time.Millisecond})
				return err
			})

			// Cancellation with no deadline at all.
			conn = silentPeer(t, drain)
			netDial = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			cctx, ccancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, ccancel)
			boundedDial(t, name+", canceled", limit, func() error {
				_, err := Dial(cctx, "test.invalid", 22, cred, DialOptions{Mode: ModeTOFU})
				return err
			})
			netDial = saved

			// DialConn on a caller's connection.
			dctx, dcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			boundedDial(t, name+", DialConn", limit, func() error {
				_, err := DialConn(dctx, silentPeer(t, drain), "test.invalid", cred, DialOptions{Mode: ModeTOFU})
				return err
			})
			dcancel()
		}

		// A successful handshake leaves no bound on the live client.
		host, port, _, _ := startTestServer(t, testServerOpts{password: "test-only"})
		c, err := Dial(context.Background(), host, port, cred,
			DialOptions{Mode: ModeTOFU, Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatalf("dial test server: %v", err)
		}
		defer c.Close()
		time.Sleep(500 * time.Millisecond)
		sess, err := c.NewSession()
		if err != nil {
			t.Fatalf("new session after the handshake bound passed: %v", err)
		}
		defer sess.Close()
		out, err := sess.Output("anything")
		if err != nil || string(out) != "hello\n" {
			t.Fatalf("command after the handshake bound passed: %q %v", out, err)
		}
	})
}
