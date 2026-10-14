// @spec system-host-discovery

package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
	"golang.org/x/crypto/ssh"
)

// hangingServer completes an SSH handshake on conn with any password and
// accepts sessions, then answers a command's exec request and never sends
// output or an exit status. onExec, if set, runs when the exec arrives.
func hangingServer(t *testing.T, conn net.Conn, onExec func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)
	go func() {
		_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			ch, chReqs, err := nc.Accept()
			if err != nil {
				return
			}
			go func(ch ssh.Channel) {
				for req := range chReqs {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					if req.Type == "exec" && onExec != nil {
						onExec()
					}
				}
			}(ch)
		}
	}()
}

// stallConn is the client's end of a peer that dies mid-command: once
// stalled, every Read and Write blocks until the connection is closed, as
// with a host that has gone away without closing TCP.
type stallConn struct {
	net.Conn
	once    sync.Once
	stalled chan struct{}
	closed  chan struct{}
	shut    sync.Once
}

func newStallConn(c net.Conn) *stallConn {
	return &stallConn{Conn: c, stalled: make(chan struct{}), closed: make(chan struct{})}
}

func (c *stallConn) stall() { c.once.Do(func() { close(c.stalled) }) }

func (c *stallConn) wait() error {
	select {
	case <-c.stalled:
		<-c.closed
		return net.ErrClosed
	default:
		return nil
	}
}

func (c *stallConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if werr := c.wait(); werr != nil {
		return 0, werr
	}
	return n, err
}

func (c *stallConn) Write(b []byte) (int, error) {
	if err := c.wait(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *stallConn) Close() error {
	c.shut.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// pipeTransport dials through the real handshake and session code over an
// in-memory connection supplied by peer.
func pipeTransport(peer func() net.Conn) *SSHTransportProd {
	tr := NewSSHTransport(owssh.ModeTOFU, owssh.NewMemoryStore())
	tr.dial = func(ctx context.Context, host string, _ int, cred *credential.Credential, opts owssh.DialOptions) (SSHSession, error) {
		c, err := owssh.DialConn(ctx, peer(), host, cred, opts)
		if err != nil {
			return nil, err
		}
		return &SSHClientSession{client: c}, nil
	}
	return tr
}

// @ac AC-31
// AC-31: a Discover run ends within its bound when the host stops answering
// during the handshake or during a command, and the run's failure is
// recorded under its lease.
func TestDiscover_RunIsBounded(t *testing.T) {
	t.Run("system-host-discovery/AC-31", func(t *testing.T) {
		saved := sessionGrace
		sessionGrace = 100 * time.Millisecond
		t.Cleanup(func() { sessionGrace = saved })

		pool, hostID, credSvc := freshDBHost(t)
		ctx := context.Background()
		const runBound = 400 * time.Millisecond
		const limit = 5 * time.Second

		// The command cases need a buffered connection: over net.Pipe both
		// ends write their version banner first and deadlock before the
		// handshake completes.
		loopback := func(stallClient bool) func() net.Conn {
			return func() net.Conn {
				lis, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				t.Cleanup(func() { _ = lis.Close() })
				raw, err := net.Dial("tcp", lis.Addr().String())
				if err != nil {
					t.Fatalf("dial loopback: %v", err)
				}
				client := newStallConn(raw)
				t.Cleanup(func() { _ = client.Close() })
				var onExec func()
				if stallClient {
					onExec = client.stall
				}
				s, err := lis.Accept()
				if err != nil {
					t.Fatalf("accept: %v", err)
				}
				t.Cleanup(func() { _ = s.Close() })
				hangingServer(t, s, onExec)
				return client
			}
		}
		cases := []struct {
			name       string
			peer       func() net.Conn
			wantDialOK bool
		}{
			{"no SSH banner", func() net.Conn {
				c, s := net.Pipe()
				t.Cleanup(func() { _ = s.Close() })
				go func() { _, _ = io.Copy(io.Discard, s) }()
				return c
			}, false},
			{"command never answers", loopback(false), true},
			{"peer dies mid-command", loopback(true), true},
		}
		for i, tc := range cases {
			if _, err := pool.Exec(ctx, "DELETE FROM job_queue"); err != nil {
				t.Fatalf("clear jobs: %v", err)
			}
			svc := NewService(pool, nil, nil).
				WithHostLookup(PoolHostLookup{Pool: pool}).
				WithCredentialService(credSvc).
				WithSSHTransport(pipeTransport(tc.peer)).
				WithRunTimeout(runBound)
			l := claimLease(t, pool, hostID)
			done := make(chan error, 1)
			start := time.Now()
			go func() {
				_, err := svc.Discover(ctx, hostID, l)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s: Discover succeeded against a hung host", tc.name)
				}
				if tc.wantDialOK != (!errors.Is(err, owssh.ErrDialTimeout)) {
					t.Fatalf("%s: ended with %v, but the case is meant to %s", tc.name, err,
						map[bool]string{true: "get past the handshake", false: "hang in the handshake"}[tc.wantDialOK])
				}
			case <-time.After(limit):
				t.Fatalf("%s: Discover still running after %s (run bound %s)", tc.name, time.Since(start), runBound)
			}
			if st, msg := jobState(t, pool, l.JobID); st != "failed" || msg == "" {
				t.Fatalf("%s: job %s %q, want failed with a message", tc.name, st, msg)
			}
			if n := backoffCount(t, pool, hostID); n != i+1 {
				t.Fatalf("%s: backoff %d, want %d", tc.name, n, i+1)
			}
		}

		// The bound cannot be raised above RunTimeout.
		if got := NewService(pool, nil, nil).WithRunTimeout(RunTimeout + time.Hour).runTimeout; got != RunTimeout {
			t.Fatalf("WithRunTimeout above RunTimeout set %s", got)
		}
		if RunTimeout >= StaleDeadline {
			t.Fatalf("RunTimeout %s must stay below StaleDeadline %s", RunTimeout, StaleDeadline)
		}
	})
}
