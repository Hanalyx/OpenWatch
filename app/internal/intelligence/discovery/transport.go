package discovery

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
	"golang.org/x/crypto/ssh"
)

// SSHTransport is the seam between the discovery service and the actual
// SSH path. Production uses sshTransport (wraps owssh.Dial + ssh.Session);
// tests use stubSSHTransport.
//
// Dial MUST be called at most once per Discover (spec C-10).
type SSHTransport interface {
	Dial(ctx context.Context, host string, port int, cred *credential.Credential) (SSHSession, error)
}

// SSHSession is one live session against a remote host. Run executes
// a single command and returns stdout + exit code; the same session can
// be reused for every command the probe needs. Close releases the
// underlying transport.
type SSHSession interface {
	Run(ctx context.Context, cmd string) (stdout []byte, exitCode int, err error)
	Close() error
}

// DefaultProbeTimeout is the per-command budget on the SSH session.
// Commands that exceed it return an error and the field stays empty —
// a host with one hung command should not block the whole probe batch.
const DefaultProbeTimeout = 10 * time.Second

// sshTransport is the production SSHTransport. Wraps internal/ssh.Dial
// to honor the project's host-key + auth policy.
type sshTransport struct {
	mode  owssh.Mode
	store owssh.KnownHostsStore
}

// newSSHTransport returns a production SSHTransport with the given
// host-key policy.
func newSSHTransport(mode owssh.Mode, store owssh.KnownHostsStore) *sshTransport {
	return &sshTransport{mode: mode, store: store}
}

// Dial opens one SSH client connection and returns it as an SSHSession
// that multiplexes ssh.Session per Run call.
func (t *sshTransport) Dial(ctx context.Context, host string, port int, cred *credential.Credential) (SSHSession, error) {
	if cred == nil {
		return nil, errors.New("discovery: dial requires a resolved credential")
	}
	client, err := owssh.Dial(ctx, host, port, cred, owssh.DialOptions{
		Mode:    t.mode,
		Store:   t.store,
		Timeout: owssh.DefaultDialTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &sshClientSession{client: client}, nil
}

// sshClientSession is the per-host live SSH client. Each Run opens a
// fresh ssh.Session (one channel per command) atop the single client.
// crypto/ssh sessions are not reusable across commands, so this is the
// idiomatic shape.
type sshClientSession struct {
	client *ssh.Client
}

func (s *sshClientSession) Run(ctx context.Context, cmd string) ([]byte, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer sess.Close()

	// Honor caller deadline via a derived timeout so a hung command
	// can't wedge the probe batch indefinitely.
	deadline, ok := ctx.Deadline()
	var timer *time.Timer
	if ok {
		dur := time.Until(deadline)
		if dur > 0 {
			timer = time.AfterFunc(dur, func() { _ = sess.Signal(ssh.SIGKILL); _ = sess.Close() })
			defer timer.Stop()
		}
	}

	out, runErr := sess.CombinedOutput(cmd)
	exitCode := 0
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
			// Non-zero exit is NOT a Go-level error for our purposes;
			// the probe inspects exitCode itself (sudo failure path).
			return out, exitCode, nil
		}
		return out, -1, runErr
	}
	return out, exitCode, nil
}

func (s *sshClientSession) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

// joinHostPort formats host:port for log messages without importing net.
func joinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
