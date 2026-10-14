package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

// ConnProfileStore is the subset of connprofile the transport uses to lead
// with the host's known-good SSH auth method and record what authenticated.
// nil disables learning (dial in the default key-first order). The host id
// is read from the context via connprofile.HostIDFrom.
type ConnProfileStore interface {
	Get(ctx context.Context, hostID uuid.UUID) (connprofile.Profile, error)
	RecordSSHAuth(ctx context.Context, hostID uuid.UUID, m connprofile.SSHAuthMethod) error
}

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
	// RunWithStdin is the sudo-password-fallback hook (system-ssh-
	// connectivity v1.1.0 C-10). ssh.RunSudo pipes the credential
	// password through here when the policy allows.
	RunWithStdin(ctx context.Context, cmd string, stdin []byte) (stdout []byte, exitCode int, err error)
	Close() error
}

// DefaultProbeTimeout is the per-command budget on the SSH session.
// Commands that exceed it return an error and the field stays empty —
// a host with one hung command should not block the whole probe batch.
const DefaultProbeTimeout = 10 * time.Second

// SSHTransportProd is the production SSHTransport. Wraps internal/ssh.Dial
// to honor the project's host-key + auth policy. Exported so cmd/openwatch
// and tests that want a real (not stubbed) transport can construct one
// without internal package boundaries.
type SSHTransportProd struct {
	mode     owssh.Mode
	store    owssh.KnownHostsStore
	profiles ConnProfileStore
	// dial is the seam over internal/ssh.Dial — overridden in tests to
	// exercise the auth-learning path (PreferAuth in / ObservedAuth out)
	// without standing up a real SSH server. Defaults to dialReal.
	dial func(ctx context.Context, host string, port int, cred *credential.Credential, opts owssh.DialOptions) (SSHSession, error)
}

// NewSSHTransport returns a production SSHTransport with the given
// host-key policy. NewService() calls this with TOFU + an in-memory
// known-hosts store by default; cmd/openwatch can override with a
// strict + persistent store later.
func NewSSHTransport(mode owssh.Mode, store owssh.KnownHostsStore) *SSHTransportProd {
	return &SSHTransportProd{mode: mode, store: store, dial: dialReal}
}

// dialReal is the production dial: open the real SSH client and wrap it.
func dialReal(ctx context.Context, host string, port int, cred *credential.Credential, opts owssh.DialOptions) (SSHSession, error) {
	client, err := owssh.Dial(ctx, host, port, cred, opts)
	if err != nil {
		return nil, err
	}
	return &SSHClientSession{client: client}, nil
}

// WithProfiles enables per-host SSH auth-method learning: the transport
// leads the dial with the host's recorded method and records which method
// authenticated. The host id comes from connprofile.WithHostID on the ctx.
// nil (the default) keeps the historical key-first, no-learning behavior.
func (t *SSHTransportProd) WithProfiles(p ConnProfileStore) *SSHTransportProd {
	t.profiles = p
	return t
}

// Dial opens one SSH client connection and returns it as an SSHSession
// that multiplexes ssh.Session per Run call. When a profile store is wired
// and the ctx carries a host id, the dial leads with the host's recorded
// auth method and records the one that authenticated (a hint, not a lock:
// both methods are still offered, and a stale hint self-heals).
func (t *SSHTransportProd) Dial(ctx context.Context, host string, port int, cred *credential.Credential) (SSHSession, error) {
	if cred == nil {
		return nil, errors.New("discovery: dial requires a resolved credential")
	}

	hostID, learn := connprofile.HostIDFrom(ctx)
	learn = learn && t.profiles != nil

	opts := owssh.DialOptions{
		Mode:    t.mode,
		Store:   t.store,
		Timeout: owssh.DefaultDialTimeout,
	}
	var observed string
	if learn {
		if p, err := t.profiles.Get(ctx, hostID); err == nil {
			opts.PreferAuth = string(p.SSHAuthMethod) // "key"/"password" match the ssh.Prefer* tokens
		}
		opts.ObservedAuth = &observed
	}

	sess, err := t.dial(ctx, host, port, cred, opts)
	if err != nil {
		return nil, err
	}
	if learn && observed != "" {
		// A discovery run collects the observation and records it in the
		// transaction that writes its results under its job lease, so a
		// run that has lost its job cannot overwrite a newer profile
		// (bugs/OW-120). Other callers record it at once.
		if o := observationsFrom(ctx); o != nil {
			o.sshAuth = connprofile.SSHAuthMethod(observed)
		} else {
			_ = t.profiles.RecordSSHAuth(ctx, hostID, connprofile.SSHAuthMethod(observed))
		}
	}
	return sess, nil
}

// observations holds what one discovery run learned about reaching its
// host. The run records it with its results, under its lease.
type observations struct {
	sshAuth connprofile.SSHAuthMethod
	sudo    connprofile.SudoMode
}

type observationsKey struct{}

func withObservations(ctx context.Context, o *observations) context.Context {
	return context.WithValue(ctx, observationsKey{}, o)
}

func observationsFrom(ctx context.Context) *observations {
	o, _ := ctx.Value(observationsKey{}).(*observations)
	return o
}

// SSHClientSession is the per-host live SSH client. Each Run opens a
// fresh ssh.Session (one channel per command) atop the single client.
// crypto/ssh sessions are not reusable across commands, so this is the
// idiomatic shape.
type SSHClientSession struct {
	client *ssh.Client
}

// Run executes cmd on a fresh session, bounded by ctx (see run).
func (s *SSHClientSession) Run(ctx context.Context, cmd string) ([]byte, int, error) {
	return s.run(ctx, cmd, nil, false)
}

// RunWithStdin runs cmd with the given bytes piped to the remote
// process's stdin. Used by ssh.RunSudo for the `sudo -S` password
// fallback path. Same channel-per-command pattern as Run.
//
// Spec system-ssh-connectivity v1.1.0 C-10.
func (s *SSHClientSession) RunWithStdin(ctx context.Context, cmd string, stdin []byte) ([]byte, int, error) {
	return s.run(ctx, cmd, stdin, true)
}

// sessionGrace is how long a canceled command has to stop after its
// session is signaled and closed. A server that has stopped answering may
// never acknowledge the close, so after the grace the whole connection is
// closed, which always unblocks the read.
var sessionGrace = 2 * time.Second

// run executes cmd on a new session, bounded by ctx: opening the session,
// the command and its output all end when ctx does, whether it is canceled
// or reaches its deadline (bugs/OW-120, spec system-host-discovery C-16).
// A non-zero exit is not a Go-level error; the probe inspects the code.
func (s *SSHClientSession) run(ctx context.Context, cmd string, stdin []byte, withStdin bool) ([]byte, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, -1, err
	}
	type result struct {
		out  []byte
		code int
		err  error
	}
	done := make(chan result, 1)
	var mu sync.Mutex
	var sess *ssh.Session
	go func() {
		ss, err := s.client.NewSession()
		if err != nil {
			done <- result{nil, -1, err}
			return
		}
		mu.Lock()
		sess = ss
		mu.Unlock()
		defer ss.Close()
		if withStdin {
			pipe, err := ss.StdinPipe()
			if err != nil {
				done <- result{nil, -1, err}
				return
			}
			go func() {
				_, _ = pipe.Write(stdin)
				_ = pipe.Close()
			}()
		}
		out, runErr := ss.CombinedOutput(cmd)
		if runErr != nil {
			var exitErr *ssh.ExitError
			if errors.As(runErr, &exitErr) {
				done <- result{out, exitErr.ExitStatus(), nil}
				return
			}
			done <- result{out, -1, runErr}
			return
		}
		done <- result{out, 0, nil}
	}()

	select {
	case r := <-done:
		return r.out, r.code, r.err
	case <-ctx.Done():
	}
	// Signal and close in the background: against a server that has
	// stopped reading, these writes can block, and the grace below must
	// still run.
	mu.Lock()
	if sess != nil {
		go func(ss *ssh.Session) {
			_ = ss.Signal(ssh.SIGKILL)
			_ = ss.Close()
		}(sess)
	}
	mu.Unlock()
	var r result
	select {
	case r = <-done:
	case <-time.After(sessionGrace):
		_ = s.client.Close()
		r = <-done
	}
	return r.out, -1, fmt.Errorf("discovery: command ended by its context: %w", ctx.Err())
}

func (s *SSHClientSession) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}
