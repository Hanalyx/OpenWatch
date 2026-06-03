// @spec system-ssh-connectivity
//
// AC traceability (this file):
//
//   AC-18  TestPrivilegeProbe_PasswordFallback_SuccessAndPolicyOff
//   AC-19  TestPrivilegeProbe_PasswordFallback_NoPassword_NoSecondCall
//   AC-21  TestPrivilegeProbe_NoFallbackOnSudoNSuccess
//
// The tests substitute a stub SSH executor so the wiring can be
// exercised without standing up a real SSH server (gliderlabs/ssh has
// its own coverage at internal/ssh).

package sshprivilege

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/liveness"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
)

// testEd25519PEM returns a freshly-generated PKCS#8 Ed25519 private
// key encoded as PEM. The shape is what credential.AuthSSHKey expects
// in cred.PrivateKey.
func testEd25519PEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// stubExec records every command sent through Run / RunWithStdin and
// can be programmed to return a specific exit code per command prefix.
// A nil reader on RunWithStdin asserts the test forgot to send a
// password.
type stubExec struct {
	mu sync.Mutex
	// programmed outcomes keyed by exact command string. Default is
	// exit 0 with no output unless a key matches.
	outcomes map[string]execResult
	// recorded calls in chronological order.
	calls []recordedCall
}

type execResult struct {
	out  []byte
	code int
	err  error
}

type recordedCall struct {
	cmd      string
	hadStdin bool
}

func (s *stubExec) Run(_ context.Context, cmd string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, recordedCall{cmd: cmd, hadStdin: false})
	if r, ok := s.outcomes[cmd]; ok {
		return r.out, r.code, r.err
	}
	return nil, 0, nil
}

func (s *stubExec) RunWithStdin(_ context.Context, cmd string, stdin io.Reader) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, recordedCall{cmd: cmd, hadStdin: stdin != nil})
	if r, ok := s.outcomes[cmd]; ok {
		return r.out, r.code, r.err
	}
	return nil, 0, nil
}

func (s *stubExec) Close() error { return nil }

func (s *stubExec) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// stubResolver returns a fixed credential.
type stubResolver struct {
	cred *credential.Credential
	err  error
}

func (r stubResolver) Resolve(_ context.Context, _ uuid.UUID) (*credential.Credential, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.cred, nil
}

// stubPolicy returns a fixed SecurityConfig.
type stubPolicy struct {
	cfg systemconfig.SecurityConfig
	err error
}

func (p stubPolicy) LoadSecurity(_ context.Context) (systemconfig.SecurityConfig, error) {
	return p.cfg, p.err
}

// stubDialer returns a programmed stubExec without touching real SSH.
type stubDialer struct {
	exec    *stubExec
	dialErr error
}

func (d *stubDialer) Dial(_ context.Context, _ *credential.Credential, _ string, _ time.Duration) (SessionExecutor, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.exec, nil
}

func validCred() *credential.Credential {
	return &credential.Credential{
		Username:   "owadmin",
		AuthMethod: credential.AuthBoth,
		Password:   "secret-pw",
	}
}

// @ac AC-18
// AC-18 (positive): sudo -n fails → policy on + cred has password →
// sudo -S -k -p ” succeeds → probe returns ok=true.
// AC-18 (negative): same stub responses but policy off → probe returns
// ok=false and issues NO sudo -S call.
func TestPrivilegeProbe_PasswordFallback_SuccessAndPolicyOff(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-18", func(t *testing.T) {
		hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())

		// Programming: sudo -n exit 1; sudo -S -k exit 0.
		mkExec := func() *stubExec {
			return &stubExec{
				outcomes: map[string]execResult{
					"sudo -n true":          {code: 1, err: errors.New("exit 1")},
					"sudo -S -k -p '' true": {code: 0},
				},
			}
		}

		// Policy ON, password present → fallback engages, probe ok.
		exec := mkExec()
		probe := Probe(
			stubResolver{cred: validCred()},
			WithPolicyLoader(stubPolicy{cfg: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true}}),
			WithDialer(&stubDialer{exec: exec}),
		)
		attempted, ok, err := probe(context.Background(), hostID, "192.0.2.1:22", 2*time.Second)
		if !attempted {
			t.Errorf("attempted: want true, got false")
		}
		if !ok {
			t.Errorf("ok: want true (fallback succeeded), got false; err=%v", err)
		}
		if exec.callCount() != 2 {
			t.Errorf("call count: want 2 (sudo -n + sudo -S -k), got %d", exec.callCount())
		}
		// Fallback call MUST carry stdin (the password).
		if !exec.calls[1].hadStdin {
			t.Errorf("fallback call missing stdin (password not fed)")
		}
		// Fallback cmd MUST carry -k.
		if exec.calls[1].cmd != "sudo -S -k -p '' true" {
			t.Errorf("fallback cmd = %q, want %q", exec.calls[1].cmd, "sudo -S -k -p '' true")
		}

		// Policy OFF → no fallback issued.
		exec2 := mkExec()
		probe2 := Probe(
			stubResolver{cred: validCred()},
			WithPolicyLoader(stubPolicy{cfg: systemconfig.SecurityConfig{AllowCredentialSudoPassword: false}}),
			WithDialer(&stubDialer{exec: exec2}),
		)
		_, ok2, _ := probe2(context.Background(), hostID, "192.0.2.1:22", 2*time.Second)
		if ok2 {
			t.Errorf("policy off: want ok=false, got true")
		}
		if exec2.callCount() != 1 {
			t.Errorf("policy off: want exactly 1 call (sudo -n), got %d", exec2.callCount())
		}
	})
}

// @ac AC-19
// AC-19: credential cannot supply a password (ssh_key only OR empty
// Password). Policy on but no password to feed → probe MUST NOT issue
// sudo -S; sudo -n exit 1 surfaces as ok=false.
func TestPrivilegeProbe_PasswordFallback_NoPassword_NoSecondCall(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-19", func(t *testing.T) {
		hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())

		// AuthMethod ssh_key with empty Password.
		keyOnly := &credential.Credential{
			Username:   "owadmin",
			AuthMethod: credential.AuthSSHKey,
			PrivateKey: testEd25519PEM(t),
		}

		exec := &stubExec{
			outcomes: map[string]execResult{
				"sudo -n true": {code: 1, err: errors.New("exit 1")},
			},
		}
		probe := Probe(
			stubResolver{cred: keyOnly},
			WithPolicyLoader(stubPolicy{cfg: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true}}),
			WithDialer(&stubDialer{exec: exec}),
		)
		_, ok, _ := probe(context.Background(), hostID, "192.0.2.1:22", 2*time.Second)
		if ok {
			t.Errorf("ok: want false (no password to fall back with), got true")
		}
		if exec.callCount() != 1 {
			t.Errorf("call count: want 1 (sudo -n only), got %d", exec.callCount())
		}

		// And AuthMethod=password with EMPTY Password is the same shape.
		emptyPw := &credential.Credential{
			Username:   "owadmin",
			AuthMethod: credential.AuthPassword,
			Password:   "",
		}
		exec2 := &stubExec{
			outcomes: map[string]execResult{
				"sudo -n true": {code: 1, err: errors.New("exit 1")},
			},
		}
		probe2 := Probe(
			stubResolver{cred: emptyPw},
			WithPolicyLoader(stubPolicy{cfg: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true}}),
			WithDialer(&stubDialer{exec: exec2}),
		)
		_, ok2, _ := probe2(context.Background(), hostID, "192.0.2.1:22", 2*time.Second)
		if ok2 {
			t.Errorf("empty password: want ok=false, got true")
		}
		if exec2.callCount() != 1 {
			t.Errorf("empty password: want 1 call, got %d", exec2.callCount())
		}
	})
}

// @ac AC-21
// AC-21 (sshprivilege half): sudo -n succeeds → fallback path MUST NOT
// execute even with policy + password available. Negative invariant.
func TestPrivilegeProbe_NoFallbackOnSudoNSuccess(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-21", func(t *testing.T) {
		hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())

		exec := &stubExec{
			outcomes: map[string]execResult{
				"sudo -n true": {code: 0}, // NOPASSWD host
			},
		}
		probe := Probe(
			stubResolver{cred: validCred()},
			WithPolicyLoader(stubPolicy{cfg: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true}}),
			WithDialer(&stubDialer{exec: exec}),
		)
		_, ok, err := probe(context.Background(), hostID, "192.0.2.1:22", 2*time.Second)
		if !ok {
			t.Errorf("ok: want true (sudo -n succeeded), got false; err=%v", err)
		}
		if exec.callCount() != 1 {
			t.Errorf("call count: want 1 (sudo -n succeeded; no fallback), got %d", exec.callCount())
		}
	})
}
