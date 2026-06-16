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

	"github.com/Hanalyx/openwatch/internal/connprofile"
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
// gotPrefer records the auth-method hint the probe passed, so tests can
// assert the learning lead-with behaviour; observed is the method the
// stub reports as having authenticated.
type stubDialer struct {
	exec      *stubExec
	dialErr   error
	observed  connprofile.SSHAuthMethod
	gotPrefer connprofile.SSHAuthMethod
}

func (d *stubDialer) Dial(_ context.Context, _ *credential.Credential, _ string, _ time.Duration, prefer connprofile.SSHAuthMethod) (SessionExecutor, connprofile.SSHAuthMethod, error) {
	d.gotPrefer = prefer
	if d.dialErr != nil {
		return nil, "", d.dialErr
	}
	return d.exec, d.observed, nil
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

// TestBuildAuthMethods covers the realDialer's auth-method construction
// for every credential.AuthMethod branch. AuthBoth is the regression
// guard: the dialer must offer BOTH PublicKeys AND Password so a host
// where the key isn't authorized still falls back to password auth.
// The prior bug returned a key-only list for AuthBoth, leaving hosts
// stuck on "unable to authenticate, attempted methods [none publickey]"
// even though their credential carried a valid password.
func TestBuildAuthMethods(t *testing.T) {
	keyPEM := testEd25519PEM(t)

	t.Run("AuthSSHKey returns one method", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthSSHKey,
			PrivateKey: keyPEM,
		}
		methods, err := buildAuthMethods(cred, "", &authObserver{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got := len(methods); got != 1 {
			t.Errorf("methods: want 1, got %d", got)
		}
	})

	t.Run("AuthPassword returns one method", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthPassword,
			Password:   "p",
		}
		methods, err := buildAuthMethods(cred, "", &authObserver{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got := len(methods); got != 1 {
			t.Errorf("methods: want 1, got %d", got)
		}
	})

	t.Run("AuthBoth with key+password returns BOTH methods (regression guard)", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthBoth,
			PrivateKey: keyPEM,
			Password:   "p",
		}
		methods, err := buildAuthMethods(cred, "", &authObserver{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got := len(methods); got != 2 {
			t.Errorf("methods: want 2 (PublicKeys + Password), got %d -- this is the dialer bug from post-v1.2.0 regression", got)
		}
	})

	t.Run("AuthBoth with key only returns one method", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthBoth,
			PrivateKey: keyPEM,
		}
		methods, err := buildAuthMethods(cred, "", &authObserver{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got := len(methods); got != 1 {
			t.Errorf("methods: want 1 (PublicKeys), got %d", got)
		}
	})

	t.Run("AuthBoth with password only returns one method", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthBoth,
			Password:   "p",
		}
		methods, err := buildAuthMethods(cred, "", &authObserver{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got := len(methods); got != 1 {
			t.Errorf("methods: want 1 (Password), got %d", got)
		}
	})

	t.Run("AuthBoth with neither key nor password errors", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthBoth,
		}
		_, err := buildAuthMethods(cred, "", &authObserver{})
		if err == nil {
			t.Errorf("err: want non-nil for empty AuthBoth credential")
		}
	})

	t.Run("unknown AuthMethod errors", func(t *testing.T) {
		cred := &credential.Credential{
			Username:   "u",
			AuthMethod: credential.AuthMethod("bogus"),
		}
		_, err := buildAuthMethods(cred, "", &authObserver{})
		if err == nil {
			t.Errorf("err: want non-nil for unknown auth method")
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

// stubProfiles is an in-memory connprofile store for the learning tests.
type stubProfiles struct {
	mu       sync.Mutex
	prefer   connprofile.SSHAuthMethod
	recorded connprofile.SSHAuthMethod
	getErr   error
}

func (s *stubProfiles) Get(_ context.Context, _ uuid.UUID) (connprofile.Profile, error) {
	if s.getErr != nil {
		return connprofile.Profile{}, s.getErr
	}
	return connprofile.Profile{SSHAuthMethod: s.prefer}, nil
}

func (s *stubProfiles) RecordSSHAuth(_ context.Context, _ uuid.UUID, m connprofile.SSHAuthMethod) error {
	s.mu.Lock()
	s.recorded = m
	s.mu.Unlock()
	return nil
}

// @spec system-connection-profile
// @ac AC-09
// AC-09 (liveness half): when a profile store is wired, the probe leads
// the dial with the host's recorded auth method and records the method
// that authenticated. Without a store, no learning occurs.
func TestPrivilegeProbe_AuthLearning(t *testing.T) {
	t.Run("system-connection-profile/AC-09", func(t *testing.T) {
		hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())
		exec := &stubExec{outcomes: map[string]execResult{"sudo -n true": {code: 0}}}

		profiles := &stubProfiles{prefer: connprofile.AuthPassword}
		dialer := &stubDialer{exec: exec, observed: connprofile.AuthPassword}

		probe := Probe(
			stubResolver{cred: validCred()},
			WithDialer(dialer),
			WithProfiles(profiles),
		)
		if _, ok, err := probe(context.Background(), hostID, "192.0.2.1:22", 2*time.Second); !ok {
			t.Fatalf("ok: want true, got false; err=%v", err)
		}
		if dialer.gotPrefer != connprofile.AuthPassword {
			t.Errorf("lead-with: want dial prefer=password, got %q", dialer.gotPrefer)
		}
		if profiles.recorded != connprofile.AuthPassword {
			t.Errorf("record: want recorded=password, got %q", profiles.recorded)
		}
	})

	t.Run("no store: no learning", func(t *testing.T) {
		hostID := liveness.HostID(uuid.Must(uuid.NewV7()).String())
		exec := &stubExec{outcomes: map[string]execResult{"sudo -n true": {code: 0}}}
		dialer := &stubDialer{exec: exec, observed: connprofile.AuthKey}

		probe := Probe(stubResolver{cred: validCred()}, WithDialer(dialer))
		if _, ok, _ := probe(context.Background(), hostID, "192.0.2.1:22", 2*time.Second); !ok {
			t.Fatalf("ok: want true")
		}
		if dialer.gotPrefer != "" {
			t.Errorf("no-store: want empty prefer, got %q", dialer.gotPrefer)
		}
	})
}
