// @spec system-connection-profile
//
// Live-host SSH/sudo integration test. Unlike every other test in this
// package (which stubs the transport), this one opens REAL SSH connections
// to real boxes and runs real sudo, closing the project's biggest test
// blind spot: the dial, auth-ordering, and sudo `-n`/`-S` paths are
// otherwise only exercised at the command-construction level, never
// against a live host.
//
// It is OPT-IN and self-skipping: set both
//
//	OPENWATCH_LIVE_HOSTS=/path/to/test_hosts.csv   (hostname,ip,username,credential[=password])
//	OPENWATCH_LIVE_KEY=/path/to/id_rsa             (an OpenSSH private key authorized for the user)
//
// to run it. With either unset it t.Skip()s, so it never gates normal CI.
// The inventory + key live on the operator's workstation, never in the repo.
//
// What it asserts per reachable host:
//
//	AC-04  key auth dials and ObservedAuth reports "key"
//	AC-04  password auth dials and ObservedAuth reports "password"
//	AC-10  RunSudo confirms a sudo mode (nopasswd or password) via `true`
//	AC-10  leading with SudoPassword exercises the real `sudo -S` wire path
//
// These are exactly the observations the per-host connprofile memo records,
// so a green run is end-to-end proof that the learning inputs are real.

package ssh

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
)

type liveHost struct {
	name     string
	addr     string
	user     string
	password string
}

// loadLiveHosts reads the opt-in inventory + key, or skips the test.
func loadLiveHosts(t *testing.T) ([]liveHost, string) {
	t.Helper()
	csvPath := os.Getenv("OPENWATCH_LIVE_HOSTS")
	keyPath := os.Getenv("OPENWATCH_LIVE_KEY")
	if csvPath == "" || keyPath == "" {
		t.Skip("set OPENWATCH_LIVE_HOSTS (csv) and OPENWATCH_LIVE_KEY (private key) to run live-host SSH tests")
	}

	keyBytes, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied test key path
	if err != nil {
		t.Fatalf("read OPENWATCH_LIVE_KEY %q: %v", keyPath, err)
	}
	// Sanity-check the key parses before we fan out to every host, so a bad
	// key fails once with a clear message instead of N opaque dial errors.
	if _, perr := cryptossh.ParsePrivateKey(keyBytes); perr != nil {
		t.Fatalf("OPENWATCH_LIVE_KEY %q is not a usable private key: %v", keyPath, perr)
	}

	f, err := os.Open(csvPath) // #nosec G304 -- operator-supplied test inventory path
	if err != nil {
		t.Fatalf("open OPENWATCH_LIVE_HOSTS %q: %v", csvPath, err)
	}
	defer func() { _ = f.Close() }()

	var hosts []liveHost
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		cols := strings.Split(line, ",")
		// Skip the header row (hostname,ip,username,credential).
		if first {
			first = false
			if strings.EqualFold(strings.TrimSpace(cols[0]), "hostname") {
				continue
			}
		}
		if len(cols) < 3 {
			continue
		}
		h := liveHost{
			name: strings.TrimSpace(cols[0]),
			addr: strings.TrimSpace(cols[1]),
			user: strings.TrimSpace(cols[2]),
		}
		if len(cols) >= 4 {
			h.password = strings.TrimSpace(cols[3])
		}
		if h.addr == "" || h.user == "" {
			continue
		}
		hosts = append(hosts, h)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan inventory: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatalf("OPENWATCH_LIVE_HOSTS %q yielded no usable rows", csvPath)
	}
	return hosts, string(keyBytes)
}

// liveSession adapts a real *ssh.Client to SudoSession so RunSudo (the
// shared sudo primitive) can run against it exactly as production does.
type liveSession struct{ client *cryptossh.Client }

func (s liveSession) Run(_ context.Context, cmd string) ([]byte, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer func() { _ = sess.Close() }()
	out, runErr := sess.CombinedOutput(cmd)
	return out, exitCodeOf(runErr), nonExitErr(runErr)
}

func (s liveSession) RunWithStdin(_ context.Context, cmd string, stdin []byte) ([]byte, int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, -1, err
	}
	defer func() { _ = sess.Close() }()
	pipe, perr := sess.StdinPipe()
	if perr != nil {
		return nil, -1, perr
	}
	go func() {
		_, _ = pipe.Write(stdin)
		_ = pipe.Close()
	}()
	out, runErr := sess.CombinedOutput(cmd)
	return out, exitCodeOf(runErr), nonExitErr(runErr)
}

// exitCodeOf returns the remote exit status (0 on success), or -1 for a
// transport-level error.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *cryptossh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus()
	}
	return -1
}

// nonExitErr passes through transport errors but swallows a clean non-zero
// exit (that is a valid result, surfaced via the code).
func nonExitErr(err error) error {
	var ee *cryptossh.ExitError
	if err == nil || errors.As(err, &ee) {
		return nil
	}
	return err
}

// isAuthRejection reports a server-side auth REJECTION (the key isn't
// authorized, or PasswordAuthentication is off) as opposed to a transport
// fault. A real fleet is heterogeneous — not every host accepts every
// method — so a rejection is a host-config fact to tolerate, not an
// OpenWatch bug. (A handshake/protocol error is neither and stays fatal.)
func isAuthRejection(err error) bool {
	s := err.Error()
	return strings.Contains(s, "unable to authenticate") ||
		strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "no supported methods remain")
}

// isUnreachable reports a connection-level failure (host down / firewalled
// / wrong subnet) — reachability is the operator's network, not our code,
// so the host is skipped rather than failed.
func isUnreachable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "no route to host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connect: ") ||
		strings.Contains(s, "tcp connect failed")
}

// tryAuth performs one real dial with the given method. It returns a live
// client on success (caller closes it), nil + ok=false on a tolerated auth
// rejection, skips the whole subtest on an unreachable host, and fails the
// test on any other (unexpected, protocol-level) error. On success it
// asserts ObservedAuth reports the method that authenticated — the exact
// value the connprofile memo records (spec AC-04).
func tryAuth(t *testing.T, ctx context.Context, h liveHost, method, wantObserved string, cred *credential.Credential, store KnownHostsStore) (*cryptossh.Client, bool) {
	t.Helper()
	var observed string
	client, err := Dial(ctx, h.addr, 22, cred, DialOptions{
		Mode:         ModeTOFU,
		Store:        store,
		Timeout:      DefaultDialTimeout,
		ObservedAuth: &observed,
	})
	if err != nil {
		switch {
		case isUnreachable(err):
			t.Skipf("%s (%s) unreachable: %v", h.name, h.addr, err)
		case isAuthRejection(err):
			t.Logf("%s: %s auth not accepted by host (config): %v", h.name, method, err)
			return nil, false
		default:
			t.Fatalf("%s: %s dial failed with an unexpected (non-auth) error: %v", h.name, method, err)
		}
	}
	if observed != wantObserved {
		t.Errorf("%s: %s auth ObservedAuth=%q, want %q", h.name, method, observed, wantObserved)
	}
	return client, true
}

// TestLiveHost_AuthAndSudoMatrix dials every inventory host and validates,
// against the REAL box, the auth + sudo machinery the connprofile learning
// rests on. The fleet is heterogeneous: a host may accept key auth, or
// password auth, or both, and use NOPASSWD or password sudo. The test
// discovers each host's capabilities and asserts the machinery is correct
// for whatever the host supports — it does NOT demand every method on every
// host. A host with no usable auth, or that is unreachable, is skipped.
func TestLiveHost_AuthAndSudoMatrix(t *testing.T) {
	hosts, key := loadLiveHosts(t)

	for _, h := range hosts {
		h := h
		t.Run(h.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// One known-hosts store per host: the first dial records the
			// host key (TOFU); any later dial verifies against it.
			store := NewMemoryStore()

			// --- AC-04: key auth ---
			keyClient, keyOK := tryAuth(t, ctx, h, "key", PreferKey, &credential.Credential{
				Username:   h.user,
				AuthMethod: credential.AuthSSHKey,
				PrivateKey: key,
			}, store)
			if keyClient != nil {
				defer func() { _ = keyClient.Close() }()
			}

			// --- AC-04: password auth (only if the inventory carries one) ---
			var pwClient *cryptossh.Client
			pwOK := false
			if h.password != "" {
				pwClient, pwOK = tryAuth(t, ctx, h, "password", PreferPassword, &credential.Credential{
					Username:   h.user,
					AuthMethod: credential.AuthPassword,
					Password:   h.password,
				}, store)
				if pwClient != nil {
					defer func() { _ = pwClient.Close() }()
				}
			}

			if !keyOK && !pwOK {
				t.Skipf("%s: neither key nor password auth accepted — nothing to exercise", h.name)
			}

			// Run sudo over whichever auth succeeded.
			sudoClient := keyClient
			if sudoClient == nil {
				sudoClient = pwClient
			}
			sess := liveSession{client: sudoClient}
			bothCred := &credential.Credential{
				Username:   h.user,
				AuthMethod: credential.AuthBoth,
				Password:   h.password,
				PrivateKey: key,
			}
			policy := SudoPolicy{AllowCredentialPassword: true}

			// --- AC-10: confirm the host's sudo mode via the `true` sentinel.
			_, code, _, observed, serr := RunSudo(ctx, sess, bothCred, policy, "", "true")
			if serr != nil {
				t.Fatalf("sudo true on %s: transport error: %v", h.name, serr)
			}
			if code != 0 {
				t.Fatalf("sudo true on %s: exit %d (sudo not usable with this credential)", h.name, code)
			}
			if observed != SudoNopasswd && observed != SudoPassword {
				t.Fatalf("sudo mode not confirmed on %s: observed=%q", h.name, observed)
			}
			t.Logf("%s (%s): keyAuth=%v passwordAuth=%v sudo=%s", h.name, h.addr, keyOK, pwOK, observed)

			// --- AC-10: exercise the real `sudo -S` wire path. Leading with
			// SudoPassword forces `sudo -S -k -p '' true` with the password on
			// stdin; a NOPASSWD host still accepts it, so this proves the
			// password-on-stdin path works end to end regardless of mode.
			// Only meaningful when the credential carries a password.
			if h.password != "" {
				_, codeS, usedS, _, sErr := RunSudo(ctx, sess, bothCred, policy, SudoPassword, "true")
				switch {
				case sErr != nil:
					t.Errorf("sudo -S true on %s: %v", h.name, sErr)
				case !usedS:
					t.Errorf("sudo -S true on %s: leading with SudoPassword did not take the sudo -S path", h.name)
				case codeS != 0 && observed == SudoNopasswd:
					t.Errorf("sudo -S true on %s: exit %d on a NOPASSWD host (should accept regardless of password)", h.name, codeS)
				}
			}
		})
	}
}
