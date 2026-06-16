// @spec system-ssh-connectivity
//
// AC traceability (this file):
//
//   AC-11  TestRunSudo_FallbackEngagesWhenAllowed
//   AC-12  TestRunSudo_NoFallbackWhenPolicyDisabled
//   AC-13  TestRunSudo_NoFallbackWhenSshKeyOnly
//   AC-14  TestRunSudo_NopasswdShortCircuits
//   AC-15  TestRunSudo_PasswordOnlyInStdinNeverInArgv
//   AC-17  TestRunSudo_WrongPasswordNoRetry

package ssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/credential"
)

// stubSession captures every call so the tests can assert exactly what
// hit the wire — Run vs RunWithStdin, the cmd string, and the stdin
// payload — without needing a real SSH transport.
type stubSession struct {
	runCalls         []runCall
	stdinCalls       []stdinCall
	nopasswdSucceeds bool
	fallbackOK       bool
	transportErr     error
}

type runCall struct{ cmd string }
type stdinCall struct {
	cmd   string
	stdin []byte
}

func (s *stubSession) Run(ctx context.Context, cmd string) ([]byte, int, error) {
	s.runCalls = append(s.runCalls, runCall{cmd: cmd})
	if s.transportErr != nil {
		return nil, 0, s.transportErr
	}
	if s.nopasswdSucceeds {
		return []byte("nopasswd-output\n"), 0, nil
	}
	return []byte("sudo: a password is required\n"), 1, nil
}

func (s *stubSession) RunWithStdin(ctx context.Context, cmd string, stdin []byte) ([]byte, int, error) {
	s.stdinCalls = append(s.stdinCalls, stdinCall{cmd: cmd, stdin: stdin})
	if s.fallbackOK {
		return []byte("fallback-output\n"), 0, nil
	}
	return []byte("Sorry, try again.\n"), 1, nil
}

// AC-14: NOPASSWD path short-circuits — the fallback never executes
// even when policy + credential would allow it.
// @ac AC-14
func TestRunSudo_NopasswdShortCircuits(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-14", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: true}
		cred := &credential.Credential{
			AuthMethod: credential.AuthBoth,
			Password:   "hunter2", // pragma: allowlist secret
		}
		policy := SudoPolicy{AllowCredentialPassword: true}

		out, code, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 || string(out) != "nopasswd-output\n" {
			t.Errorf("nopasswd path: out=%q code=%d", out, code)
		}
		if used {
			t.Error("usedFallback=true on NOPASSWD path (C-12 violation)")
		}
		if len(sess.runCalls) != 1 || !strings.HasPrefix(sess.runCalls[0].cmd, "sudo -n ") {
			t.Errorf("expected exactly one `sudo -n` call, got %+v", sess.runCalls)
		}
		if len(sess.stdinCalls) != 0 {
			t.Errorf("stdin path executed on NOPASSWD success: %+v", sess.stdinCalls)
		}
	})
}

// AC-11: With AllowCredentialPassword=true + AuthMethod=both + non-empty
// password, a sudo -n failure triggers the sudo -S retry and the call
// succeeds.
// @ac AC-11
func TestRunSudo_FallbackEngagesWhenAllowed(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-11", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: true}
		cred := &credential.Credential{
			AuthMethod: credential.AuthBoth,
			Password:   "p4ssw0rd!", // pragma: allowlist secret
		}
		policy := SudoPolicy{AllowCredentialPassword: true}

		out, code, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 || string(out) != "fallback-output\n" {
			t.Errorf("fallback success: out=%q code=%d", out, code)
		}
		if !used {
			t.Error("usedFallback=false despite fallback path executing")
		}
		// One sudo -n then one sudo -S -k.
		if len(sess.runCalls) != 1 || len(sess.stdinCalls) != 1 {
			t.Fatalf("expected 1 Run + 1 RunWithStdin, got run=%d stdin=%d",
				len(sess.runCalls), len(sess.stdinCalls))
		}
		if !strings.HasPrefix(sess.stdinCalls[0].cmd, "sudo -S -k -p '' ") {
			t.Errorf("fallback cmd missing `sudo -S -k -p ''` prefix: %q", sess.stdinCalls[0].cmd)
		}
		// Password lands on stdin verbatim (with terminating newline).
		want := append([]byte("p4ssw0rd!"), '\n') // pragma: allowlist secret
		if !bytes.Equal(sess.stdinCalls[0].stdin, want) {
			t.Errorf("stdin payload = %q, want %q", sess.stdinCalls[0].stdin, want)
		}
	})
}

// AC-12: Same setup as AC-11 but with AllowCredentialPassword=false.
// The sudo -n failure propagates with no retry.
// @ac AC-12
func TestRunSudo_NoFallbackWhenPolicyDisabled(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-12", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: true}
		cred := &credential.Credential{
			AuthMethod: credential.AuthBoth,
			Password:   "p4ssw0rd!", // pragma: allowlist secret
		}
		policy := SudoPolicy{AllowCredentialPassword: false}

		_, code, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 1 {
			t.Errorf("policy off: exit code = %d, want 1 (sudo -n failed)", code)
		}
		if used {
			t.Error("usedFallback=true despite policy disabled (C-09 violation)")
		}
		if len(sess.stdinCalls) != 0 {
			t.Errorf("stdin path executed despite policy disabled: %+v", sess.stdinCalls)
		}
	})
}

// AC-13: Same setup as AC-11 but with auth_method=ssh_key and empty
// password. No retry — password is unavailable.
// @ac AC-13
func TestRunSudo_NoFallbackWhenSshKeyOnly(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-13", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: true}
		cred := &credential.Credential{
			AuthMethod: credential.AuthSSHKey,
			Password:   "", // ssh_key mode never stores a password
		}
		policy := SudoPolicy{AllowCredentialPassword: true}

		_, _, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if used {
			t.Error("usedFallback=true for ssh_key-only credential (no password to feed)")
		}
		if len(sess.stdinCalls) != 0 {
			t.Errorf("stdin path executed for ssh_key-only credential: %+v", sess.stdinCalls)
		}
	})
}

// AC-17: A wrong password during the fallback retry MUST NOT cause a
// second retry. -k flag in the cmd protects against host-side account
// lockout via pam_tally2 / pam_faillock by clearing the cached creds
// before each attempt.
// @ac AC-17
func TestRunSudo_WrongPasswordNoRetry(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-17", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: false}
		cred := &credential.Credential{
			AuthMethod: credential.AuthBoth,
			Password:   "wrong-password", // pragma: allowlist secret
		}
		policy := SudoPolicy{AllowCredentialPassword: true}

		_, code, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 1 || !used {
			t.Errorf("wrong-pw fallback: code=%d usedFallback=%v, want code=1 used=true", code, used)
		}
		// Exactly ONE sudo -n call and ONE sudo -S -k call. No retry.
		if len(sess.runCalls) != 1 {
			t.Errorf("expected 1 sudo -n call, got %d", len(sess.runCalls))
		}
		if len(sess.stdinCalls) != 1 {
			t.Errorf("expected 1 sudo -S -k call (no retry), got %d", len(sess.stdinCalls))
		}
		// AC-17: the -k flag MUST be present in the fallback cmd.
		if !strings.Contains(sess.stdinCalls[0].cmd, "-k") {
			t.Errorf("fallback cmd missing -k flag (lockout protection): %q", sess.stdinCalls[0].cmd)
		}
	})
}

// AC-15: source-inspection — the password MUST be passed via stdin,
// never via fmt.Sprintf into the cmd string. We assert directly on
// the source of sudo.go.
// @ac AC-15
func TestRunSudo_PasswordOnlyInStdinNeverInArgv(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-15", func(t *testing.T) {
		_, thisFile, _, _ := runtime.Caller(0)
		src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "sudo.go"))
		if err != nil {
			t.Fatalf("read sudo.go: %v", err)
		}
		s := string(src)
		// Banned: fmt.Sprintf with a "%s" that could place password in cmd.
		if strings.Contains(s, "Sprintf") && strings.Contains(s, "Password") {
			t.Error("sudo.go has fmt.Sprintf near `Password` — possible argv leak (C-10)")
		}
		// Required: the fallback path passes pwIn through RunWithStdin's
		// stdin parameter, not via the cmd string.
		if !strings.Contains(s, "RunWithStdin(ctx, \"sudo -S -k -p '' \"+cmd, pwIn)") {
			t.Error("sudo.go does not feed pwIn through RunWithStdin's stdin slot")
		}
		// The password MUST originate from cred.Password (not a literal).
		if !strings.Contains(s, "cred.Password") {
			t.Error("sudo.go does not source password from cred.Password")
		}
	})
}

// Transport-error pass-through: if Run returns an error, the wrapper
// returns the error without attempting the fallback. Belt-and-suspenders
// safety against a torn SSH session being papered over by sudo -S.
func TestRunSudo_TransportErrorBubblesUp(t *testing.T) {
	sess := &stubSession{transportErr: errors.New("session closed")}
	policy := SudoPolicy{AllowCredentialPassword: true}
	cred := &credential.Credential{AuthMethod: credential.AuthBoth, Password: "x"}
	_, _, used, _, err := RunSudo(context.Background(), sess, cred, policy, "", "ls")
	if err == nil || !strings.Contains(err.Error(), "session closed") {
		t.Errorf("transport error not propagated: err=%v", err)
	}
	if used {
		t.Error("transport error triggered fallback (should bypass)")
	}
}

// @spec system-connection-profile
// @ac AC-10
// AC-10 (collector/discovery half, sudo): RunSudo reports the sudo mode
// observed to work (SudoNopasswd / SudoPassword on a confirmed exit-0,
// "" otherwise), and when told prefer=SudoPassword it leads with sudo -S
// and skips the doomed sudo -n round-trip.
func TestRunSudo_SudoModeLearning(t *testing.T) {
	cred := &credential.Credential{AuthMethod: credential.AuthBoth, Password: "hunter2"} // pragma: allowlist secret
	policy := SudoPolicy{AllowCredentialPassword: true}

	t.Run("system-connection-profile/AC-10", func(t *testing.T) {
		// Known password host: lead with sudo -S, no sudo -n attempt.
		sess := &stubSession{fallbackOK: true}
		_, code, used, observed, err := RunSudo(context.Background(), sess, cred, policy, SudoPassword, "cat /etc/shadow")
		if err != nil || code != 0 {
			t.Fatalf("want success, got code=%d err=%v", code, err)
		}
		if !used {
			t.Error("usedFallback=false; leading with sudo -S should count as fallback")
		}
		if observed != SudoPassword {
			t.Errorf("observed=%q, want %q", observed, SudoPassword)
		}
		if len(sess.runCalls) != 0 {
			t.Errorf("lead-with-password issued %d sudo -n call(s), want 0", len(sess.runCalls))
		}
		if len(sess.stdinCalls) != 1 {
			t.Errorf("want exactly 1 sudo -S call, got %d", len(sess.stdinCalls))
		}
	})

	t.Run("nopasswd observed on default order", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: true}
		_, _, used, observed, _ := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if used {
			t.Error("usedFallback=true on a NOPASSWD host")
		}
		if observed != SudoNopasswd {
			t.Errorf("observed=%q, want %q", observed, SudoNopasswd)
		}
	})

	t.Run("password observed via default-order fallback", func(t *testing.T) {
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: true}
		_, _, _, observed, _ := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if observed != SudoPassword {
			t.Errorf("observed=%q, want %q", observed, SudoPassword)
		}
	})

	t.Run("no observation when neither form confirms", func(t *testing.T) {
		// sudo -n denied, password rejected: nothing definitively worked.
		sess := &stubSession{nopasswdSucceeds: false, fallbackOK: false}
		_, _, _, observed, _ := RunSudo(context.Background(), sess, cred, policy, "", "cat /etc/shadow")
		if observed != "" {
			t.Errorf("observed=%q, want empty (ambiguous)", observed)
		}
	})

	t.Run("stale password hint self-heals to nopasswd", func(t *testing.T) {
		// prefer=password but the host now grants NOPASSWD and rejects the
		// piped password: lead sudo -S (fails), fall back to sudo -n (ok).
		sess := &stubSession{nopasswdSucceeds: true, fallbackOK: false}
		_, code, _, observed, _ := RunSudo(context.Background(), sess, cred, policy, SudoPassword, "cat /etc/shadow")
		if code != 0 || observed != SudoNopasswd {
			t.Errorf("self-heal: code=%d observed=%q, want code=0 observed=%q", code, observed, SudoNopasswd)
		}
	})
}
