// @spec system-ssh-connectivity

package ssh

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/credprotect"
)

func sudoContainerPolicy(c *sshdContainer, nopasswd bool) {
	rule := "ops ALL=(root) PASSWD: ALL"
	if nopasswd {
		rule = "ops ALL=(root) NOPASSWD: ALL"
	}
	c.exec("sh", "-c", "printf '%s\\n' 'Defaults:ops passwd_tries=1,timestamp_type=global' '"+rule+"' > /etc/sudoers.d/openwatch-test && chmod 440 /etc/sudoers.d/openwatch-test && visudo -cf /etc/sudoers.d/openwatch-test") // pragma: allowlist secret (test policy, no password)
}
func sudoContainerClient(t *testing.T, c *sshdContainer) *cryptossh.Client {
	t.Helper()
	client, err := Dial(context.Background(), "127.0.0.1", c.port, activePassword("ops", "P1"), DialOptions{Mode: ModeTOFU})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func sudoRealOptions(f *protectedFixture, cred *credential.Credential, command string, mode ProtectedSudoMode) ProtectedSudoOptions {
	auth := f.opts(cred, credprotect.KindOrdinary)
	return ProtectedSudoOptions{Mode: mode, Auth: auth, Timeout: 15 * time.Second,
		Profile: &ValidatedSudoProfile{HostID: f.hostID, Username: cred.Username, Command: command,
			EvidenceID: "rocky9-sudo-single-try-fixture", ExpiresAt: time.Now().Add(time.Hour), PasswordTries: 1, MaxPAMFailures: 1, InvokingUser: true}}
}

// @ac AC-39
func TestProtectedSudo_ContainerPAMAndRecovery(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-39", func(t *testing.T) {
		c := startSSHD(t)
		c.setPassword("P1")
		sudoContainerPolicy(c, false)
		f := newProtectedFixture(t, "ops")
		p1 := activePassword("ops", "P1")
		const n = 8
		clients := make([]*cryptossh.Client, n)
		for i := range n {
			clients[i] = sudoContainerClient(t, c)
		}
		res, err := ProtectedSudo(context.Background(), clients[0], p1, "", sudoRealOptions(f, p1, "", SudoVerifyPassword))
		if err != nil || res.Attempt.Outcome != credprotect.OutcomeVerified {
			t.Fatalf("verify: outcome=%s err=%v", res.Attempt.Outcome, err)
		}
		if c.failures() != 0 {
			t.Fatal("correct password added a failure")
		}
		c.setPassword("P2")
		var wg sync.WaitGroup
		results := make([]SudoResult, n)
		errs := make([]error, n)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = ProtectedSudo(context.Background(), clients[i], p1, "true", sudoRealOptions(f, p1, "true", SudoPasswordOnly))
			}()
		}
		close(start)
		wg.Wait()
		submitted := 0
		for i, r := range results {
			if r.Submitted {
				submitted++
				if r.Attempt.Outcome != credprotect.OutcomeUnsuccessful {
					t.Errorf("outcome=%s", r.Attempt.Outcome)
				}
			}
			if errs[i] == nil {
				t.Error("stale password accepted")
			}
		}
		if submitted != 1 || c.failures() != 1 || f.mode(t, "P1") != credprotect.ModeBlocked {
			t.Fatalf("submissions=%d failures=%d mode=%s", submitted, c.failures(), f.mode(t, "P1"))
		}
		for range 5 {
			_, err := ProtectedSudo(context.Background(), clients[0], p1, "true", sudoRealOptions(f, p1, "true", SudoPasswordOnly))
			if !errors.Is(err, ErrProtected) {
				t.Fatalf("later attempt: %v", err)
			}
		}
		if c.failures() != 1 {
			t.Fatal("later attempts reached PAM")
		}
		p2 := activePassword("ops", "P2")
		res, err = ProtectedSudo(context.Background(), clients[0], p2, "", sudoRealOptions(f, p2, "", SudoVerifyPassword))
		if err != nil || res.Attempt.Outcome != credprotect.OutcomeVerified || f.mode(t, "P2") != credprotect.ModeActive {
			t.Fatalf("new password: outcome=%s err=%v", res.Attempt.Outcome, err)
		}
	})
}

// @ac AC-40
func TestProtectedSudo_ContainerCacheAndExecution(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-40", func(t *testing.T) {
		t.Run("NOPASSWD does not verify", func(t *testing.T) {
			c := startSSHD(t)
			c.setPassword("P1")
			sudoContainerPolicy(c, true)
			client := sudoContainerClient(t, c)
			f := newProtectedFixture(t, "ops")
			wrong := activePassword("ops", "not-the-password")
			res, err := ProtectedSudo(context.Background(), client, wrong, "", sudoRealOptions(f, wrong, "", SudoVerifyPassword))
			if err != nil || res.Submitted || res.PromptSeen || res.Attempt.Outcome != credprotect.OutcomeNotSubmitted {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			if c.failures() != 0 || f.mode(t, wrong.Password) != credprotect.ModeVerifying {
				t.Fatal("NOPASSWD was treated as verification")
			}
			// A command's error text must never cause a second execution.
			command := `n=$(cat /tmp/ow-counter 2>/dev/null || echo 0); echo $((n+1)) >/tmp/ow-counter; printf 'a password is required\n' >&2; exit 1`
			res, err = ProtectedSudo(context.Background(), client, wrong, command, sudoRealOptions(f, wrong, command, SudoReadOnlyFallback))
			if err == nil || !res.CommandStarted || res.Attempt.Reserved || strings.TrimSpace(c.exec("cat", "/tmp/ow-counter")) != "1" {
				t.Fatalf("replayed command: res=%+v err=%v", res, err)
			}
			command = `printf '%s' "a'b"`
			res, err = ProtectedSudo(context.Background(), client, nil, command, ProtectedSudoOptions{Mode: SudoCachedOnly})
			if err != nil || string(res.Stdout) != "a'b" {
				t.Fatalf("quoting: out=%q err=%v", res.Stdout, err)
			}
		})
		t.Run("cache is not fresh verification", func(t *testing.T) {
			c := startSSHD(t)
			c.setPassword("P1")
			sudoContainerPolicy(c, false)
			client := sudoContainerClient(t, c)
			f := newProtectedFixture(t, "ops")
			// Prime a timestamp only in this synthetic fixture, through stdin.
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			session.Stdin = strings.NewReader("P1\n")
			session.Stdout = io.Discard
			session.Stderr = io.Discard
			err = session.Run("sudo -S -p fixture: -v")
			_ = session.Close()
			if err != nil {
				t.Fatal(err)
			}
			wrong := activePassword("ops", "not-the-password")
			res, err := ProtectedSudo(context.Background(), client, wrong, "true", ProtectedSudoOptions{Mode: SudoCachedOnly})
			if err != nil || !res.CommandStarted || res.Submitted {
				t.Fatalf("cache: res=%+v err=%v", res, err)
			}
			res, err = ProtectedSudo(context.Background(), client, wrong, "", sudoRealOptions(f, wrong, "", SudoVerifyPassword))
			if err == nil || !res.PromptSeen || !res.Submitted || res.Attempt.Outcome != credprotect.OutcomeUnsuccessful || c.failures() != 1 {
				t.Fatalf("fresh: outcome=%s tally=%d err=%v", res.Attempt.Outcome, c.failures(), err)
			}
		})
		t.Run("correct password with account policy denial", func(t *testing.T) {
			c := startSSHD(t)
			c.setPassword("P1")
			sudoContainerPolicy(c, false)
			client := sudoContainerClient(t, c)
			f := newProtectedFixture(t, "ops")
			p1 := activePassword("ops", "P1")
			c.exec("sh", "-c", "printf '\\naccount requisite pam_deny.so\\n' >> /etc/pam.d/sudo")
			res, err := ProtectedSudo(context.Background(), client, p1, "", sudoRealOptions(f, p1, "", SudoVerifyPassword))
			if err == nil || !res.PromptSeen || !res.Submitted || res.Attempt.Outcome != credprotect.OutcomeUnsuccessful {
				t.Fatalf("policy denial: outcome=%s submitted=%v prompt=%v err=%v", res.Attempt.Outcome, res.Submitted, res.PromptSeen, err)
			}
			if c.failures() != 0 {
				t.Fatal("the correct password was not an authentication rejection")
			}
		})
		t.Run("unknown policy is refused before PAM", func(t *testing.T) {
			c := startSSHD(t)
			c.setPassword("P1")
			c.exec("sh", "-c", "printf '%s\\n' 'ops ALL=(root) PASSWD: ALL' > /etc/sudoers.d/openwatch-test && chmod 440 /etc/sudoers.d/openwatch-test")
			client := sudoContainerClient(t, c)
			f := newProtectedFixture(t, "ops")
			wrong := activePassword("ops", "not-the-password")
			o := sudoRealOptions(f, wrong, "", SudoVerifyPassword)
			o.Profile = nil
			res, err := ProtectedSudo(context.Background(), client, wrong, "", o)
			if !errors.Is(err, ErrSudoProfile) || res.Attempt.Reserved || c.failures() != 0 {
				t.Fatalf("unknown profile: err=%v tally=%d", err, c.failures())
			}
		})
	})
}
