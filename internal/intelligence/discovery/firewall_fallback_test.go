// @spec system-ssh-connectivity
//
// AC traceability (this file):
//
//   AC-20  TestProbeFirewall_PasswordFallback_UFWSuccess
//          TestProbeFirewall_PasswordFallback_PolicyOff
//   AC-21  TestProbeFirewall_NoFallbackOnSudoNSuccess
//
// system-host-discovery AC-05 (v1.2.0 sudo-S retry before partial-success)
// is covered indirectly: these tests exercise the same probeFirewall
// helper the host-discovery flow calls into.

package discovery

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// validHostCred builds a credential that satisfies the password-fallback
// preconditions (AuthMethod ∈ {password, both} with a non-empty Password).
func validHostCred() *credential.Credential {
	return &credential.Credential{
		Username:   "owadmin",
		AuthMethod: credential.AuthBoth,
		Password:   "secret-pw",
	}
}

// @ac AC-20
// AC-20 (success): sudo -n ufw status fails → policy on + cred has
// password → probeFirewall retries via sudo -S -k -p ” ufw status with
// the password fed via stdin → returns service="ufw", status="active".
func TestProbeFirewall_PasswordFallback_UFWSuccess(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-20", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		// First firewall attempt (systemctl is-active firewalld) returns
		// 127 from the SeedAll default — not present on this Ubuntu host.
		// Then sudo -n ufw status fails; the fallback sudo -S -k -p ''
		// ufw status succeeds.
		stub.FailCommand("sudo -n ufw status", "a password is required", 1)
		stub.outputs["sudo -S -k -p '' ufw status"] = stubResult{
			out:      []byte("Status: active\n"),
			exitCode: 0,
		}

		sess, err := stub.Dial(testCtx(t), "host", 22, validHostCred())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}

		cfg := sudoFallbackConfig{
			policy: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true},
			cred:   validHostCred(),
		}
		svc, status, learned, ok, _ := probeFirewall(testCtx(t), sess, cfg)
		if !ok {
			t.Fatalf("ok: want true (fallback succeeded), got false")
		}
		if svc != "ufw" {
			t.Errorf("service: want ufw, got %q", svc)
		}
		if status != "active" {
			t.Errorf("status: want active, got %q", status)
		}
		// The sudo -S fallback confirmed password sudo — learned mode.
		if learned != connprofile.SudoPassword {
			t.Errorf("learned sudo mode: want %q, got %q", connprofile.SudoPassword, learned)
		}
		// The fallback call MUST have been issued through RunWithStdin
		// with the credential password on stdin.
		if got := len(stub.stdinCalls); got == 0 {
			t.Fatal("no RunWithStdin calls recorded — fallback did not engage")
		}
		found := false
		for _, c := range stub.stdinCalls {
			if c.cmd == "sudo -S -k -p '' ufw status" && string(c.stdin) == "secret-pw\n" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected RunWithStdin(sudo -S -k -p '' ufw status, %q\\n), recorded calls: %+v",
				"secret-pw", stub.stdinCalls)
		}
	})
}

// @ac AC-20
// AC-20 (policy off): same stub setup but AllowCredentialSudoPassword=false.
// The sudo -n exit 1 propagates and probeFirewall falls through to the
// next firewall — ultimately returning ("", "", false) when none are
// programmed to succeed. NO sudo -S -k call is issued.
func TestProbeFirewall_PasswordFallback_PolicyOff(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-20", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		stub.FailCommand("sudo -n ufw status", "a password is required", 1)
		// Seed sudo -S -k success — should NOT be reached.
		stub.outputs["sudo -S -k -p '' ufw status"] = stubResult{out: []byte("Status: active\n"), exitCode: 0}
		stub.FailCommand("sudo -n nft list ruleset", "denied", 1)
		stub.FailCommand("sudo -n iptables -L", "denied", 1)
		stub.FailCommand("sudo -n firewall-cmd --state", "denied", 1)

		sess, _ := stub.Dial(testCtx(t), "host", 22, validHostCred())
		cfg := sudoFallbackConfig{
			policy: systemconfig.SecurityConfig{AllowCredentialSudoPassword: false},
			cred:   validHostCred(),
		}
		_, _, learned, ok, _ := probeFirewall(testCtx(t), sess, cfg)
		if ok {
			t.Errorf("ok: want false (policy off, no sudo path succeeded), got true")
		}
		// Nothing confirmed sudo (policy off, every form denied).
		if learned != connprofile.SudoUnknown {
			t.Errorf("learned sudo mode: want unknown, got %q", learned)
		}
		if got := len(stub.stdinCalls); got != 0 {
			t.Errorf("RunWithStdin called %d times with policy off; want 0", got)
		}
	})
}

// @ac AC-21
// AC-21 (discovery half): firewalld is already active via systemctl
// (sudoless) → probeFirewall returns immediately. The sudo -S -k path
// MUST NOT execute even with policy + password available.
func TestProbeFirewall_NoFallbackOnSudoNSuccess(t *testing.T) {
	t.Run("system-ssh-connectivity/AC-21", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		stub.outputs["systemctl is-active firewalld"] = stubResult{
			out: []byte("active\n"), exitCode: 0,
		}

		sess, _ := stub.Dial(testCtx(t), "host", 22, validHostCred())
		cfg := sudoFallbackConfig{
			policy: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true},
			cred:   validHostCred(),
		}
		svc, status, learned, ok, _ := probeFirewall(testCtx(t), sess, cfg)
		if !ok || svc != "firewalld" || status != "active" {
			t.Errorf("first-firewall hit: svc=%q status=%q ok=%v", svc, status, ok)
		}
		// Sudoless firewalld hit first — no sudo command ran, so the probe
		// confirms no sudo mode (learning stays with whatever liveness knows).
		if learned != connprofile.SudoUnknown {
			t.Errorf("learned sudo mode: want unknown (sudoless path), got %q", learned)
		}
		// Zero RunWithStdin calls — fallback never engaged.
		if got := len(stub.stdinCalls); got != 0 {
			t.Errorf("RunWithStdin called %d times though sudo -n was not even attempted", got)
		}
	})
}

// @spec system-connection-profile
// @ac AC-11
// AC-11 (discovery sudo): the firewall probe opportunistically reports the
// sudo mode a real sudo command confirms — NOPASSWD here (sudo -n ufw
// status exits 0) — and leads with sudo -S when the host is recorded as
// needing a password.
func TestProbeFirewall_SudoModeLearning(t *testing.T) {
	t.Run("system-connection-profile/AC-11", func(t *testing.T) {
		// NOPASSWD host: firewalld absent, sudo -n ufw status succeeds.
		stub := newStubSSHTransport()
		stub.SeedAll()
		stub.outputs["sudo -n ufw status"] = stubResult{out: []byte("Status: active\n"), exitCode: 0}

		sess, _ := stub.Dial(testCtx(t), "host", 22, validHostCred())
		cfg := sudoFallbackConfig{
			policy: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true},
			cred:   validHostCred(),
		}
		svc, _, learned, ok, _ := probeFirewall(testCtx(t), sess, cfg)
		if !ok || svc != "ufw" {
			t.Fatalf("probe: ok=%v svc=%q, want true/ufw", ok, svc)
		}
		if learned != connprofile.SudoNopasswd {
			t.Errorf("learned: want %q, got %q", connprofile.SudoNopasswd, learned)
		}
		// NOPASSWD confirmed via sudo -n: no password fed to stdin.
		if got := len(stub.stdinCalls); got != 0 {
			t.Errorf("RunWithStdin called %d times on a NOPASSWD host; want 0", got)
		}
	})

	t.Run("known password host leads with sudo -S", func(t *testing.T) {
		stub := newStubSSHTransport()
		stub.SeedAll()
		// Only sudo -S ufw status is seeded; sudo -n is left unseeded (127).
		stub.outputs["sudo -S -k -p '' ufw status"] = stubResult{out: []byte("Status: active\n"), exitCode: 0}

		sess, _ := stub.Dial(testCtx(t), "host", 22, validHostCred())
		cfg := sudoFallbackConfig{
			policy: systemconfig.SecurityConfig{AllowCredentialSudoPassword: true},
			cred:   validHostCred(),
			prefer: connprofile.SudoPassword,
		}
		svc, _, learned, ok, _ := probeFirewall(testCtx(t), sess, cfg)
		if !ok || svc != "ufw" {
			t.Fatalf("probe: ok=%v svc=%q, want true/ufw", ok, svc)
		}
		if learned != connprofile.SudoPassword {
			t.Errorf("learned: want %q, got %q", connprofile.SudoPassword, learned)
		}
		// Led with sudo -S: the password was fed on the first ufw attempt.
		if len(stub.stdinCalls) == 0 || stub.stdinCalls[0].cmd != "sudo -S -k -p '' ufw status" {
			t.Errorf("did not lead with sudo -S: stdinCalls=%+v", stub.stdinCalls)
		}
	})
}
