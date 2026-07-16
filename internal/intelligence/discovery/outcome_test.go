// @spec system-host-discovery
//
// AC traceability (this file):
//
//	AC-26  TestClassifyOutcome_AndSudoDenied
//	AC-28  TestProbeFirewall_ReasonOnNonObservation

package discovery

import (
	"context"
	"errors"
	"testing"
)

// @ac AC-26
// AC-26: classifyOutcome maps a probe's (out, err) to a non-observed reason —
// deadline→timeout, other error→failed, sudo signature→denied, non-zero exit
// without a signature→failed; sudoDenied is a case-insensitive substring match.
func TestClassifyOutcome_AndSudoDenied(t *testing.T) {
	t.Run("system-host-discovery/AC-26", func(t *testing.T) {
		cases := []struct {
			name string
			out  string
			err  error
			want string
		}{
			{"deadline is timeout", "partial", context.DeadlineExceeded, outcomeTimeout},
			{"wrapped deadline is timeout", "x", errWrap(context.DeadlineExceeded), outcomeTimeout},
			{"transport error is failed", "x", errors.New("ssh: connection lost"), outcomeFailed},
			{"sudo password signature is denied", "sudo: a password is required", nil, outcomeDenied},
			{"sudoers signature is denied", "owadmin is not in the sudoers file", nil, outcomeDenied},
			{"not-allowed signature is denied", "user is not allowed to execute", nil, outcomeDenied},
			{"command-not-found is failed", "bash: getenforce: command not found", nil, outcomeFailed},
			{"empty non-zero is failed", "", nil, outcomeFailed},
		}
		for _, c := range cases {
			if got := classifyOutcome([]byte(c.out), c.err); got != c.want {
				t.Errorf("%s: classifyOutcome(%q, %v) = %q, want %q", c.name, c.out, c.err, got, c.want)
			}
		}

		// sudoDenied is case-insensitive and does not false-positive on benign
		// output.
		if !sudoDenied([]byte("SUDO: A PASSWORD IS REQUIRED")) {
			t.Error("sudoDenied should match case-insensitively")
		}
		if sudoDenied([]byte("Status: active")) {
			t.Error("sudoDenied should not match benign firewall output")
		}
	})
}

// errWrap wraps err so errors.Is still finds it — proves classifyOutcome uses
// errors.Is, not ==.
func errWrap(err error) error { return errWrapped{err} }

type errWrapped struct{ err error }

func (e errWrapped) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrapped) Unwrap() error { return e.err }

// @ac AC-28
// AC-28: probeFirewall reports WHY it found no firewall — "denied" when any
// attempt shows a sudo-refusal signature, "failed" when the attempts fail
// without one, and an empty reason on success.
func TestProbeFirewall_ReasonOnNonObservation(t *testing.T) {
	t.Run("system-host-discovery/AC-28", func(t *testing.T) {
		cred := validHostCred()

		// Denied: systemctl absent (127), sudo -n ufw status refused with a
		// password-required signature. Policy off → no sudo -S fallback.
		denyStub := newStubSSHTransport()
		denyStub.SeedAll()
		denyStub.FailCommand("sudo -n ufw status", "sudo: a password is required", 1)
		denySess, _ := denyStub.Dial(testCtx(t), "host", 22, cred)
		_, _, _, ok, reason := probeFirewall(testCtx(t), denySess, sudoFallbackConfig{cred: cred})
		if ok {
			t.Fatalf("denied case: ok=true, want false")
		}
		if reason != outcomeDenied {
			t.Errorf("denied case: reason=%q, want %q", reason, outcomeDenied)
		}

		// Failed: no firewall tool present, every attempt returns 127 with no
		// sudo signature → reason "failed", not a false "denied".
		failStub := newStubSSHTransport()
		failStub.SeedAll() // firewall left unseeded → 127, nil output
		failSess, _ := failStub.Dial(testCtx(t), "host", 22, cred)
		_, _, _, ok, reason = probeFirewall(testCtx(t), failSess, sudoFallbackConfig{cred: cred})
		if ok {
			t.Fatalf("failed case: ok=true, want false")
		}
		if reason != outcomeFailed {
			t.Errorf("failed case: reason=%q, want %q", reason, outcomeFailed)
		}

		// Success: firewalld active via sudoless systemctl → empty reason.
		okStub := newStubSSHTransport()
		okStub.SeedAll()
		okStub.outputs["systemctl is-active firewalld"] = stubResult{out: []byte("active\n"), exitCode: 0}
		okSess, _ := okStub.Dial(testCtx(t), "host", 22, cred)
		_, _, _, ok, reason = probeFirewall(testCtx(t), okSess, sudoFallbackConfig{cred: cred})
		if !ok {
			t.Fatalf("success case: ok=false, want true")
		}
		if reason != "" {
			t.Errorf("success case: reason=%q, want empty", reason)
		}
	})
}
