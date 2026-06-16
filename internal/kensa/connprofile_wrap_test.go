// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-05  TestWrap_BySudoMode
//	AC-07  TestSudoPasswordFor_GatedByPolicyAndAuthMethod

package kensa

import (
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/connprofile"
	"github.com/Hanalyx/openwatch/internal/credential"
)

// @ac AC-07
// AC-07: the scan's sudo password is gated by the SAME two conditions the
// collector/liveness/discovery paths enforce — the AllowCredentialSudoPassword
// kill-switch AND the credential auth method (password|both). When either
// fails the transport gets no sudo password, so it never attempts sudo -S.
func TestSudoPasswordFor_GatedByPolicyAndAuthMethod(t *testing.T) {
	t.Run("system-connection-profile/AC-07", func(t *testing.T) {
		pwBoth := &credential.Credential{AuthMethod: credential.AuthBoth, Password: "pw"}
		pwOnly := &credential.Credential{AuthMethod: credential.AuthPassword, Password: "pw"}
		keyOnly := &credential.Credential{AuthMethod: credential.AuthSSHKey, Password: ""}
		// A key credential that somehow carries a password must still be gated out.
		keyWithPw := &credential.Credential{AuthMethod: credential.AuthSSHKey, Password: "pw"}

		cases := []struct {
			name    string
			cred    *credential.Credential
			allowed bool
			want    string
		}{
			{"kill-switch off blocks password+both", pwBoth, false, ""},
			{"kill-switch off blocks password-only", pwOnly, false, ""},
			{"allowed + both -> password", pwBoth, true, "pw"},
			{"allowed + password -> password", pwOnly, true, "pw"},
			{"allowed + ssh_key (no password) -> empty", keyOnly, true, ""},
			{"allowed + ssh_key carrying a password -> empty (auth-method gate)", keyWithPw, true, ""},
			{"nil credential -> empty", nil, true, ""},
		}
		for _, c := range cases {
			if got := sudoPasswordFor(c.cred, c.allowed); got != c.want {
				t.Errorf("%s: sudoPasswordFor = %q, want %q", c.name, got, c.want)
			}
		}
	})
}

// @ac AC-05
// AC-05: the scan transport wraps a command per the connection's learned
// sudo mode — no sudo verbatim, NOPASSWD via `sudo -n sh -c`, and password
// via `sudo -S -p ” sh -c` with the credential password on stdin (never
// in the command line / argv).
func TestWrap_BySudoMode(t *testing.T) {
	t.Run("system-connection-profile/AC-05", func(t *testing.T) {
		// no sudo -> verbatim, no stdin.
		if line, stdin := (&sshTransport{sudo: false}).wrap("id"); line != "id" || stdin != nil {
			t.Errorf("no-sudo wrap = %q (stdin=%v)", line, stdin)
		}
		// NOPASSWD -> sudo -n, no stdin.
		if line, stdin := (&sshTransport{sudo: true, mode: connprofile.SudoNopasswd}).wrap("id"); line != `sudo -n sh -c 'id'` || stdin != nil {
			t.Errorf("nopasswd wrap = %q (stdin=%v)", line, stdin)
		}
		// password -> sudo -S -p '' with the password on stdin, never argv.
		pw := &sshTransport{sudo: true, mode: connprofile.SudoPassword, password: "p@ss"}
		line, stdin := pw.wrap("id")
		if line != `sudo -S -p '' sh -c 'id'` {
			t.Errorf("password wrap = %q", line)
		}
		if string(stdin) != "p@ss\n" {
			t.Errorf("stdin = %q, want password+newline", stdin)
		}
		if strings.Contains(line, "p@ss") {
			t.Error("password must not appear in the command line")
		}
		// unknown mode degrades to sudo -n (historical behaviour).
		if line, _ := (&sshTransport{sudo: true, mode: connprofile.SudoUnknown}).wrap("id"); line != `sudo -n sh -c 'id'` {
			t.Errorf("unknown-mode wrap = %q, want sudo -n", line)
		}
	})
}
