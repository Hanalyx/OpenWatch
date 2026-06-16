// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-05  TestWrap_BySudoMode

package kensa

import (
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/connprofile"
)

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
