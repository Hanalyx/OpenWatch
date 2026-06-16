// @spec system-kensa-executor
//
// Transport adapter tests (v2.2.0 C-15):
//
//	AC-19  TestCommandLine_SudoWrapsAndQuotes
//	AC-20  TestTrimOneTrailingNewline / TestRun_ExitCodeMapping_SourceInspection
//	AC-21  TestPutGet_NotSupported / TestKeyPath_OnlyInComments
package kensa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/connprofile"
)

// @ac AC-19
func TestCommandLine_SudoWrapsAndQuotes(t *testing.T) {
	t.Run("system-kensa-executor/AC-19", func(t *testing.T) {
		// Sudo disabled: pass-through, byte for byte, no stdin.
		noSudo := &sshTransport{sudo: false}
		if line, stdin := noSudo.wrap(`grep -q "^x" /etc/f`); line != `grep -q "^x" /etc/f` || stdin != nil {
			t.Errorf("non-sudo wrap = %q (stdin=%v), want passthrough no-stdin", line, stdin)
		}

		// NOPASSWD mode: sudo -n sh -c wrapping, no stdin.
		nopasswd := &sshTransport{sudo: true, mode: connprofile.SudoNopasswd}
		if line, stdin := nopasswd.wrap("systemctl is-active sshd"); line != `sudo -n sh -c 'systemctl is-active sshd'` || stdin != nil {
			t.Errorf("nopasswd wrap = %q (stdin=%v)", line, stdin)
		}
		// Embedded single quotes survive via the '\'' idiom.
		if line, _ := nopasswd.wrap(`echo it's`); line != `sudo -n sh -c 'echo it'\''s'` {
			t.Errorf("quote escape = %q", line)
		}

		// Password mode: sudo -S -p '' sh -c wrapping, password (newline
		// terminated) on stdin, never in the command line.
		pw := &sshTransport{sudo: true, mode: connprofile.SudoPassword, password: "s3cr3t"}
		line, stdin := pw.wrap("cat /etc/shadow")
		if line != `sudo -S -p '' sh -c 'cat /etc/shadow'` {
			t.Errorf("password wrap line = %q", line)
		}
		if string(stdin) != "s3cr3t\n" {
			t.Errorf("password stdin = %q, want %q", stdin, "s3cr3t\n")
		}
		if strings.Contains(line, "s3cr3t") {
			t.Error("password leaked into the command line")
		}
	})
}

// @ac AC-20
func TestTrimOneTrailingNewline(t *testing.T) {
	t.Run("system-kensa-executor/AC-20", func(t *testing.T) {
		cases := []struct{ in, want string }{
			{"enabled\n", "enabled"},
			{"enabled\r\n", "enabled"},
			{"enabled", "enabled"},
			// Exactly ONE trailing newline is removed — interior and
			// double-trailing newlines are content.
			{"a\nb\n", "a\nb"},
			{"a\n\n", "a\n"},
			{"", ""},
		}
		for _, c := range cases {
			if got := trimOneTrailingNewline(c.in); got != c.want {
				t.Errorf("trim(%q) = %q, want %q", c.in, got, c.want)
			}
		}
	})
}

// @ac AC-20
// Exit-code semantics can't be unit-tested without a live SSH peer
// (cryptossh.ExitError is not constructible outside x/crypto), so the
// mapping is pinned by source inspection: Run must convert
// *ssh.ExitError into CommandResult.ExitCode and return nil error.
func TestRun_ExitCodeMapping_SourceInspection(t *testing.T) {
	t.Run("system-kensa-executor/AC-20", func(t *testing.T) {
		src := mustReadFile(t, filepath.Join(pkgDir(t), "transport.go"))
		for _, needle := range []string{
			"errors.As(werr, &exitErr)",
			"res.ExitCode = exitErr.ExitStatus()",
			"return res, nil",
		} {
			if !strings.Contains(src, needle) {
				t.Errorf("transport.go missing %q — non-zero exit must map to CommandResult.ExitCode, not a Go error (AC-20)", needle)
			}
		}
	})
}

// @ac AC-21
func TestPutGet_NotSupported(t *testing.T) {
	t.Run("system-kensa-executor/AC-21", func(t *testing.T) {
		tr := &sshTransport{} // Put/Get never touch the client
		if err := tr.Put(context.Background(), "/tmp/l", "/tmp/r", 0o644); !errors.Is(err, ErrTransportOpNotSupported) {
			t.Errorf("Put error = %v, want ErrTransportOpNotSupported", err)
		}
		if err := tr.Get(context.Background(), "/tmp/r", "/tmp/l"); !errors.Is(err, ErrTransportOpNotSupported) {
			t.Errorf("Get error = %v, want ErrTransportOpNotSupported", err)
		}
		if tr.ControlChannelSensitive() {
			t.Error("ControlChannelSensitive() = true; scan transport must report false")
		}
	})
}

// @ac AC-21
// HostConfig.KeyPath must never be consulted: the in-memory credential
// is the only auth source. The string "KeyPath" may appear in
// internal/kensa only inside comments explaining why it is ignored.
func TestKeyPath_OnlyInComments(t *testing.T) {
	t.Run("system-kensa-executor/AC-21", func(t *testing.T) {
		entries, err := os.ReadDir(pkgDir(t))
		if err != nil {
			t.Fatalf("read pkg dir: %v", err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src := mustReadFile(t, filepath.Join(pkgDir(t), name))
			for i, line := range strings.Split(src, "\n") {
				if !strings.Contains(line, "KeyPath") {
					continue
				}
				if !strings.HasPrefix(strings.TrimSpace(line), "//") {
					t.Errorf("%s:%d references KeyPath outside a comment: %s", name, i+1, strings.TrimSpace(line))
				}
			}
		}
	})
}

// pkgDir returns the directory of this package's source files.
func pkgDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}
