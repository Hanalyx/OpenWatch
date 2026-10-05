package packaging_test

// The code-only rollback block in UPGRADE_PROCEDURE.md. It used to reinstall
// the previous packages, run `systemctl start` and read health. The previous
// package's scriptlet has already started the service by then, inside the
// transaction and with the newer rule files still on disk, so `start` is a
// no-op and health answers healthy while the rule library failed to load
// (CP bugs/OW-094, bugs/OW-105 B5). These tests run the block as the Markdown
// states it, with only its inputs filled, against stub systemctl, dnf,
// journalctl, curl and runuser, and check that it restarts after the
// transaction and stops unless the rule library is proven loaded.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const codeOnlyHeading = "### Code-only rollback (the schema did not advance)"

// codeOnlyBlock returns the first bash block under the code-only heading.
func codeOnlyBlock(t *testing.T) string {
	t.Helper()
	doc := readRunbook(t, "UPGRADE_PROCEDURE.md")
	i := strings.Index(doc, "\n"+codeOnlyHeading+"\n")
	if i < 0 {
		t.Fatalf("UPGRADE_PROCEDURE.md has no heading %q", codeOnlyHeading)
	}
	rest := doc[i:]
	if next := strings.Index(rest[1:], "\n### "); next >= 0 {
		rest = rest[:next+1]
	}
	open := strings.Index(rest, "\n```bash\n")
	if open < 0 {
		t.Fatalf("no bash block under %q", codeOnlyHeading)
	}
	body := rest[open+len("\n```bash\n"):]
	end := strings.Index(body, "\n```\n")
	if end < 0 {
		t.Fatalf("unterminated bash block under %q", codeOnlyHeading)
	}
	return body[:end+1]
}

// TestUpgrade_CodeOnlyRollbackBlockIsGuarded is the always-on structural guard.
func TestUpgrade_CodeOnlyRollbackBlockIsGuarded(t *testing.T) {
	b := codeOnlyBlock(t)
	if strings.Contains(b, "systemctl start") {
		t.Error("the code-only rollback starts the service; the scriptlet already did, so start proves nothing (OW-094)")
	}
	inOrder(t, "code-only", b,
		"set -euo pipefail", "EXPECTED=", "OLD_OPENWATCH=", "OLD_KENSA=", "TOKEN_FILE=", "PHASE=inputs",
		"trap 'on_stop $LINENO' ERR", `[ "$GOT" != "$EXPECTED" ]`,
		"PHASE=packages", `dnf install -y "$OLD_OPENWATCH" "$OLD_KENSA"`,
		"PHASE=verify", "systemctl restart openwatch", `[ "$READY" = yes ]`,
		`[[ "$LOG" != *"kensa scan wiring unavailable"* ]]`, `[[ "$LOG" != *"kensa rule library unavailable"* ]]`,
		`[ "$RULES" = 200 ]`, "trap - ERR", `echo "ROLLED BACK (code only)`)
	if strings.Count(b, "ROLLED BACK") != 1 {
		t.Errorf("the block prints ROLLED BACK %d times, want once", strings.Count(b, "ROLLED BACK"))
	}
}

type codeOnlyRun struct {
	exit   int
	stdout string
	stderr string
	calls  string
}

// runCodeOnly runs the filled block with stub tools on PATH. env tunes the
// stubs: OW_SCHEMA (what runuser psql prints), DNF_EXIT, JOURNAL (journal
// text), RULES_CODE (status for /api/v1/rules).
func runCodeOnly(t *testing.T, block string, env map[string]string) codeOnlyRun {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	stubs := map[string]string{
		"runuser":    `echo "runuser $*" >> "$CALLS"; echo "${OW_SCHEMA:-65}"`,
		"dnf":        `echo "dnf $*" >> "$CALLS"; exit "${DNF_EXIT:-0}"`,
		"apt-get":    `echo "apt-get $*" >> "$CALLS"; exit 0`,
		"systemctl":  `echo "systemctl $*" >> "$CALLS"; exit 0`,
		"journalctl": `echo "journalctl $*" >> "$CALLS"; printf '%s' "${JOURNAL:-}"`,
		"curl": `cat >/dev/null 2>&1 || true
for a in "$@"; do case "$a" in
  */api/v1/health) echo "curl health" >> "$CALLS"; exit 0 ;;
  */api/v1/rules) echo "curl rules" >> "$CALLS"; printf '%s' "${RULES_CODE:-200}"; exit 0 ;;
esac; done
exit 7`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", block)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CALLS="+calls)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(calls)
	return codeOnlyRun{exit: code, stdout: out.String(), stderr: errb.String(), calls: string(c)}
}

func TestUpgrade_CodeOnlyRollbackBlockBehaves(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	ow := filepath.Join(dir, "openwatch-0.8.1-1.x86_64.rpm")
	kr := filepath.Join(dir, "kensa-rules-0.10.0-1.noarch.rpm")
	tok := filepath.Join(dir, "token")
	for p, v := range map[string]string{ow: "rpm", kr: "rpm", tok: "owk_code_only_test_token"} {
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fill := func(expected string) string {
		b := codeOnlyBlock(t)
		b = setInput(t, b, "EXPECTED", "'"+expected+"'")
		b = setInput(t, b, "OLD_OPENWATCH", "'"+ow+"'")
		b = setInput(t, b, "OLD_KENSA", "'"+kr+"'")
		b = setInput(t, b, "TOKEN_FILE", "'"+tok+"'")
		return b
	}
	lastSystemctl := func(calls string) string {
		last := ""
		for _, l := range strings.Split(calls, "\n") {
			if strings.HasPrefix(l, "systemctl ") {
				last = l
			}
		}
		return last
	}

	t.Run("schema unchanged: installs, restarts, proves the rule library", func(t *testing.T) {
		r := runCodeOnly(t, fill("65"), map[string]string{"OW_SCHEMA": "65"})
		if r.exit != 0 || !strings.Contains(r.stdout, "ROLLED BACK (code only): schema 65 unchanged") {
			t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.exit, r.stdout, r.stderr)
		}
		inOrder(t, "calls", r.calls, "runuser", "dnf install -y "+ow+" "+kr, "systemctl restart openwatch",
			"curl health", "journalctl -u openwatch", "curl rules")
		if strings.Contains(r.calls, "systemctl start") || strings.Contains(r.calls, "systemctl stop") {
			t.Fatalf("unexpected start or stop on success:\n%s", r.calls)
		}
	})
	t.Run("schema advanced: stops before touching packages or the service", func(t *testing.T) {
		r := runCodeOnly(t, fill("56"), map[string]string{"OW_SCHEMA": "65"})
		if r.exit == 0 || !strings.Contains(r.stderr, "it advanced. Use the full rollback.") ||
			!strings.Contains(r.stderr, "phase: inputs") {
			t.Fatalf("exit %d\nstderr: %s", r.exit, r.stderr)
		}
		if strings.Contains(r.calls, "dnf") || strings.Contains(r.calls, "systemctl") {
			t.Fatalf("an advanced schema still reached packages or the service:\n%s", r.calls)
		}
	})
	t.Run("unfilled values: stops before anything", func(t *testing.T) {
		r := runCodeOnly(t, codeOnlyBlock(t), nil)
		if r.exit == 0 || !strings.Contains(r.stderr, "fill in the four values at the top first") || r.calls != "" {
			t.Fatalf("exit %d calls %q\nstderr: %s", r.exit, r.calls, r.stderr)
		}
	})
	for _, c := range []struct {
		name string
		env  map[string]string
	}{
		{"journal says the rule library is unavailable", map[string]string{"JOURNAL": "kensa rule library unavailable: load rule corpus: x.yml"}},
		{"journal says scan wiring is unavailable", map[string]string{"JOURNAL": "kensa scan wiring unavailable"}},
		{"rules endpoint does not answer 200", map[string]string{"RULES_CODE": "503"}},
		{"package installation fails", map[string]string{"DNF_EXIT": "1"}},
	} {
		t.Run(c.name+": stops the service, no success line", func(t *testing.T) {
			env := map[string]string{"OW_SCHEMA": "65"}
			for k, v := range c.env {
				env[k] = v
			}
			r := runCodeOnly(t, fill("65"), env)
			if r.exit == 0 || strings.Contains(r.stdout, "ROLLED BACK") {
				t.Fatalf("exit %d\nstdout: %s", r.exit, r.stdout)
			}
			if !strings.Contains(r.stderr, "Package installation HAD begun") || lastSystemctl(r.calls) != "systemctl stop openwatch" {
				t.Fatalf("a failure after installation began must stop the service\nstderr: %s\ncalls:\n%s", r.stderr, r.calls)
			}
		})
	}
	t.Run("the token never reaches a command line or the output", func(t *testing.T) {
		r := runCodeOnly(t, fill("65"), map[string]string{"OW_SCHEMA": "65"})
		if strings.Contains(r.calls+r.stdout+r.stderr, "owk_code_only_test_token") {
			t.Fatal("the API token appeared in a command line or the output")
		}
	})
}
