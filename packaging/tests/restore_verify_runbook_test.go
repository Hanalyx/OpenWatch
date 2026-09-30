// Restore verification in BACKUP_RECOVERY.md. A 200 from /api/v1/health does
// not prove OpenWatch works: when the Kensa rule library fails to load, the
// service starts, health answers healthy, and every scan fails (CP
// bugs/OW-094). The runbook's "Prove the restored service works" section
// therefore has two fail-fast blocks, one that proves the rule library loaded
// and one that runs a scan end to end. These tests run the blocks as the
// Markdown states them, byte for byte apart from their input lines, against a
// local TLS server with the real curl, and stubbed systemctl and journalctl.
package packaging_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	restoreVerifyHeading = "#### Check that the rule library loaded"
	restoreScanHeading   = "#### Run one scan end to end"
)

// restoreBlock returns the first ```bash block after heading in
// BACKUP_RECOVERY.md, without its fences.
func restoreBlock(t *testing.T, heading string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForLinks(t), "docs", "runbooks", "BACKUP_RECOVERY.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		t.Fatalf("BACKUP_RECOVERY.md has no heading %q", heading)
	}
	rest := doc[i:]
	open := strings.Index(rest, "\n```bash\n")
	if open < 0 {
		t.Fatalf("no bash block after %q", heading)
	}
	body := rest[open+len("\n```bash\n"):]
	end := strings.Index(body, "\n```\n")
	if end < 0 {
		t.Fatalf("unterminated bash block after %q", heading)
	}
	return body[:end+1]
}

// setInput replaces the one line that assigns name, keeping its indentation.
func setInput(t *testing.T, block, name, value string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^(\s*)` + regexp.QuoteMeta(name) + `=.*$`)
	if n := len(re.FindAllStringIndex(block, -1)); n != 1 {
		t.Fatalf("block assigns %s %d times, want 1", name, n)
	}
	return re.ReplaceAllString(block, "${1}"+name+"="+value)
}

// orderedAfter asserts each needle appears, in order, and returns the offset
// after the last one.
func orderedAfter(t *testing.T, block string, needles ...string) {
	t.Helper()
	at := 0
	for _, n := range needles {
		i := strings.Index(block[at:], n)
		if i < 0 {
			t.Fatalf("block is missing %q after offset %d, or has it out of order", n, at)
		}
		at += i + len(n)
	}
}

// TestRunbook_RestoreVerifyBlocksAreGuarded is the always-on structural guard:
// no success line without every check before it, and no curl without both
// timeouts.
func TestRunbook_RestoreVerifyBlocksAreGuarded(t *testing.T) {
	verify := restoreBlock(t, restoreVerifyHeading)
	scan := restoreBlock(t, restoreScanHeading)

	orderedAfter(t, verify,
		"set -euo pipefail",
		"TOKEN_FILE=",
		"trap '",
		"[[ \"$TOKEN\" == owk_* ]]",
		"systemctl restart openwatch",
		"$URL/api/v1/health",
		"[ \"$READY\" = yes ]",
		"journalctl -u openwatch --since \"$SINCE\"",
		`*"kensa scan wiring unavailable"*`,
		`*"kensa rule library unavailable"*`,
		"$URL/api/v1/rules",
		"[ \"$RULES\" = 200 ]",
		"trap - ERR",
		"echo \"VERIFIED:",
	)
	if strings.Count(verify, "echo \"VERIFIED:") != 1 {
		t.Fatal("the verify block must print VERIFIED exactly once")
	}
	orderedAfter(t, scan,
		"set -euo pipefail",
		"SCAN_TOKEN_FILE=",
		"trap '",
		"[[ \"$TOKEN\" == owk_* ]]",
		"Idempotency-Key: $KEY",
		"$URL/api/v1/hosts/$HOST_ID/scans",
		"[ \"$CODE\" = 202 ]",
		"$URL/api/v1/scans/$SCAN_ID",
		"[ \"$STATE\" = \"completed 0\" ]",
		"trap - ERR",
		"echo \"SCANNED:",
	)
	for name, b := range map[string]string{"verify": verify, "scan": scan} {
		for _, line := range strings.Split(b, "\n") {
			if !strings.Contains(line, "curl ") {
				continue
			}
			if !strings.Contains(line, "--connect-timeout") || !strings.Contains(line, "--max-time") {
				t.Errorf("%s block: curl without both timeouts: %s", name, strings.TrimSpace(line))
			}
			if strings.Contains(line, "Bearer") && !strings.Contains(line, "-K -") {
				t.Errorf("%s block: token passed on the command line: %s", name, strings.TrimSpace(line))
			}
		}
		if regexp.MustCompile(`echo[^\n]*\$TOKEN`).MatchString(b) {
			t.Errorf("%s block echoes the token", name)
		}
	}
}

// hang holds a request open until the client gives up, so a curl timeout is
// what ends it, and the test server can close without waiting.
func hang(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(60 * time.Second):
	}
}

// fakeOpenWatch is the local stand-in for the service.
type fakeOpenWatch struct {
	mu          sync.Mutex
	token       string
	health      string // "ok", "503", "hang"
	rules       string // "ok", "503", "hang"
	scanPost    int
	scanStates  []string // successive status values; the last repeats
	rulesError  int
	polls       int
	sawIdemKey  bool
	sawBadToken bool
}

func (f *fakeOpenWatch) authorized(r *http.Request) bool {
	ok := r.Header.Get("Authorization") == "Bearer "+f.token
	if !ok {
		f.sawBadToken = true
	}
	return ok
}

func (f *fakeOpenWatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v1/health":
		switch f.health {
		case "hang":
			f.mu.Unlock()
			hang(r)
			f.mu.Lock()
		case "503":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			fmt.Fprint(w, `{"status":"healthy","db_connected":true}`)
		}
	case r.URL.Path == "/api/v1/rules":
		if !f.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch f.rules {
		case "hang":
			f.mu.Unlock()
			hang(r)
			f.mu.Lock()
		case "503":
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"code":"server.unavailable","human_message":"rule library not wired"}}`)
		default:
			fmt.Fprint(w, `{"rules":[],"total":769}`)
		}
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/scans"):
		if !f.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.sawIdemKey = r.Header.Get("Idempotency-Key") != ""
		w.WriteHeader(f.scanPost)
		if f.scanPost == http.StatusAccepted {
			fmt.Fprint(w, `{"scan_id":"01a0f45a-3830-7d60-8dc7-12ca5e2bf816","status":"queued","queued_at":"2026-09-30T18:05:00Z"}`)
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/scans/"):
		if !f.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st := f.scanStates[len(f.scanStates)-1]
		if f.polls < len(f.scanStates) {
			st = f.scanStates[f.polls]
		}
		f.polls++
		b, _ := json.Marshal(map[string]any{"scan": map[string]any{
			"scan_id": "01a0f45a-3830-7d60-8dc7-12ca5e2bf816", "status": st, "rules_error": f.rulesError,
		}})
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type blockRun struct {
	exit     int
	stdout   string
	stderr   string
	calls    string
	elapsed  time.Duration
	tokenHit bool
}

// runRestoreBlock runs block with stubbed systemctl and journalctl on PATH.
// journal is what journalctl prints.
func runRestoreBlock(t *testing.T, block, journal, token string) blockRun {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.log")
	journalFile := filepath.Join(dir, "journal.txt")
	if err := os.WriteFile(journalFile, []byte(journal), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("systemctl", fmt.Sprintf("echo \"systemctl $*\" >> %q\n", calls))
	stub("journalctl", fmt.Sprintf("echo \"journalctl $*\" >> %q\ncat %q\n", calls, journalFile))
	script := filepath.Join(dir, "block.sh")
	if err := os.WriteFile(script, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err := cmd.Run()
	r := blockRun{stdout: so.String(), stderr: se.String(), elapsed: time.Since(start)}
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run block: %v", err)
		}
		r.exit = ee.ExitCode()
	}
	c, _ := os.ReadFile(calls)
	r.calls = string(c)
	r.tokenHit = strings.Contains(r.stdout+r.stderr+r.calls, token)
	return r
}

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	if _, err := os.Stat("/proc/sys/kernel/random/uuid"); err != nil {
		t.Skip("no /proc/sys/kernel/random/uuid")
	}
}

func TestRunbook_RestoreVerifyBlockBehaves(t *testing.T) {
	needTools(t)
	const token = "owk_test_restore_verify_token_value"
	const warnScan = "WARN kensa scan wiring unavailable — on-demand scans will fail\n"
	const warnLib = "WARN kensa rule library unavailable; /api/v1/rules disabled\n"

	cases := []struct {
		name        string
		health      string
		rules       string
		journal     string
		fileToken   string
		healthWait  string
		wantOK      bool
		maxDuration time.Duration
	}{
		{name: "happy path", health: "ok", rules: "ok", fileToken: token, healthWait: "120", wantOK: true, maxDuration: 20 * time.Second},
		{name: "health never healthy", health: "503", rules: "ok", fileToken: token, healthWait: "4", maxDuration: 10 * time.Second},
		{name: "health request hangs", health: "hang", rules: "ok", fileToken: token, healthWait: "4", maxDuration: 10 * time.Second},
		{name: "scan wiring warning", health: "ok", rules: "ok", journal: warnScan, fileToken: token, healthWait: "120", maxDuration: 20 * time.Second},
		{name: "rule library warning", health: "ok", rules: "ok", journal: warnLib, fileToken: token, healthWait: "120", maxDuration: 20 * time.Second},
		{name: "rules answers 503", health: "ok", rules: "503", fileToken: token, healthWait: "120", maxDuration: 20 * time.Second},
		{name: "rules answers 401 for a token not in this database", health: "ok", rules: "ok", fileToken: "owk_a_token_created_after_the_backup", healthWait: "120", maxDuration: 20 * time.Second},
		{name: "rules request hangs", health: "ok", rules: "hang", fileToken: token, healthWait: "120", maxDuration: 40 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeOpenWatch{token: token, health: tc.health, rules: tc.rules}
			srv := httptest.NewTLSServer(f)
			defer srv.Close()
			tf := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tf, []byte(tc.fileToken), 0o600); err != nil {
				t.Fatal(err)
			}
			b := restoreBlock(t, restoreVerifyHeading)
			b = setInput(t, b, "TOKEN_FILE", "'"+tf+"'")
			b = setInput(t, b, "URL", srv.URL)
			b = setInput(t, b, "HEALTH_WAIT", tc.healthWait)
			r := runRestoreBlock(t, b, tc.journal, tc.fileToken)

			printed := strings.Contains(r.stdout, "VERIFIED:")
			if tc.wantOK && (r.exit != 0 || !printed) {
				t.Fatalf("want success, got exit %d, VERIFIED printed %v\nstderr: %s", r.exit, printed, r.stderr)
			}
			if !tc.wantOK {
				if r.exit == 0 || printed {
					t.Fatalf("want a stop, got exit %d, VERIFIED printed %v\nstdout: %s", r.exit, printed, r.stdout)
				}
				if !strings.Contains(r.stderr, "VERIFY STOPPED") || !strings.Contains(r.calls, "systemctl stop openwatch") {
					t.Fatalf("a stop must say so and stop the service\nstderr: %s\ncalls: %s", r.stderr, r.calls)
				}
			}
			if !strings.Contains(r.calls, "systemctl restart openwatch") {
				t.Fatalf("the block must restart the service, calls: %s", r.calls)
			}
			if r.elapsed > tc.maxDuration {
				t.Fatalf("took %s, want at most %s", r.elapsed, tc.maxDuration)
			}
			if r.tokenHit {
				t.Fatal("the token appeared in output or in a stub's arguments")
			}
		})
	}
}

func TestRunbook_RestoreScanBlockBehaves(t *testing.T) {
	needTools(t)
	const token = "owk_test_restore_scan_token_value"
	const hostID = "01a0ed4c-c03a-752b-8600-a15fff968665"
	cases := []struct {
		name       string
		post       int
		states     []string
		rulesError int
		fileToken  string
		scanWait   string
		wantOK     bool
	}{
		{name: "scan completes", post: 202, states: []string{"queued", "running", "completed"}, fileToken: token, scanWait: "60", wantOK: true},
		{name: "scan fails", post: 202, states: []string{"running", "failed"}, fileToken: token, scanWait: "60"},
		{name: "scan completes with rule errors", post: 202, states: []string{"completed"}, rulesError: 3, fileToken: token, scanWait: "60"},
		{name: "start refused 403", post: 403, states: []string{"completed"}, fileToken: token, scanWait: "60"},
		{name: "token not valid in this database", post: 202, states: []string{"completed"}, fileToken: "owk_a_token_created_after_the_backup", scanWait: "60"},
		{name: "scan never finishes within SCAN_WAIT", post: 202, states: []string{"running"}, fileToken: token, scanWait: "3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeOpenWatch{token: token, scanPost: tc.post, scanStates: tc.states, rulesError: tc.rulesError}
			srv := httptest.NewTLSServer(f)
			defer srv.Close()
			tf := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tf, []byte(tc.fileToken), 0o600); err != nil {
				t.Fatal(err)
			}
			b := restoreBlock(t, restoreScanHeading)
			b = setInput(t, b, "SCAN_TOKEN_FILE", "'"+tf+"'")
			b = setInput(t, b, "HOST_ID", "'"+hostID+"'")
			b = setInput(t, b, "URL", srv.URL)
			b = setInput(t, b, "SCAN_WAIT", tc.scanWait)
			r := runRestoreBlock(t, b, "", tc.fileToken)
			printed := strings.Contains(r.stdout, "SCANNED:")
			if tc.wantOK {
				if r.exit != 0 || !printed {
					t.Fatalf("want success, got exit %d, SCANNED printed %v\nstderr: %s", r.exit, printed, r.stderr)
				}
				if !f.sawIdemKey {
					t.Fatal("the scan request carried no Idempotency-Key")
				}
			} else if r.exit == 0 || printed {
				t.Fatalf("want a stop, got exit %d, SCANNED printed %v\nstdout: %s", r.exit, printed, r.stdout)
			}
			if r.elapsed > 45*time.Second {
				t.Fatalf("took %s", r.elapsed)
			}
			if r.tokenHit {
				t.Fatal("the token appeared in output or in a stub's arguments")
			}
		})
	}
}
