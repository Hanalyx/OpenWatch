// Restore verification in BACKUP_RECOVERY.md. A 200 from /api/v1/health does
// not prove OpenWatch works: when the Kensa rule library fails to load, the
// service starts, health answers healthy, and every scan fails (CP
// bugs/OW-094). The runbook's "Prove the restored service works" section
// therefore has two fail-fast blocks, one that proves the rule library loaded
// and one that runs a scan end to end, and other runbooks point to it after a
// restart. These tests run the blocks as the Markdown states them, apart from
// their input lines, with the real curl against a local TLS server and stubbed
// systemctl and journalctl.
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	restoreVerifyHeading = "#### Check that the rule library loaded"
	restoreScanHeading   = "#### Run one scan end to end"
	proveSectionLink     = "BACKUP_RECOVERY.md#prove-the-restored-service-works"
)

func readRunbook(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForLinks(t), "docs", "runbooks", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// restoreBlock returns the first ```bash block after heading in
// BACKUP_RECOVERY.md, without its fences.
func restoreBlock(t *testing.T, heading string) string {
	t.Helper()
	doc := readRunbook(t, "BACKUP_RECOVERY.md")
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

// replaceOnce swaps an exact string that must appear once; used only to
// shorten a wait that the structural guard has already checked.
func replaceOnce(t *testing.T, block, old, new string) string {
	t.Helper()
	if n := strings.Count(block, old); n != 1 {
		t.Fatalf("block contains %q %d times, want 1", old, n)
	}
	return strings.Replace(block, old, new, 1)
}

// inOrder asserts each needle appears in s, in order.
func inOrder(t *testing.T, label, s string, needles ...string) {
	t.Helper()
	at := 0
	for _, n := range needles {
		i := strings.Index(s[at:], n)
		if i < 0 {
			t.Fatalf("%s: missing %q after offset %d, or out of order", label, n, at)
		}
		at += i + len(n)
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// upgradeBounds reads the single statement of the health and rules bounds in
// UPGRADE_PROCEDURE.md, the source BACKUP_RECOVERY.md points to.
func upgradeBounds(t *testing.T) (connect, healthMax, deadline, pause, rulesMax, total int) {
	t.Helper()
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(readRunbook(t, "UPGRADE_PROCEDURE.md"), " ")
	flags := regexp.MustCompile("carries `--connect-timeout (\\d+) --max-time (\\d+)`").FindStringSubmatch(flat)
	doc := regexp.MustCompile(`The health wait gives up after at most \*\*(\d+) seconds\*\*: a (\d+)-second deadline, ` +
		`plus one last request of at most (\d+) seconds and a (\d+)-second pause\. The rules check then gives up ` +
		`after at most \*\*(\d+) seconds\*\*`).FindStringSubmatch(flat)
	if flags == nil || doc == nil {
		t.Fatal("UPGRADE_PROCEDURE.md does not state the request flags and bounds in the expected sentences")
	}
	if atoi(flags[2]) != atoi(doc[3]) {
		t.Fatalf("UPGRADE_PROCEDURE.md states --max-time %s but a last request of %s seconds", flags[2], doc[3])
	}
	return atoi(flags[1]), atoi(flags[2]), atoi(doc[2]), atoi(doc[4]), atoi(doc[5]), atoi(doc[1])
}

// scanBounds reads BACKUP_RECOVERY.md's own statement of the scan wait.
func scanBounds(t *testing.T) (total, start, deadline, last, pause int) {
	t.Helper()
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(readRunbook(t, "BACKUP_RECOVERY.md"), " ")
	m := regexp.MustCompile(`The scan check gives up after at most \*\*(\d+) seconds\*\*: (\d+) for the request that starts ` +
		`the scan, a (\d+)-second polling deadline, then one last poll of at most (\d+) seconds and a (\d+)-second pause\.`).FindStringSubmatch(flat)
	if m == nil {
		t.Fatal("BACKUP_RECOVERY.md does not state the scan wait in the expected sentence")
	}
	return atoi(m[1]), atoi(m[2]), atoi(m[3]), atoi(m[4]), atoi(m[5])
}

// TestRunbook_RestoreVerifyBlocksAreGuarded is the always-on structural guard.
func TestRunbook_RestoreVerifyBlocksAreGuarded(t *testing.T) {
	verify := restoreBlock(t, restoreVerifyHeading)
	scan := restoreBlock(t, restoreScanHeading)

	// No success line without every check before it.
	inOrder(t, "verify", verify,
		"set -euo pipefail", "TOKEN_FILE=", "STAGE=inputs", "trap 'on_stop $LINENO' ERR",
		"[[ \"$TOKEN\" == owk_* ]]", "STAGE=verify", "systemctl restart openwatch",
		"DEADLINE=$((SECONDS + ", `while [ "$SECONDS" -lt "$DEADLINE" ]; do`, `"$URL/api/v1/health"`,
		`[ "$READY" = yes ]`, `journalctl -u openwatch --since "$SINCE"`,
		`*"kensa scan wiring unavailable"*`, `*"kensa rule library unavailable"*`,
		`-K - "$URL/api/v1/rules"`, `[ "$RULES" = 200 ]`, "trap - ERR\n", "echo \"VERIFIED:")
	inOrder(t, "scan", scan,
		"set -euo pipefail", "SCAN_TOKEN_FILE=", "STAGE=inputs", "trap 'on_stop $LINENO' ERR",
		"[[ \"$TOKEN\" == owk_* ]]", "STAGE=scan", "Idempotency-Key: $KEY",
		`"$URL/api/v1/hosts/$HOST_ID/scans"`, `[ "$CODE" = 202 ]`, `"$URL/api/v1/scans/$SCAN_ID"`,
		`[ "$STATE" = "completed 0" ]`, "trap - ERR\n", "echo \"SCANNED:")

	// Input failures never touch the service: nothing that calls systemctl,
	// journalctl or curl runs before the stage leaves "inputs", and the
	// inputs branch of each stop handler calls nothing.
	for label, b := range map[string]string{"verify": verify, "scan": scan} {
		next := "STAGE=verify"
		if label == "scan" {
			next = "STAGE=scan"
		}
		body := b[strings.Index(b, "trap 'on_stop $LINENO' ERR"):strings.Index(b, next)]
		for _, cmd := range []string{"systemctl", "journalctl", "curl"} {
			if strings.Contains(body, cmd) {
				t.Errorf("%s block runs %s before leaving the inputs stage", label, cmd)
			}
		}
		handler := b[strings.Index(b, "inputs)"):strings.Index(b, ";;")]
		if strings.Contains(handler, "systemctl") {
			t.Errorf("%s block's inputs stop branch touches the service", label)
		}
	}
	// The scan block never stops or restarts the service.
	if strings.Contains(scan, "systemctl") {
		t.Error("the scan block calls systemctl; a failed scan must not take the service down")
	}

	// Request timeouts and waits equal the single statement in
	// UPGRADE_PROCEDURE.md, which BACKUP_RECOVERY.md points to.
	connect, healthMax, deadline, pause, rulesMax, total := upgradeBounds(t)
	if total != deadline+healthMax+pause {
		t.Fatalf("UPGRADE_PROCEDURE.md says %d seconds, but %d + %d + %d = %d", total, deadline, healthMax, pause, deadline+healthMax+pause)
	}
	if !strings.Contains(readRunbook(t, "BACKUP_RECOVERY.md"), "(UPGRADE_PROCEDURE.md#how-long-the-checks-wait)") {
		t.Error("BACKUP_RECOVERY.md does not point to the upgrade runbook's timing section")
	}
	for _, l := range regexp.MustCompile(`(?m)^.*curl .*$`).FindAllString(verify, -1) {
		want := healthMax
		if strings.Contains(l, "/api/v1/rules") {
			want = rulesMax
		}
		flags := fmt.Sprintf("--connect-timeout %d --max-time %d", connect, want)
		if !strings.Contains(l, flags) {
			t.Errorf("verify block curl lacks %q: %s", flags, strings.TrimSpace(l))
		}
	}
	if !strings.Contains(verify, fmt.Sprintf("DEADLINE=$((SECONDS + %d))", deadline)) ||
		!regexp.MustCompile(fmt.Sprintf(`(?m)^    sleep %d$`, pause)).MatchString(verify) {
		t.Errorf("verify block deadline or pause disagrees with UPGRADE_PROCEDURE.md (%d s, %d s)", deadline, pause)
	}

	// The scan block states its own wait; the numbers add up and match.
	sTotal, sStart, sDeadline, sLast, sPause := scanBounds(t)
	if sTotal != sStart+sDeadline+sLast+sPause {
		t.Fatalf("scan wait %d != %d + %d + %d + %d", sTotal, sStart, sDeadline, sLast, sPause)
	}
	for _, l := range regexp.MustCompile(`(?m)^.*curl .*$`).FindAllString(scan, -1) {
		flags := fmt.Sprintf("--connect-timeout %d --max-time %d", connect, sLast)
		if !strings.Contains(l, flags) {
			t.Errorf("scan block curl lacks %q: %s", flags, strings.TrimSpace(l))
		}
	}
	if sStart != sLast {
		t.Errorf("scan start request bound %d differs from the per-request --max-time %d", sStart, sLast)
	}
	if !strings.Contains(scan, fmt.Sprintf("DEADLINE=$((SECONDS + %d))", sDeadline)) ||
		!regexp.MustCompile(fmt.Sprintf(`(?m)^    sleep %d$`, sPause)).MatchString(scan) {
		t.Errorf("scan block deadline or pause disagrees with the stated wait (%d s, %d s)", sDeadline, sPause)
	}

	// The token is never printed and never on a command line.
	for label, b := range map[string]string{"verify": verify, "scan": scan} {
		if regexp.MustCompile(`echo[^\n]*\$TOKEN`).MatchString(b) {
			t.Errorf("%s block echoes the token", label)
		}
		for _, l := range strings.Split(b, "\n") {
			if strings.Contains(l, "curl ") && (strings.Contains(l, "Bearer") || strings.Contains(l, "$AUTH")) && !strings.Contains(l, "-K -") {
				if !strings.Contains(l, "\\") {
					t.Errorf("%s block passes the token on the command line: %s", label, strings.TrimSpace(l))
				}
			}
		}
	}

	// Every runbook that restarts OpenWatch and used to call it recovered on
	// health alone now points to the shared section, and the anchor exists.
	if !strings.Contains(readRunbook(t, "BACKUP_RECOVERY.md"), "\n### Prove the restored service works\n") {
		t.Fatal("BACKUP_RECOVERY.md lost the section other runbooks point to")
	}
	for _, f := range []string{"SECRET_ROTATION.md", "SERVICE_DOWN.md", "HIGH_CPU.md", "DATABASE_ISSUES.md", "SECURITY_INCIDENT.md"} {
		if !strings.Contains(readRunbook(t, f), "]("+proveSectionLink+")") {
			t.Errorf("%s does not point to %s", f, proveSectionLink)
		}
	}
}

// hang holds a request open until the client gives up, so a curl timeout is
// what ends it, and the test server can close without waiting.
func hang(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(120 * time.Second):
	}
}

// fakeOpenWatch is the local stand-in for the service.
type fakeOpenWatch struct {
	mu         sync.Mutex
	token      string
	health     string // "ok", "503", "hang"
	rules      string // "ok", "503", "hang"
	scanPost   int
	scanPoll   string   // "ok" or "hang"
	scanStates []string // successive status values; the last repeats
	rulesError int
	polls      int
	sawIdemKey bool
}

func (f *fakeOpenWatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	authorized := r.Header.Get("Authorization") == "Bearer "+f.token
	switch {
	case r.URL.Path == "/api/v1/health":
		mode := f.health
		f.mu.Unlock()
		switch mode {
		case "hang":
			hang(r)
		case "503":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			fmt.Fprint(w, `{"status":"healthy","db_connected":true}`)
		}
	case r.URL.Path == "/api/v1/rules":
		mode := f.rules
		f.mu.Unlock()
		switch {
		case !authorized:
			w.WriteHeader(http.StatusUnauthorized)
		case mode == "hang":
			hang(r)
		case mode == "503":
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"code":"server.unavailable","human_message":"rule library not wired"}}`)
		default:
			fmt.Fprint(w, `{"rules":[],"total":769}`)
		}
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/scans"):
		f.sawIdemKey = r.Header.Get("Idempotency-Key") != ""
		post := f.scanPost
		f.mu.Unlock()
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(post)
		if post == http.StatusAccepted {
			fmt.Fprint(w, `{"scan_id":"01a0f45a-3830-7d60-8dc7-12ca5e2bf816","status":"queued","queued_at":"2026-09-30T18:05:00Z"}`)
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/scans/"):
		st := f.scanStates[len(f.scanStates)-1]
		if f.polls < len(f.scanStates) {
			st = f.scanStates[f.polls]
		}
		f.polls++
		poll, rulesErr := f.scanPoll, f.rulesError
		f.mu.Unlock()
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if poll == "hang" {
			hang(r)
			return
		}
		b, _ := json.Marshal(map[string]any{"scan": map[string]any{
			"scan_id": "01a0f45a-3830-7d60-8dc7-12ca5e2bf816", "status": st, "rules_error": rulesErr,
		}})
		_, _ = w.Write(b)
	default:
		f.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}
}

type blockRun struct {
	exit    int
	stdout  string
	stderr  string
	calls   string
	elapsed time.Duration
}

// count returns how many logged calls start with cmd.
func (r blockRun) count(cmd string) int {
	n := 0
	for _, l := range strings.Split(r.calls, "\n") {
		if strings.HasPrefix(l, cmd+" ") || l == cmd {
			n++
		}
	}
	return n
}

// runRestoreBlock runs block with stubbed systemctl and journalctl on PATH.
// With logCurl, curl is a logging stub too (for the input cases, which must
// make no request); otherwise the real curl runs.
func runRestoreBlock(t *testing.T, block, journal string, logCurl bool) blockRun {
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
	if logCurl {
		stub("curl", fmt.Sprintf("echo \"curl\" >> %q\nexit 7\n", calls))
	}
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

// TestRunbook_RestoreBlocksRefuseBadInputs: a bad input must stop the block
// without a single call to systemctl, journalctl or curl, so it can never take
// a healthy service down.
func TestRunbook_RestoreBlocksRefuseBadInputs(t *testing.T) {
	needTools(t)
	const hostID = "01a0ed4c-c03a-752b-8600-a15fff968665"
	type input struct {
		name   string
		mutate func(t *testing.T, dir string) (tokenPath string, placeholder bool)
	}
	inputs := []input{
		{"token file missing", func(t *testing.T, dir string) (string, bool) { return filepath.Join(dir, "absent"), false }},
		{"token file unreadable", func(t *testing.T, dir string) (string, bool) {
			p := filepath.Join(dir, "token")
			if err := os.WriteFile(p, []byte("owk_x"), 0o000); err != nil {
				t.Fatal(err)
			}
			return p, false
		}},
		{"value left unfilled", func(t *testing.T, dir string) (string, bool) { return "", true }},
		{"token without owk_ prefix", func(t *testing.T, dir string) (string, bool) {
			p := filepath.Join(dir, "token")
			if err := os.WriteFile(p, []byte("Bearer eyJhbGciOi"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p, false
		}},
	}
	for _, block := range []struct {
		name, heading, tokenVar, marker string
	}{
		{"verify", restoreVerifyHeading, "TOKEN_FILE", "VERIFIED:"},
		{"scan", restoreScanHeading, "SCAN_TOKEN_FILE", "SCANNED:"},
	} {
		for _, in := range inputs {
			t.Run(block.name+"/"+in.name, func(t *testing.T) {
				t.Parallel()
				if in.name == "token file unreadable" && os.Geteuid() == 0 {
					t.Skip("root reads a mode-000 file")
				}
				path, placeholder := in.mutate(t, t.TempDir())
				b := restoreBlock(t, block.heading)
				if !placeholder {
					b = setInput(t, b, block.tokenVar, "'"+path+"'")
					if block.name == "scan" {
						b = setInput(t, b, "HOST_ID", "'"+hostID+"'")
					}
				}
				r := runRestoreBlock(t, b, "", true)
				if r.exit == 0 || strings.Contains(r.stdout, block.marker) {
					t.Fatalf("want a stop, got exit %d, stdout %q", r.exit, r.stdout)
				}
				for _, cmd := range []string{"systemctl", "journalctl", "curl"} {
					if n := r.count(cmd); n != 0 {
						t.Fatalf("%s called %d times on a bad input; calls:\n%s", cmd, n, r.calls)
					}
				}
				if !strings.Contains(r.stderr, "stage: inputs") || !strings.Contains(r.stderr, "Nothing was changed") {
					t.Fatalf("stop message does not say nothing was changed: %s", r.stderr)
				}
			})
		}
	}
}

func TestRunbook_RestoreVerifyBlockBehaves(t *testing.T) {
	needTools(t)
	const token = "owk_test_restore_verify_token_value"
	const warnScan = "WARN kensa scan wiring unavailable — on-demand scans will fail\n"
	const warnLib = "WARN kensa rule library unavailable; /api/v1/rules disabled\n"
	_, healthMax, deadline, pause, rulesMax, total := upgradeBounds(t)
	slack := 4 * time.Second
	healthBound := time.Duration(total)*time.Second + slack
	cases := []struct {
		name      string
		health    string
		rules     string
		journal   string
		fileToken string
		wantOK    bool
		bound     time.Duration
		minimum   time.Duration
	}{
		{name: "happy path", health: "ok", rules: "ok", fileToken: token, wantOK: true, bound: 15 * time.Second},
		{name: "health never healthy", health: "503", rules: "ok", fileToken: token, bound: healthBound,
			minimum: time.Duration(deadline) * time.Second},
		{name: "health request hangs", health: "hang", rules: "ok", fileToken: token, bound: healthBound,
			minimum: time.Duration(deadline) * time.Second},
		{name: "scan wiring warning", health: "ok", rules: "ok", journal: warnScan, fileToken: token, bound: 15 * time.Second},
		{name: "rule library warning", health: "ok", rules: "ok", journal: warnLib, fileToken: token, bound: 15 * time.Second},
		{name: "rules answers 503", health: "ok", rules: "503", fileToken: token, bound: 15 * time.Second},
		{name: "rules answers 401 for a token not in this database", health: "ok", rules: "ok",
			fileToken: "owk_a_token_created_after_the_backup", bound: 15 * time.Second},
		{name: "rules request hangs", health: "ok", rules: "hang", fileToken: token,
			bound: time.Duration(rulesMax)*time.Second + slack, minimum: time.Duration(rulesMax) * time.Second},
	}
	_ = healthMax
	_ = pause
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
			r := runRestoreBlock(t, b, tc.journal, false)

			printed := strings.Contains(r.stdout, "VERIFIED:")
			if tc.wantOK {
				if r.exit != 0 || !printed {
					t.Fatalf("want success, got exit %d, VERIFIED printed %v\nstderr: %s", r.exit, printed, r.stderr)
				}
				if r.count("systemctl stop") != 0 {
					t.Fatalf("a passing check stopped the service; calls:\n%s", r.calls)
				}
			} else {
				if r.exit == 0 || printed {
					t.Fatalf("want a stop, got exit %d, VERIFIED printed %v\nstdout: %s", r.exit, printed, r.stdout)
				}
				if !strings.Contains(r.stderr, "stage: verify") || r.count("systemctl stop") != 1 {
					t.Fatalf("a stop after the restart must say so and stop the service once\nstderr: %s\ncalls:\n%s", r.stderr, r.calls)
				}
			}
			if r.count("systemctl restart") != 1 {
				t.Fatalf("the block must restart the service once; calls:\n%s", r.calls)
			}
			// The HTTP bounds hold with the real curl: health stops after its
			// documented wait, and a hanging request is cut at --max-time.
			if r.elapsed > tc.bound || r.elapsed < tc.minimum {
				t.Fatalf("took %s, want between %s and %s", r.elapsed.Round(time.Millisecond), tc.minimum, tc.bound)
			}
			t.Logf("elapsed %s (bound %s)", r.elapsed.Round(time.Millisecond), tc.bound)
			if strings.Contains(r.stdout+r.stderr+r.calls, tc.fileToken) {
				t.Fatal("the token appeared in output or in a stub's arguments")
			}
		})
	}
}

func TestRunbook_RestoreScanBlockBehaves(t *testing.T) {
	needTools(t)
	const token = "owk_test_restore_scan_token_value"
	const hostID = "01a0ed4c-c03a-752b-8600-a15fff968665"
	_, _, sDeadline, sLast, sPause := scanBounds(t)
	cases := []struct {
		name       string
		post       int
		poll       string
		states     []string
		rulesError int
		fileToken  string
		shortWait  bool
		wantOK     bool
		bound      time.Duration
	}{
		{name: "scan completes", post: 202, states: []string{"queued", "running", "completed"}, fileToken: token, wantOK: true, bound: 40 * time.Second},
		{name: "scan fails", post: 202, states: []string{"running", "failed"}, fileToken: token, bound: 30 * time.Second},
		{name: "scan completes with rule errors", post: 202, states: []string{"completed"}, rulesError: 3, fileToken: token, bound: 15 * time.Second},
		{name: "start refused 403", post: 403, states: []string{"completed"}, fileToken: token, bound: 15 * time.Second},
		{name: "token not valid in this database", post: 202, states: []string{"completed"}, fileToken: "owk_a_token_created_after_the_backup", bound: 15 * time.Second},
		{name: "poll request hangs", post: 202, poll: "hang", states: []string{"running"}, fileToken: token,
			bound: time.Duration(sLast)*time.Second + 4*time.Second},
		{name: "scan never finishes within the deadline", post: 202, states: []string{"running"}, fileToken: token, shortWait: true,
			bound: time.Duration(3+sLast+sPause)*time.Second + 4*time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeOpenWatch{token: token, scanPost: tc.post, scanPoll: tc.poll, scanStates: tc.states, rulesError: tc.rulesError}
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
			if tc.shortWait {
				// The guard checks the real deadline against the runbook; this
				// case only needs one to expire.
				b = replaceOnce(t, b, fmt.Sprintf("DEADLINE=$((SECONDS + %d))", sDeadline), "DEADLINE=$((SECONDS + 3))")
			}
			r := runRestoreBlock(t, b, "", false)
			printed := strings.Contains(r.stdout, "SCANNED:")
			if tc.wantOK {
				if r.exit != 0 || !printed {
					t.Fatalf("want success, got exit %d, SCANNED printed %v\nstderr: %s", r.exit, printed, r.stderr)
				}
				if !f.sawIdemKey {
					t.Fatal("the scan request carried no Idempotency-Key")
				}
			} else {
				if r.exit == 0 || printed {
					t.Fatalf("want a stop, got exit %d, SCANNED printed %v\nstdout: %s", r.exit, printed, r.stdout)
				}
				if !strings.Contains(r.stderr, "The service was left running") {
					t.Fatalf("a failed scan must say the service was left running: %s", r.stderr)
				}
			}
			if r.count("systemctl") != 0 {
				t.Fatalf("the scan block touched the service; calls:\n%s", r.calls)
			}
			if r.elapsed > tc.bound {
				t.Fatalf("took %s, want at most %s", r.elapsed.Round(time.Millisecond), tc.bound)
			}
			t.Logf("elapsed %s (bound %s)", r.elapsed.Round(time.Millisecond), tc.bound)
			if strings.Contains(r.stdout+r.stderr+r.calls, tc.fileToken) {
				t.Fatal("the token appeared in output or in a stub's arguments")
			}
		})
	}
}
