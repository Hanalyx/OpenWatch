// The session-based scan check in BACKUP_RECOVERY.md. On OpenWatch 0.7.1 and
// 0.8.1 a scan started with an API token answers 500 while the scan runs (CP
// bugs/OW-097), so the token-based scan check cannot pass there. This check
// signs in as a user instead, runs one scan, and signs out, proving the
// sign-out by replaying the session cookie. These tests run the block as the
// Markdown states it, apart from its input lines, with the real curl and
// python3 behind logging wrappers, against a local TLS server.
package packaging_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

const sessionScanHeading = "#### Run one scan end to end with a user session"

// sessionScanBounds reads the session check's own statement of its wait.
func sessionScanBounds(t *testing.T) (total, signIn, signOut int) {
	t.Helper()
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(readRunbook(t, "BACKUP_RECOVERY.md"), " ")
	m := regexp.MustCompile(`The check gives up after at most \*\*(\d+) seconds\*\*: (\d+) to sign in, the (\d+) seconds of the scan wait above, and (\d+) to sign out and check the cookie\.`).FindStringSubmatch(flat)
	if m == nil {
		t.Fatal("BACKUP_RECOVERY.md does not state the session check's wait in the expected sentence")
	}
	if sTotal, _, _, _, _ := scanBounds(t); atoi(m[3]) != sTotal {
		t.Fatalf("session check cites a %s-second scan wait, but the scan check states %d", m[3], sTotal)
	}
	return atoi(m[1]), atoi(m[2]), atoi(m[4])
}

// TestRunbook_SessionScanBlockIsGuarded is the always-on structural guard.
func TestRunbook_SessionScanBlockIsGuarded(t *testing.T) {
	b := restoreBlock(t, sessionScanHeading)

	// No success line without sign-in, the scan, and a sign-out attempt
	// before it; the sign-out proof is the cookie answering 401.
	inOrder(t, "session", b,
		"set -euo pipefail", "USER_NAME=", "PASSWORD_FILE=", "HOST_ID=", "STAGE=inputs", "SIGN_IN=not-started",
		"JAR_DIR=$(mktemp -d)", "sign_out() {", `-b "$JAR" -X POST "$URL/api/v1/auth/logout"`,
		`-b "$JAR" "$URL/api/v1/rules`, `[ "$out" = 204 ] && [ "$after" = 401 ]`,
		"on_stop() {", "sign_out\n", "trap 'on_stop $LINENO' ERR", `trap 'rm -rf "$JAR_DIR"' EXIT`,
		"python3 -I -S -c 'import json'", `test -r "$PASSWORD_FILE"`,
		"STAGE=login", "SIGN_IN=no-answer", `--data-binary @- "$URL/api/v1/auth/login") || { CODE="no answer"; false; }`,
		"SIGN_IN=answered", `[ "$CODE" = 200 ]`, `[ -n "$ACCESS" ]`,
		"STAGE=start", "Idempotency-Key: $KEY", `"$URL/api/v1/hosts/$HOST_ID/scans"`, `[ "$CODE" = 202 ]`,
		"STAGE=poll", `"completed 0") ;;`, "trap - ERR\n", "(scan result only)", "sign_out\n",
		`if [ "$SIGNOUT" != proven ]; then`, "exit 2", "echo \"SCANNED:")
	// A stop exits 1, so a stop is never confused with the exit 2 of an
	// unproven sign-out after a passing scan.
	inOrder(t, "session stop", b, "on_stop() {", "sign_out\n", "exit 1\n  }")
	if strings.Count(b, "SCANNED:") != 1 {
		t.Errorf("the session block prints SCANNED %d times, want once", strings.Count(b, "SCANNED:"))
	}

	// A request that gets no HTTP answer must never read as a status code.
	so := b[strings.Index(b, "sign_out() {"):strings.Index(b, "on_stop() {")]
	if regexp.MustCompile(`\|\|\s*(echo|out=[0-9]|after=[0-9])`).MatchString(so) {
		t.Error("sign_out falls back to an echo or a numeric status when a request fails")
	}
	// Cleanup follows the cookie jar: the only gates are "not run twice" and
	// "a sign-in was attempted". "No session" is said only after a definite
	// refusal, never after a sign-in that got no answer.
	inOrder(t, "sign_out", so, `[ "$SIGNOUT_DONE" = no ] || return 0`, `[ "$SIGN_IN" != not-started ] || return 0`,
		`if ! grep -q 'openwatch_session' "$JAR"`, `if [ "$SIGN_IN" = no-answer ]; then`, "Sign-in outcome unknown",
		`elif [ "$CODE" != 200 ]; then`, "there is no session to sign out")
	if n := strings.Count(so, "|| return 0"); n != 2 {
		t.Errorf("sign_out has %d early returns before the cookie check, want 2", n)
	}
	for _, want := range []string{`|| out="no answer"`, `|| after="no answer"`, `[ "$out" = 204 ] && [ "$after" = 401 ]`} {
		if !strings.Contains(so, want) {
			t.Errorf("sign_out lacks %q", want)
		}
	}

	// Nothing that sends a request runs before the stage leaves "inputs".
	pre := b[strings.Index(b, "trap 'on_stop $LINENO' ERR"):strings.Index(b, "STAGE=login")]
	if regexp.MustCompile(`(?m)^[^#\n]*\bcurl\b`).MatchString(pre) {
		t.Error("the session block calls curl before leaving the inputs stage")
	}
	if strings.Contains(b, "systemctl") {
		t.Error("the session block calls systemctl; a failed scan must not take the service down")
	}

	// The password is read only by python3 from the file; it never reaches a
	// command line, and nothing echoes it or the access token.
	if regexp.MustCompile(`(?m)\$\(cat "?\$PASSWORD_FILE`).MatchString(b) {
		t.Error("the session block expands the password file into the shell")
	}
	if regexp.MustCompile(`echo[^\n]*\$(ACCESS|AUTH)`).MatchString(b) {
		t.Error("the session block echoes the access token")
	}

	// Request bounds equal the stated wait.
	total, signIn, signOut := sessionScanBounds(t)
	sTotal, _, _, sLast, _ := scanBounds(t)
	if total != signIn+sTotal+signOut {
		t.Fatalf("session wait %d != %d + %d + %d", total, signIn, sTotal, signOut)
	}
	for _, l := range regexp.MustCompile(`(?m)^[^#\n]*curl .*$`).FindAllString(b, -1) {
		want := sLast
		if strings.Contains(l, "-c \"$JAR\"") || strings.Contains(l, "-o /dev/null -w '%{http_code}'") && !strings.Contains(l, "Idempotency") {
			want = signIn
		}
		flags := fmt.Sprintf("--connect-timeout 3 --max-time %d", want)
		if !strings.Contains(l, flags) {
			t.Errorf("session block curl lacks %q: %s", flags, strings.TrimSpace(l))
		}
	}
	if signOut != 2*signIn {
		t.Errorf("sign-out and the cookie check are two requests of %d seconds, stated as %d", signIn, signOut)
	}

	// The rollback text points to this check for 0.7.1.
	if !strings.Contains(readRunbook(t, "UPGRADE_PROCEDURE.md"), "(BACKUP_RECOVERY.md#run-one-scan-end-to-end-with-a-user-session)") {
		t.Error("UPGRADE_PROCEDURE.md does not point a 0.7.1 rollback to the session-based scan check")
	}
}

// fakeSessionOpenWatch stands in for the service's sign-in, scan and
// sign-out endpoints.
type fakeSessionOpenWatch struct {
	mu         sync.Mutex
	password   string
	login      string // "ok", "badpw", "mfa", "stallbody", "dropbody", "stallheaders", "badjson"
	scanPost   int
	scanState  string
	rulesError int
	logout     string // "ok", "500", "norevoke", "drop" (connection closed, no answer)
	probe      string // "ok", "drop", "hang", "gone" (server stops listening after sign-out)
	revoked    bool
	afterOut   bool // sign-out has been requested
	stopListen func()
	requests   []string // every request: method, URL, headers and body
	logouts    int
	scanPosts  int
}

const (
	fakeAccess  = "eyJ-fake-access-token-value"
	fakeSession = "fake-session-cookie-value"
	fakeScanID  = "01a0f45a-3830-7d60-8dc7-12ca5e2bf816"
)

func (f *fakeSessionOpenWatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	var hdr strings.Builder
	for k, v := range r.Header {
		fmt.Fprintf(&hdr, "%s=%s;", k, strings.Join(v, ","))
	}
	f.requests = append(f.requests, r.Method+" "+r.URL.String()+" "+hdr.String()+" "+string(body))
	bearer := r.Header.Get("Authorization") == "Bearer "+fakeAccess
	cookie, _ := r.Cookie("openwatch_session")
	hasCookie := cookie != nil && cookie.Value == fakeSession
	// The cookie replay after sign-out, when it must fail at the network
	// level rather than answer.
	if f.afterOut && hasCookie && r.URL.Path == "/api/v1/rules" {
		switch f.probe {
		case "drop":
			dropConn(w)
			return
		case "hang":
			f.mu.Unlock()
			hang(r)
			f.mu.Lock()
			return
		}
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/login":
		var req struct{ Username, Password string }
		_ = json.Unmarshal(body, &req)
		cookie := &http.Cookie{Name: "openwatch_session", Value: fakeSession, Path: "/", Secure: true, HttpOnly: true}
		switch {
		case f.login == "badpw" || req.Password != f.password:
			w.WriteHeader(http.StatusUnauthorized)
		case f.login == "mfa":
			fmt.Fprint(w, `{"mfa_required":true}`)
		case f.login == "stallheaders":
			// No status line, no headers, no cookie: the client times out.
			f.mu.Unlock()
			hang(r)
			f.mu.Lock()
		case f.login == "stallbody" || f.login == "dropbody":
			// The cookie and headers arrive; the body never completes.
			http.SetCookie(w, cookie)
			w.Header().Set("Content-Length", "200")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"access_tok`)
			w.(http.Flusher).Flush()
			if f.login == "dropbody" {
				// The deferred Unlock runs during the panic.
				panic(http.ErrAbortHandler) // closes the connection mid-body
			}
			f.mu.Unlock()
			hang(r)
			f.mu.Lock()
		case f.login == "badjson":
			http.SetCookie(w, cookie)
			fmt.Fprint(w, `{"access_token": "unterminated`)
		default:
			http.SetCookie(w, &http.Cookie{Name: "openwatch_session", Value: fakeSession, Path: "/", Secure: true, HttpOnly: true})
			fmt.Fprintf(w, `{"access_token":%q}`, fakeAccess)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/logout":
		f.logouts++
		f.afterOut = true
		if f.probe == "gone" && f.stopListen != nil {
			// New connections are refused from here on.
			f.stopListen()
		}
		switch f.logout {
		case "drop":
			dropConn(w)
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
		case "norevoke":
			w.WriteHeader(http.StatusNoContent)
		default:
			if hasCookie {
				f.revoked = true
			}
			w.WriteHeader(http.StatusNoContent)
		}
	case r.URL.Path == "/api/v1/rules":
		if (hasCookie && !f.revoked) || bearer {
			fmt.Fprint(w, `{"rules":[],"total":769}`)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/scans"):
		f.scanPosts++
		if !bearer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(f.scanPost)
		if f.scanPost == http.StatusAccepted {
			fmt.Fprintf(w, `{"scan_id":%q,"status":"queued","queued_at":"2026-10-02T12:57:12Z"}`, fakeScanID)
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/scans/"):
		if !bearer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := json.Marshal(map[string]any{"scan": map[string]any{
			"scan_id": fakeScanID, "status": f.scanState, "rules_error": f.rulesError,
		}})
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// dropConn closes the connection without writing an HTTP answer.
func dropConn(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("response writer cannot hijack")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// runSessionBlock runs block with curl and python3 wrapped by loggers that
// record every command line and then run the real tool, and with TMPDIR
// private so the test can see that the cookie directory was removed.
func runSessionBlock(t *testing.T, block string) (blockRun, string) {
	t.Helper()
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls.log")
	for _, tool := range []string{"curl", "python3"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		w := fmt.Sprintf("#!/bin/sh\necho \"%s $*\" >> %q\nexec %q \"$@\"\n", tool, calls, real)
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(w), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(fmt.Sprintf("#!/bin/sh\necho \"systemctl $*\" >> %q\n", calls)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "block.sh")
	if err := os.WriteFile(script, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+tmp)
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
	return r, tmp
}

func TestRunbook_SessionScanBlockBehaves(t *testing.T) {
	needTools(t)
	const password = "pw-Session-Check-7f3a91"
	const hostID = "01a0ed4c-c03a-752b-8600-a15fff968665"
	recent := "GET /api/v1/scans?host_id=" + hostID
	inspect := "Inspect scan " + fakeScanID + " (GET /api/v1/scans/" + fakeScanID + ", or the UI) before you start another scan."
	signedOut := "signed out: sign-out answered 204, and the check's session cookie now answers 401"
	result := "scan " + fakeScanID + " completed with no rule errors (scan result only)\n"
	signInUI := "Sign out of every session for rt-operator in the UI."
	noAnswer := "Sign-in got no answer: the request failed or timed out. No scan was started."
	cookieLeft := "Sign-in did not finish normally, but it set a session cookie, so the check signs it out."
	notProven := func(out, after string) string {
		return "Sign-out not proven (sign-out: " + out + ", session cookie afterwards: " + after + ")."
	}
	// The stop for a passing scan whose sign-out is not proven.
	unproven := []string{"SCAN CHECK STOPPED, stage: sign-out. The scan passed, but the check's sign-out could not be proven.",
		"The scan result above stands on its own. The check as a whole did not pass.",
		"Sign out of every session for rt-operator in the UI before you call the restore complete."}
	cases := []struct {
		name       string
		login      string
		post       int
		state      string
		rulesError int
		logout     string
		probe      string
		wantExit   int
		wantResult bool // the separate scan-result line is printed
		wantScan   bool // the scan request is sent
		wantLogout int  // sign-out requests sent
		noSession  bool // the check may say there is no session to sign out
		wantMsgs   []string
	}{
		{name: "scan completes and sign-out is proven", login: "ok", post: 202, state: "completed", logout: "ok",
			wantExit: 0, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: []string{signedOut}},
		{name: "wrong password", login: "badpw", post: 202, state: "completed", logout: "ok",
			wantExit: 1, noSession: true, wantMsgs: []string{"stage: login.",
				"Sign-in failed (HTTP status: 401). No scan was started.",
				"A wrong password counts toward the account's lockout. Check the file before you try again.",
				"Sign-in was refused and set no session cookie, so there is no session to sign out."}},
		{name: "account uses MFA", login: "mfa", post: 202, state: "completed", logout: "ok",
			wantExit: 1, wantMsgs: []string{"stage: login.",
				"Sign-in answered 200 without a usable access token. An account with MFA gets this answer.",
				"No scan was started. If the account uses MFA, use an account without it for this check.",
				"Sign-out not proven: sign-in answered 200 but set no session cookie to sign out with.", signInUI}},
		// Interrupted sign-in. Where a cookie was set, the check must sign it
		// out and report the proof; where none was set and the request got
		// no answer, the outcome is unknown, never "no session".
		{name: "sign-in sets a cookie, then its body stalls", login: "stallbody", post: 202, state: "completed", logout: "ok",
			wantExit: 1, wantLogout: 1, wantMsgs: []string{"stage: login.", noAnswer, cookieLeft, signedOut}},
		{name: "sign-in sets a cookie, then the connection drops", login: "dropbody", post: 202, state: "completed", logout: "ok",
			wantExit: 1, wantLogout: 1, wantMsgs: []string{"stage: login.", noAnswer, cookieLeft, signedOut}},
		{name: "sign-in stalls body after a cookie, and sign-out revokes nothing", login: "stallbody", post: 202, state: "completed", logout: "norevoke",
			wantExit: 1, wantLogout: 1, wantMsgs: []string{"stage: login.", noAnswer, cookieLeft, notProven("204", "200"), signInUI}},
		{name: "sign-in stalls before any headers", login: "stallheaders", post: 202, state: "completed", logout: "ok",
			wantExit: 1, wantMsgs: []string{"stage: login.", noAnswer,
				"Sign-in outcome unknown: the sign-in request got no answer, so a session may exist on the server.",
				"Check the sessions for rt-operator, or sign out of every session for rt-operator in the UI."}},
		{name: "sign-in answers 200 with a cookie and malformed JSON", login: "badjson", post: 202, state: "completed", logout: "ok",
			wantExit: 1, wantLogout: 1, wantMsgs: []string{"stage: login.",
				"Sign-in answered 200 without a usable access token. An account with MFA gets this answer.", cookieLeft, signedOut}},
		{name: "start answers 500", login: "ok", post: 500, state: "completed", logout: "ok",
			wantExit: 1, wantScan: true, wantLogout: 1, wantMsgs: []string{"stage: start.",
				"Verification interrupted: the request that starts the scan got no usable answer (HTTP status: 500).",
				"Its outcome is unknown. A scan may have started anyway. Before you run this block again,",
				"check this host's recent scans: " + recent + ", or the host's page in the UI.", signedOut}},
		{name: "scan ends failed", login: "ok", post: 202, state: "failed", logout: "ok",
			wantExit: 1, wantScan: true, wantLogout: 1, wantMsgs: []string{"stage: poll.",
				"Scan failed: scan " + fakeScanID + " ended failed, or completed with rule errors.", inspect, signedOut}},
		{name: "scan completes with rule errors", login: "ok", post: 202, state: "completed", rulesError: 3, logout: "ok",
			wantExit: 1, wantScan: true, wantLogout: 1, wantMsgs: []string{"stage: poll.",
				"Scan failed: scan " + fakeScanID + " ended failed, or completed with rule errors.", inspect, signedOut}},
		{name: "scan fails and the sign-out is not proven", login: "ok", post: 202, state: "failed", logout: "norevoke",
			wantExit: 1, wantScan: true, wantLogout: 1, wantMsgs: []string{"stage: poll.", notProven("204", "200"), signInUI}},
		// A passing scan whose sign-out is not proven: exit 2, no SCANNED,
		// and the scan's result on its own line.
		{name: "sign-out answers 204 but revokes nothing", login: "ok", post: 202, state: "completed", logout: "norevoke",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("204", "200"), signInUI}, unproven...)},
		{name: "sign-out answers 500", login: "ok", post: 202, state: "completed", logout: "500",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("500", "200"), signInUI}, unproven...)},
		{name: "sign-out request gets no answer", login: "ok", post: 202, state: "completed", logout: "drop",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("no answer", "200"), signInUI}, unproven...)},
		{name: "cookie check connection is dropped", login: "ok", post: 202, state: "completed", logout: "ok", probe: "drop",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("204", "no answer"), signInUI}, unproven...)},
		{name: "cookie check times out", login: "ok", post: 202, state: "completed", logout: "ok", probe: "hang",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("204", "no answer"), signInUI}, unproven...)},
		{name: "server goes away after sign-out", login: "ok", post: 202, state: "completed", logout: "ok", probe: "gone",
			wantExit: 2, wantResult: true, wantScan: true, wantLogout: 1, wantMsgs: append([]string{notProven("204", "no answer"), signInUI}, unproven...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSessionOpenWatch{password: password, login: tc.login, scanPost: tc.post,
				scanState: tc.state, rulesError: tc.rulesError, logout: tc.logout, probe: tc.probe}
			srv := httptest.NewTLSServer(f)
			defer srv.Close()
			f.mu.Lock()
			f.stopListen = func() { _ = srv.Listener.Close() }
			f.mu.Unlock()
			pf := filepath.Join(t.TempDir(), "password")
			if err := os.WriteFile(pf, []byte(password+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			b := restoreBlock(t, sessionScanHeading)
			b = setInput(t, b, "USER_NAME", "'rt-operator'")
			b = setInput(t, b, "PASSWORD_FILE", "'"+pf+"'")
			b = setInput(t, b, "HOST_ID", "'"+hostID+"'")
			b = setInput(t, b, "URL", srv.URL)
			r, tmp := runSessionBlock(t, b)

			if r.exit != tc.wantExit {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.exit, tc.wantExit, r.stdout, r.stderr)
			}
			// SCANNED only when the scan passed AND the sign-out was proven.
			if printed := strings.Contains(r.stdout+r.stderr, "SCANNED"); printed != (tc.wantExit == 0) {
				t.Fatalf("SCANNED printed %v with exit %d\nstdout: %s", printed, r.exit, r.stdout)
			}
			if tc.wantExit == 0 && !strings.HasSuffix(r.stdout, result+"SCANNED: scan "+fakeScanID+" completed with no rule errors, and the check's session is signed out\n") {
				t.Fatalf("success must print the scan result, then SCANNED last:\n%s", r.stdout)
			}
			if got := strings.Contains(r.stdout, result); got != tc.wantResult {
				t.Fatalf("scan-result line printed %v, want %v\nstdout: %s", got, tc.wantResult, r.stdout)
			}
			if tc.wantExit != 0 && !strings.Contains(r.stderr, "SCAN CHECK STOPPED") {
				t.Fatalf("a nonzero exit without a stop message: %s", r.stderr)
			}
			if tc.wantExit == 1 && !strings.Contains(r.stderr, "The service was left running") {
				t.Fatalf("a stop must say the service was left running: %s", r.stderr)
			}
			for _, m := range tc.wantMsgs {
				if !strings.Contains(r.stderr, m+"\n") {
					t.Fatalf("stderr lacks %q\nstderr:\n%s", m, r.stderr)
				}
			}
			// "No session" only after a definite refusal with no cookie.
			if got := strings.Contains(r.stderr, "no session to sign out"); got != tc.noSession {
				t.Fatalf("\"no session to sign out\" printed %v, want %v\nstderr:\n%s", got, tc.noSession, r.stderr)
			}
			// A sign-out that is not proven is never reported as one.
			if tc.wantExit == 2 && strings.Contains(r.stderr, "signed out:") {
				t.Fatalf("an unproven sign-out was reported as signed out:\n%s", r.stderr)
			}
			f.mu.Lock()
			scanPosts, logouts, revoked, reqs := f.scanPosts, f.logouts, f.revoked, append([]string(nil), f.requests...)
			f.mu.Unlock()
			if (scanPosts > 0) != tc.wantScan {
				t.Fatalf("scan requests sent: %d, want sent=%v", scanPosts, tc.wantScan)
			}
			if logouts != tc.wantLogout {
				t.Fatalf("sign-out requests: %d, want %d", logouts, tc.wantLogout)
			}
			if tc.logout == "ok" && tc.wantLogout == 1 && !revoked {
				t.Fatal("sign-out did not send the session cookie, so nothing was revoked")
			}
			// The password reaches the server only in the sign-in body.
			for _, q := range reqs {
				if strings.Contains(q, password) && !strings.HasPrefix(q, "POST /api/v1/auth/login ") {
					t.Fatalf("the password left the sign-in request: %s", q)
				}
				if strings.HasPrefix(q, "POST /api/v1/auth/login ") && strings.Contains(strings.SplitN(q, " ", 4)[2], password) {
					t.Fatal("the password appeared in the sign-in request's URL or headers")
				}
			}
			// The password and the access token appear in no command line and
			// no output.
			for _, secret := range []string{password, fakeAccess, fakeSession} {
				if strings.Contains(r.stdout+r.stderr+r.calls, secret) {
					t.Fatalf("a secret appeared in output or in a command line\ncalls:\n%s", r.calls)
				}
			}
			if r.count("systemctl") != 0 {
				t.Fatalf("the session block touched the service; calls:\n%s", r.calls)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Fatalf("the cookie directory was left behind: %v", left)
			}
			t.Logf("elapsed %s", r.elapsed.Round(time.Millisecond))
		})
	}
}

// TestRunbook_SessionScanBlockRefusesBadInputs: an unfilled value or an
// unreadable password file stops the block before any request.
func TestRunbook_SessionScanBlockRefusesBadInputs(t *testing.T) {
	needTools(t)
	const hostID = "01a0ed4c-c03a-752b-8600-a15fff968665"
	for _, tc := range []struct {
		name string
		fill bool
	}{{"values left unfilled", false}, {"password file missing", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := restoreBlock(t, sessionScanHeading)
			if tc.fill {
				b = setInput(t, b, "USER_NAME", "'rt-operator'")
				b = setInput(t, b, "PASSWORD_FILE", "'"+filepath.Join(t.TempDir(), "absent")+"'")
				b = setInput(t, b, "HOST_ID", "'"+hostID+"'")
			}
			r, tmp := runSessionBlock(t, b)
			if r.exit == 0 || strings.Contains(r.stdout, "SCANNED:") {
				t.Fatalf("want a stop, got exit %d, stdout %q", r.exit, r.stdout)
			}
			if n := r.count("curl"); n != 0 {
				t.Fatalf("curl called %d times on a bad input; calls:\n%s", n, r.calls)
			}
			if !strings.Contains(r.stderr, "stage: inputs") || !strings.Contains(r.stderr, "Nothing was changed") {
				t.Fatalf("stop message does not say nothing was changed: %s", r.stderr)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Fatalf("the cookie directory was left behind: %v", left)
			}
		})
	}
}
