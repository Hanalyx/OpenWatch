// Structural guards for the security and database runbooks (CP bugs/OW-105).
//
// Each test pins a defect an operator would otherwise follow during an
// incident: investigation SQL that looked for host OS-user events instead of
// OpenWatch account events, a DEK rotation that listed two of the four
// secret kinds the key protects and said nothing about the job queue, a
// "safe to kill" instruction that broke the per-host scan lock, and a
// database password rotation that rewrote the whole DSN with a hardcoded
// host and sslmode. The last one is also run: the embedded script edits a
// scratch secrets.env, with a stub runuser standing in for psql.
package packaging_test

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// secRunbookSection returns the text from heading to the next heading of the
// same or a higher level. heading is the full line, for example
// "### Rotate the database credential".
func secRunbookSection(t *testing.T, doc, heading string) string {
	t.Helper()
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		t.Fatalf("no heading %q", heading)
	}
	level := strings.Count(strings.Fields(heading)[0], "#")
	body := doc[i+1+len(heading):]
	re := regexp.MustCompile(fmt.Sprintf(`^#{1,%d} `, level))
	inFence := false
	off := 0
	for _, line := range strings.SplitAfter(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
		}
		if !inFence && re.MatchString(line) {
			return body[:off]
		}
		off += len(line)
	}
	return body
}

// secRunbookFences returns the bodies of the fenced code blocks in text, with
// the fence's own indentation removed from each line.
func secRunbookFences(text string) []string {
	var out []string
	var cur []string
	indent := ""
	in := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "```") {
			if in {
				out = append(out, strings.Join(cur, "\n")+"\n")
				cur, in = nil, false
				continue
			}
			indent = line[:len(line)-len(trimmed)]
			in = true
			continue
		}
		if in {
			cur = append(cur, strings.TrimPrefix(line, indent))
		}
	}
	return out
}

// The investigation SQL must look for OpenWatch's own account events, and
// must never mix the host collector's account.user.* codes into a query
// about OpenWatch accounts.
func TestSecurityIncident_AccountQueriesUseControlPlaneEvents(t *testing.T) {
	doc := readRunbook(t, "SECURITY_INCIDENT.md")
	var auditBlocks []string
	for _, b := range secRunbookFences(doc) {
		if strings.Contains(b, "FROM audit_events") {
			auditBlocks = append(auditBlocks, b)
		}
	}
	if len(auditBlocks) == 0 {
		t.Fatal("SECURITY_INCIDENT.md has no audit_events query")
	}

	for _, code := range []string{"admin.user.created", "admin.user.deleted"} {
		found := false
		for _, b := range auditBlocks {
			if strings.Contains(b, "'"+code+"'") {
				found = true
			}
		}
		if !found {
			t.Errorf("no audit_events query looks for %s, the event OpenWatch emits for its own accounts", code)
		}
	}

	for _, b := range auditBlocks {
		if !strings.Contains(b, "'account.user.") {
			continue
		}
		if strings.Contains(b, "'admin.") || strings.Contains(b, "'authz.") || strings.Contains(b, "'auth.") {
			t.Errorf("a query mixes host OS-user events (account.user.*) with OpenWatch account events:\n%s", b)
		}
	}

	symptoms := secRunbookSection(t, doc, "## Symptoms")
	for _, line := range strings.Split(symptoms, "\n") {
		if strings.Contains(line, "account.user.") && !strings.Contains(strings.ToLower(line), "host") {
			t.Errorf("symptom line presents account.user.* without naming it a host event: %q", line)
		}
	}
}

// The DEK protects four kinds of secret and keys the job-queue HMAC. The
// summary, the procedure and the checklist must all say so.
func TestSecretRotation_DEKNamesEverythingItProtects(t *testing.T) {
	doc := readRunbook(t, "SECRET_ROTATION.md")

	glance := strings.ToLower(secRunbookSection(t, doc, "## Secrets at a glance"))
	for _, want := range []string{"ssh credential", "mfa", "notification channel", "sso", "job queue"} {
		if !strings.Contains(glance, want) {
			t.Errorf("Secrets at a glance does not name %q among what the DEK protects", want)
		}
	}

	dek := secRunbookSection(t, doc, "## Rotate the credential DEK")
	for _, want := range []string{
		// What a job queued under the old key ends with, so the operator
		// can recognize it.
		"hmac_rejected: signature does not match payload",
		"job_queue",
		"/api/v1/notifications/channels/{id}",
		"/api/v1/sso/providers/{id}",
		"maintenance_global",
	} {
		if !strings.Contains(dek, want) {
			t.Errorf("the DEK procedure does not mention %q", want)
		}
	}
	if strings.Contains(strings.ToLower(dek), "write a one-off program") {
		t.Error("the DEK procedure still tells operators to write their own re-encryption program; the product has no supported path for it")
	}

	checklist := strings.ToLower(secRunbookSection(t, doc, "## Post-rotation checklist"))
	for _, want := range []string{"notification channel", "sso provider"} {
		if !strings.Contains(checklist, want) {
			t.Errorf("the post-rotation checklist does not check %q after a DEK rotation", want)
		}
	}
}

// Idle-in-transaction backends include every running scan, holding its
// per-host advisory lock. The runbook must not call them safe to kill, and
// its termination query must skip advisory-lock holders.
func TestDatabaseIssues_IdleTransactionsAreNotSafeToKill(t *testing.T) {
	doc := readRunbook(t, "DATABASE_ISSUES.md")
	if regexp.MustCompile(`(?i)safe to kill`).MatchString(doc) {
		t.Error(`DATABASE_ISSUES.md still calls terminating backends "safe to kill"`)
	}

	pathB := secRunbookSection(t, doc, "### Path B: Connection pool exhaustion")
	if !strings.Contains(pathB, "advisory") {
		t.Error("Path B does not explain the per-host advisory lock that scans hold")
	}
	for _, b := range secRunbookFences(pathB) {
		if !strings.Contains(b, "pg_terminate_backend") || !strings.Contains(b, "idle in transaction") {
			continue
		}
		if !strings.Contains(b, "NOT EXISTS") || !strings.Contains(b, "locktype = 'advisory'") {
			t.Errorf("Path B terminates idle-in-transaction backends without excluding advisory-lock holders:\n%s", b)
		}
	}

	if regexp.MustCompile(`psql -U openwatch[^\n]*SHOW data_directory`).MatchString(doc) {
		t.Error("SHOW data_directory runs as the openwatch role, which lacks superuser and pg_read_all_settings")
	}
}

// The database credential rotation must change only the password. The old
// procedure replaced the whole DSN with 127.0.0.1:5432 and sslmode=require,
// which breaks a stock install (setup writes sslmode=disable) and any remote
// database.
func TestSecurityIncident_DBCredentialRotationKeepsTheDSN(t *testing.T) {
	doc := readRunbook(t, "SECURITY_INCIDENT.md")
	section := secRunbookSection(t, doc, "### Rotate the database credential")
	blocks := secRunbookFences(section)
	if len(blocks) == 0 {
		t.Fatal("the database credential rotation has no command block")
	}
	var script string
	checkAt, restartAt := -1, -1
	for i, b := range blocks {
		if checkAt < 0 && strings.Contains(b, "check-config") {
			checkAt = i
		}
		if restartAt < 0 && strings.Contains(b, "systemctl restart openwatch") {
			restartAt = i
		}
		for _, bad := range []string{"127.0.0.1:5432", "sslmode=require", "NEW_PASSWORD_HERE", "sed -i"} {
			if strings.Contains(b, bad) {
				t.Errorf("the database credential rotation hardcodes %q:\n%s", bad, b)
			}
		}
		if strings.Contains(b, "sudo python3 - <<'PY'") {
			script = b
		}
	}
	if checkAt < 0 || restartAt < 0 || checkAt >= restartAt {
		t.Errorf("the database credential rotation must run check-config in a block before the restart (check-config block %d, restart block %d)", checkAt, restartAt)
	}
	if script == "" {
		t.Fatal("the database credential rotation has no embedded python3 script")
	}

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed; the structural checks above still ran")
	}
	start := strings.Index(script, "<<'PY'\n") + len("<<'PY'\n")
	end := strings.Index(script, "\nPY\n")
	if end < start {
		t.Fatal("embedded script has no PY terminator")
	}
	py := script[start : end+1]

	dir := t.TempDir()
	env := filepath.Join(dir, "secrets.env")
	pwFile := filepath.Join(dir, "openwatch-db.password")
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The stub stands in for psql. Each call N records its arguments, the SQL
	// on stdin and the PGPASSWORD it received; PSQL_EXIT_N lets a case make
	// call N fail (1 is ALTER ROLE, 2 is the new-password check).
	stub := `#!/bin/sh
n=$(( $(cat "$STUB_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/count"
printf '%s\n' "$@" > "$STUB_DIR/args.$n"
cat > "$STUB_DIR/sql.$n"
printf '%s' "$PGPASSWORD" > "$STUB_DIR/pw.$n"
eval "code=\${PSQL_EXIT_$n:-0}"
[ "$n" = 2 ] && [ "$code" = 0 ] && echo ow_role
exit "$code"
`
	if err := os.WriteFile(filepath.Join(bin, "psql"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	py = strings.ReplaceAll(py, "/etc/openwatch/secrets.env", env)
	py = strings.ReplaceAll(py, "/root/openwatch-db.password", pwFile)
	if strings.Contains(py, "/etc/openwatch") || strings.Contains(py, "/root/") {
		t.Fatalf("script names a path the test did not redirect:\n%s", py)
	}

	const oldDSN = "postgres://ow_role:old%40pw@db.example.internal:6432/owdb?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem"
	const newPW = "n3w'p@ss/w:rd%#?&$x"
	original := "OPENWATCH_LOG_LEVEL=debug\nOPENWATCH_DATABASE_DSN=" + oldDSN + "\nOPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE=/k\n"

	run := func(failCall string) (string, error) {
		for _, f := range []string{"count", "args.1", "args.2", "sql.1", "sql.2", "pw.1", "pw.2"} {
			_ = os.Remove(filepath.Join(dir, f))
		}
		if err := os.WriteFile(env, []byte(original), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(env, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pwFile, []byte(newPW+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", "-")
		cmd.Stdin = strings.NewReader(py)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "STUB_DIR="+dir)
		if failCall != "" {
			cmd.Env = append(cmd.Env, "PSQL_EXIT_"+failCall+"=3")
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return string(b)
	}
	// Neither password may reach a command line: the DSN on psql's argv is
	// the current one without its password.
	noPasswordOnArgv := func(t *testing.T, call string) {
		t.Helper()
		args := read("args." + call)
		for _, secret := range []string{"old%40pw", "old@pw", newPW, url.QueryEscape(newPW), url.PathEscape(newPW)} {
			if strings.Contains(args, secret) {
				t.Errorf("psql call %s received a password on its command line:\n%s", call, args)
			}
		}
		if !strings.Contains(args, "postgres://ow_role@db.example.internal:6432/owdb?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem") {
			t.Errorf("psql call %s did not connect through the current DSN without its password:\n%s", call, args)
		}
	}

	t.Run("new password does not connect, file untouched", func(t *testing.T) {
		out, err := run("2")
		if err == nil || !strings.Contains(out, "secrets.env still holds the OLD one") {
			t.Fatalf("script did not stop on a failed new-password check (err %v):\n%s", err, out)
		}
		if got, _ := os.ReadFile(env); string(got) != original {
			t.Errorf("secrets.env changed although the new password did not connect:\n%s", got)
		}
	})

	t.Run("alter role fails, file untouched", func(t *testing.T) {
		out, err := run("1")
		if err == nil {
			t.Fatalf("script succeeded although ALTER ROLE failed:\n%s", out)
		}
		got, _ := os.ReadFile(env)
		if string(got) != original {
			t.Errorf("secrets.env changed although ALTER ROLE failed:\n%s", got)
		}
	})

	t.Run("only the password changes", func(t *testing.T) {
		out, err := run("0")
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		noPasswordOnArgv(t, "1")
		noPasswordOnArgv(t, "2")
		if read("pw.1") != "old@pw" || read("pw.2") != newPW {
			t.Errorf("ALTER ROLE must use the old password and the check the new one; got %q and %q", read("pw.1"), read("pw.2"))
		}
		sql := read("sql.1")
		if !strings.Contains(sql, "SET password_encryption = 'scram-sha-256'") ||
			!strings.Contains(sql, "ALTER ROLE CURRENT_USER WITH PASSWORD 'n3w''p@ss/w:rd%#?&$x'") {
			t.Errorf("unexpected SQL sent to psql:\n%s", sql)
		}
		if !strings.Contains(read("sql.2"), "SELECT current_user") {
			t.Errorf("the new password was not proven before secrets.env changed:\n%s", read("sql.2"))
		}

		got, err := os.ReadFile(env)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(got), "\n")
		if len(lines) != 4 || lines[0] != "OPENWATCH_LOG_LEVEL=debug" || lines[2] != "OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE=/k" {
			t.Fatalf("other secrets.env lines changed:\n%s", got)
		}
		dsn, ok := strings.CutPrefix(lines[1], "OPENWATCH_DATABASE_DSN=")
		if !ok {
			t.Fatalf("DSN line lost its key: %q", lines[1])
		}
		was, _ := url.Parse(oldDSN)
		now, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("new DSN does not parse: %v", err)
		}
		if pw, _ := now.User.Password(); pw != newPW {
			t.Errorf("password = %q, want %q", pw, newPW)
		}
		if now.User.Username() != was.User.Username() || now.Host != was.Host ||
			now.Path != was.Path || now.RawQuery != was.RawQuery || now.Scheme != was.Scheme {
			t.Errorf("DSN changed beyond the password:\n was %s\n now %s", oldDSN, dsn)
		}
		if fi, _ := os.Stat(env); fi.Mode().Perm() != 0o640 {
			t.Errorf("secrets.env mode = %o, want 640", fi.Mode().Perm())
		}
	})
}

// SECRET_ROTATION's database password section used to carry its own unsafe
// procedure (a password on the command line, a sed rewrite of the whole DSN).
// It must point to the validated procedure in SECURITY_INCIDENT instead, and
// the DEK rollback must say it is clean only before the first re-entry.
func TestSecretRotation_DatabasePasswordUsesTheValidatedProcedure(t *testing.T) {
	doc := readRunbook(t, "SECRET_ROTATION.md")
	section := secRunbookSection(t, doc, "## Rotate the database password")
	if !strings.Contains(section, "(SECURITY_INCIDENT.md#rotate-the-database-credential)") {
		t.Error("the database password section does not point to the validated procedure")
	}
	for _, bad := range []string{"sed -i", "ALTER ROLE", "new-strong-password", "127.0.0.1:5432"} {
		if strings.Contains(section, bad) {
			t.Errorf("the database password section still carries its own procedure: %q", bad)
		}
	}
	dek := secRunbookSection(t, doc, "## Rotate the credential DEK")
	for _, want := range []string{"before you re-enter the first secret", "It does not carry any\n> secret forward"} {
		if !strings.Contains(dek, want) {
			t.Errorf("the DEK procedure lacks %q", want)
		}
	}
	if strings.Contains(dek, "at any point before you delete the old key") {
		t.Error("the DEK rollback still claims to work at any point; it breaks re-entered secrets")
	}
}
