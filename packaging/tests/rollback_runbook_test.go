// Full-rollback runbook blocks. UPGRADE_PROCEDURE.md "Full rollback" restores
// the upgrade scriptlet's plain-SQL dump and reinstalls the previous packages.
// It is the only recovery path once a migration has run, so every block must
// stop on its own at the first bad input rather than rely on an operator
// noticing a printed error (CP bugs/OW-092), and a stop must never swap
// databases once package installation has begun.
//
// This test runs the blocks exactly as the runbook prints them. It extracts
// each fenced block from the Markdown, substitutes only the lines the
// operator fills in, and runs the rest byte for byte against a real
// PostgreSQL server, a schema built by this tree's migrations, and a dump
// taken with the scriptlet's own pg_dump flags (internal/dbbackup). dnf,
// apt-get, systemctl, journalctl, curl, rpm, dpkg and `openwatch --version`
// are stubs that record what they were asked to do. The real
// restart-and-load behavior step 6 guards against (CP bugs/OW-094) was
// observed on a host; here only its checks are exercised.
package packaging_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rollbackRunbook holds the four blocks the test runs.
type rollbackRunbook struct {
	main, preInstall, keepRestored, putBack string
}

// rollbackBlocks returns the rollback block and its three recovery blocks,
// each identified by a line only it carries.
func rollbackBlocks(t *testing.T, root string) rollbackRunbook {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "docs", "runbooks", "UPGRADE_PROCEDURE.md"))
	if err != nil {
		t.Fatalf("read UPGRADE_PROCEDURE.md: %v", err)
	}
	fenced := regexp.MustCompile("(?s)```bash\n(.*?)```").FindAllStringSubmatch(string(b), -1)
	pick := func(label string, match func(string) bool) string {
		var found []string
		for _, m := range fenced {
			if match(m[1]) {
				found = append(found, m[1])
			}
		}
		if len(found) != 1 {
			t.Fatalf("UPGRADE_PROCEDURE.md has %d %s blocks, want exactly one", len(found), label)
		}
		return found[0]
	}
	return rollbackRunbook{
		main: pick("rollback", func(s string) bool {
			return strings.Contains(s, "ASIDE=openwatch_pre_rollback") && strings.Contains(s, "PHASE=packages")
		}),
		preInstall: pick("pre-install recovery", func(s string) bool {
			return strings.Contains(s, "FAILED=openwatch_failed_restore") && !strings.Contains(s, "NEW_VERSION=")
		}),
		keepRestored: pick("keep-restored recovery", func(s string) bool { return strings.Contains(s, "OLD_VERSION=") }),
		putBack:      pick("put-back recovery", func(s string) bool { return strings.Contains(s, "NEW_VERSION=") }),
	}
}

// fillBlock replaces the named operator-filled input lines. Everything else
// in the block runs byte for byte as the runbook prints it.
func fillBlock(t *testing.T, block string, values map[string]string) string {
	t.Helper()
	out := block
	for name, v := range values {
		re := regexp.MustCompile(`(?m)^  ` + name + `='[^'\n]*<[^'\n]*'$`)
		if n := len(re.FindAllString(out, -1)); n != 1 {
			t.Fatalf("block has %d placeholder lines for %s, want 1", n, name)
		}
		out = re.ReplaceAllLiteralString(out, "  "+name+"='"+v+"'")
	}
	if strings.Contains(out, "='<") {
		t.Fatalf("a placeholder was left unfilled:\n%s", out)
	}
	return out
}

func TestUpgrade_FullRollbackRunbookBlock(t *testing.T) {
	root := repoRootForLinks(t)
	rb := rollbackBlocks(t, root)

	t.Run("the block is fail-fast and installs only after every check", func(t *testing.T) {
		mustAppear := []string{
			"set -euo pipefail",
			"PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)",
			"PHASE=inputs",
			"trap 'on_stop $LINENO' ERR",
			`[[ "$HEAD" == *"-- PostgreSQL database dump"* ]]`,
			`[[ "$TAIL" == *"-- PostgreSQL database dump complete"* ]]`,
			"PHASE=database",
			`ALTER DATABASE openwatch RENAME TO $ASIDE`,
			`-1 -d openwatch -c 'SET ROLE openwatch' -f - < "$DUMP"`,
			`[ "$GOT" = "$EXPECTED" ]`,
			`[ "$FOREIGN" = 0 ]`,
			"PHASE=packages",
			`dnf install -y "$OLD_OPENWATCH" "$OLD_KENSA"`,
			"systemctl restart openwatch",
			`[[ "$LOG" != *"kensa scan wiring unavailable"* ]]`,
			`[[ "$LOG" != *"kensa rule library unavailable"* ]]`,
			`[ "$RULES" = 200 ]`,
			"ROLLED BACK",
		}
		last := -1
		for _, s := range mustAppear {
			i := strings.Index(rb.main, s)
			if i < 0 {
				t.Fatalf("rollback block lacks %q", s)
			}
			if i < last {
				t.Fatalf("rollback block has %q out of order", s)
			}
			last = i
		}
		for _, block := range []string{rb.main, rb.preInstall, rb.keepRestored, rb.putBack} {
			for _, forbidden := range []string{"DROP DATABASE", "dropdb", "test -z \"$("} {
				if strings.Contains(block, forbidden) {
					t.Fatalf("a rollback runbook block contains %q", forbidden)
				}
			}
		}
		// Every block that prints a success marker proves the rule library
		// loaded first (CP bugs/OW-094): restart, bounded health wait, both
		// journal checks, the authenticated rules probe, then the ERR trap
		// cleared immediately before the success line.
		successRE := regexp.MustCompile(`(?m)^  echo "(ROLLED BACK|RESTORED|KEPT):`)
		for label, block := range map[string]string{"rollback": rb.main, "pre-install": rb.preInstall,
			"keep-restored": rb.keepRestored, "put-back": rb.putBack} {
			loc := successRE.FindStringIndex(block)
			if loc == nil {
				t.Fatalf("%s block prints no success marker", label)
			}
			before := block[:loc[0]]
			last := -1
			for _, want := range []string{
				"systemctl restart openwatch",
				`DEADLINE=$((SECONDS + `,
				`while [ "$SECONDS" -lt "$DEADLINE" ]; do`,
				`"$URL/api/v1/health"`,
				`[ "$READY" = yes ]`,
				`[[ "$LOG" != *"kensa scan wiring unavailable"* ]]`,
				`[[ "$LOG" != *"kensa rule library unavailable"* ]]`,
				`-K - "$URL/api/v1/rules"`,
				`[ "$RULES" = 200 ]`,
			} {
				i := strings.Index(before, want)
				if i < 0 || i < last {
					t.Fatalf("%s block prints its success marker without %q before it, in order", label, want)
				}
				last = i
			}
			if !strings.HasSuffix(strings.TrimRight(before, " "), "trap - ERR\n") {
				t.Fatalf("%s block does not clear the ERR trap immediately before its success line", label)
			}
			if !strings.Contains(block, `[[ "$TOKEN" == owk_* ]]`) || !strings.Contains(block, "TOKEN_FILE='<") {
				t.Fatalf("%s block lacks the token input and its owk_ guard", label)
			}
		}

		// Every health and rules request carries both curl timeouts, and the
		// wait the runbook documents equals the one the blocks implement:
		// deadline + one last request's --max-time + one pause.
		book, err := os.ReadFile(filepath.Join(root, "docs", "runbooks", "UPGRADE_PROCEDURE.md"))
		if err != nil {
			t.Fatal(err)
		}
		doc := regexp.MustCompile(`The health wait gives up after at most \*\*(\d+) seconds\*\*: a\s+(\d+)-second deadline, ` +
			`plus one last request of at most (\d+) seconds and a (\d+)-second\s+pause\. The rules check then\s+gives up ` +
			`after at most \*\*(\d+) seconds\*\*`).FindStringSubmatch(regexp.MustCompile(`\s+`).ReplaceAllString(string(book), " "))
		if doc == nil {
			t.Fatal("UPGRADE_PROCEDURE.md does not state the health and rules bounds in the expected sentence")
		}
		num := func(s string) int { n, _ := strconv.Atoi(s); return n }
		docTotal, docDeadline, docMax, docPause, docRules := num(doc[1]), num(doc[2]), num(doc[3]), num(doc[4]), num(doc[5])
		if docTotal != docDeadline+docMax+docPause {
			t.Fatalf("the runbook says %d seconds, but %d + %d + %d = %d", docTotal, docDeadline, docMax, docPause, docDeadline+docMax+docPause)
		}
		curlRE := regexp.MustCompile(`(?m)^.*curl .*"\$URL/api/v1/(health|rules)".*$`)
		maxRE := regexp.MustCompile(`--max-time (\d+)`)
		for label, block := range map[string]string{"rollback": rb.main, "pre-install": rb.preInstall,
			"keep-restored": rb.keepRestored, "put-back": rb.putBack} {
			lines := curlRE.FindAllString(block, -1)
			if len(lines) != 2 {
				t.Fatalf("%s block has %d health/rules curl lines, want 2", label, len(lines))
			}
			for _, l := range lines {
				m := maxRE.FindStringSubmatch(l)
				if !strings.Contains(l, "--connect-timeout ") || m == nil {
					t.Fatalf("%s block curl lacks --connect-timeout or --max-time: %s", label, strings.TrimSpace(l))
				}
				want := docMax
				if strings.Contains(l, "/api/v1/rules") {
					want = docRules
				}
				if num(m[1]) != want {
					t.Fatalf("%s block curl --max-time %s, the runbook says %d: %s", label, m[1], want, strings.TrimSpace(l))
				}
			}
			dl := regexp.MustCompile(`DEADLINE=\$\(\(SECONDS \+ (\d+)\)\)`).FindStringSubmatch(block)
			pause := regexp.MustCompile(`(?m)^    sleep (\d+)$`).FindStringSubmatch(block)
			if dl == nil || pause == nil || num(dl[1]) != docDeadline || num(pause[1]) != docPause {
				t.Fatalf("%s block deadline %v or pause %v disagrees with the runbook (%d, %d)", label, dl, pause, docDeadline, docPause)
			}
		}

		// A stop after installation began must never rename a database.
		packagesBranch := rb.main[strings.Index(rb.main, "packages)"):strings.Index(rb.main, "esac")]
		if strings.Contains(packagesBranch, "RENAME") || strings.Contains(packagesBranch, "ALTER DATABASE") {
			t.Fatal("the post-install stop handler renames a database")
		}
	})

	t.Run("containers", func(t *testing.T) {
		image := os.Getenv("OPENWATCH_ROLLBACK_IMAGE")
		if image == "" {
			t.Skip("set OPENWATCH_ROLLBACK_IMAGE (for example postgres:16) to run the rollback blocks against PostgreSQL")
		}
		haveTool(t, "docker")
		runRollbackCases(t, root, image, rb)
	})
}

type rollbackRig struct {
	t         *testing.T
	container string
	work      string
}

// sh runs a shell command in the container as root and returns its output
// and exit status.
func (r *rollbackRig) sh(script string) (string, int) {
	r.t.Helper()
	out, err := exec.Command("docker", "exec", r.container, "bash", "-c", script).CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	r.t.Fatalf("docker exec: %v", err)
	return "", -1
}

// must runs a setup command and fails the test on a non-zero exit.
func (r *rollbackRig) must(script string) string {
	r.t.Helper()
	out, code := r.sh(script)
	if code != 0 {
		r.t.Fatalf("setup command failed (exit %d): %s\n%s", code, script, out)
	}
	return strings.TrimSpace(out)
}

func (r *rollbackRig) query(db, sql string) string {
	r.t.Helper()
	return r.must(fmt.Sprintf("runuser -u postgres -- psql -X -tA -v ON_ERROR_STOP=1 -d %s -c %q", db, sql))
}

// databases returns the rollback-related databases that exist, sorted.
func (r *rollbackRig) databases() string {
	return strings.ReplaceAll(r.query("postgres", "SELECT string_agg(datname, ',' ORDER BY datname) FROM pg_database "+
		"WHERE datname IN ('openwatch', 'openwatch_pre_rollback', 'openwatch_failed_restore')"), "\n", "")
}

// isOriginal reports whether db is the pre-rollback database, which alone
// carries the sentinel table reset() adds.
func (r *rollbackRig) isOriginal(db string) bool {
	return r.query(db, "SELECT count(*) FROM pg_tables WHERE tablename = 'rollback_sentinel'") == "1"
}

// reset builds the "current" database the rollback replaces: the fixture
// schema plus a sentinel table, owned by openwatch. It removes every database
// a previous case left behind, and the stub call log.
func (r *rollbackRig) reset() {
	r.t.Helper()
	for _, db := range []string{"openwatch", "openwatch_pre_rollback", "openwatch_failed_restore"} {
		r.must("runuser -u postgres -- dropdb --if-exists " + db)
	}
	r.must("runuser -u postgres -- createdb -O openwatch openwatch")
	r.must("runuser -u postgres -- psql -X -q -1 -v ON_ERROR_STOP=1 -d openwatch -c 'SET ROLE openwatch' -f /work/good.sql")
	r.must(`runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -d openwatch -c 'SET ROLE openwatch' ` +
		`-c "CREATE TABLE rollback_sentinel (v text)" -c "INSERT INTO rollback_sentinel VALUES ('current')"`)
	r.clearCalls()
}

func (r *rollbackRig) clearCalls() { r.must("rm -f /work/called /work/journal.txt") }

// run writes and runs a block with the given stubs directory first on PATH
// and extra environment for the stubs. It returns the exit status, the output
// and the stub call log.
func (r *rollbackRig) run(block, stubs, env string) (int, string, string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.work, "case.sh"), []byte(block), 0o644); err != nil {
		r.t.Fatal(err)
	}
	out, code := r.sh("env " + env + " PATH=/work/" + stubs + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash /work/case.sh")
	called, _ := r.sh("cat /work/called 2>/dev/null")
	return code, out, called
}

func runRollbackCases(t *testing.T, root, image string, rb rollbackRunbook) {
	work := t.TempDir()
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}

	// Build this tree's binary to create a real schema with its migrations.
	build := exec.Command("go", "build", "-o", filepath.Join(work, "openwatch-real"), "./cmd/openwatch")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build openwatch: %v\n%s", err, out)
	}

	// Stubs record their name and arguments in /work/called.
	//   curl:      the health probe (-skf) exits HEALTH_EXIT, default 0; the rules probe (-w) prints RULES_CODE, default 200.
	//   dnf:       exits DNF_EXIT, default 0.
	//   rpm:       `rpm -V` prints nothing and exits RPM_V_EXIT, default 0.
	//   openwatch: `--version` prints "openwatch $OW_VERSION".
	//   journalctl prints /work/journal.txt when a case wrote one.
	record := func(name string) string { return "#!/bin/sh\necho \"" + name + " $*\" >> /work/called\n" }
	stubBody := map[string]string{
		"systemctl":  record("systemctl") + "exit 0\n",
		"dnf":        record("dnf") + "exit ${DNF_EXIT:-0}\n",
		"apt-get":    record("apt-get") + "exit 0\n",
		"rpm":        record("rpm") + "exit ${RPM_V_EXIT:-0}\n",
		"dpkg":       record("dpkg") + "exit 0\n",
		"openwatch":  record("openwatch") + "echo \"openwatch ${OW_VERSION:-unset}\"\necho \"  commit:    stub\"\nexit 0\n",
		"journalctl": record("journalctl") + "[ -f /work/journal.txt ] && cat /work/journal.txt\nexit 0\n",
		// curl emulates --max-time: with HEALTH_HANG or RULES_HANG set, the
		// request "hangs" for its --max-time and exits 28 as curl does, or for
		// HANG_SECONDS (default 600) when the flag is missing. Real curl's
		// enforcement is not exercised (the image has no curl).
		"curl": "#!/bin/bash\necho \"curl $*\" >> /work/called\ncat >/dev/null 2>&1 || :\n" +
			"mt=\"\"; prev=\"\"; for a in \"$@\"; do [ \"$prev\" = --max-time ] && mt=$a; prev=$a; done\n" +
			"hang() { sleep \"${mt:-${HANG_SECONDS:-600}}\"; [ \"$1\" = rules ] && printf 000; exit 28; }\n" +
			"case \" $* \" in\n" +
			"  *\" -w \"*) [ -n \"${RULES_HANG:-}\" ] && hang rules; printf '%s' \"${RULES_CODE:-200}\" ;;\n" +
			"  *\" -skf \"*) [ -n \"${HEALTH_HANG:-}\" ] && hang health; exit ${HEALTH_EXIT:-0} ;;\n" +
			"esac\nexit 0\n",
	}
	for dir, names := range map[string][]string{
		"stubs-dnf": {"systemctl", "dnf", "apt-get", "journalctl", "curl", "rpm", "dpkg", "openwatch"},
		"stubs-apt": {"systemctl", "apt-get", "journalctl", "curl", "dpkg", "openwatch"},
	} {
		if err := os.MkdirAll(filepath.Join(work, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(work, dir, n), []byte(stubBody[n]), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, f := range []string{"old-openwatch.pkg", "old-kensa-rules.pkg"} {
		if err := os.WriteFile(filepath.Join(work, f), []byte("previous package stand-in\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const token = "owk_rollback-test-not-a-real-token"
	if err := os.WriteFile(filepath.Join(work, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	name := "ow-rollback-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	// --init: the postgres image runs the postmaster as PID 1, and a process
	// the test leaves in the background would otherwise be re-parented to it;
	// its exit then reads as a crashed server child and restarts PostgreSQL.
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--init", "--name", name,
		"-e", "POSTGRES_PASSWORD=postgres-test-only", "-v", work+":/work", image).CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	rig := &rollbackRig{t: t, container: name, work: work}

	ready := false
	for i := 0; i < 60; i++ {
		if _, code := rig.sh("pg_isready -h 127.0.0.1 -q"); code == 0 {
			ready = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ready {
		t.Fatal("PostgreSQL did not become ready within 60s")
	}

	// A real schema, owned by openwatch, from this tree's migrations; then a
	// dump with the scriptlet's flags (internal/dbbackup dumpArgs).
	rig.must(`runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -c "CREATE ROLE openwatch LOGIN PASSWORD 'openwatch-test-only'"`)
	rig.must("runuser -u postgres -- createdb -O openwatch openwatch")
	rig.must("OPENWATCH_DATABASE_DSN='postgres://openwatch:openwatch-test-only@127.0.0.1:5432/openwatch?sslmode=disable' /work/openwatch-real migrate")
	rig.must("PGHOST=127.0.0.1 PGUSER=openwatch PGPASSWORD=openwatch-test-only PGDATABASE=openwatch " +
		"pg_dump --no-owner --no-privileges -f /work/good.sql")
	expected := rig.query("openwatch", "SELECT max(version_id) FROM goose_db_version")
	t.Logf("fixture schema at migration version %s", expected)

	// Damaged dumps. nomarker.sql loses the completion line. badcopy.sql keeps
	// the header and the completion line but corrupts one COPY row, so only
	// psql can catch it.
	rig.must("grep -v '^-- PostgreSQL database dump complete' /work/good.sql > /work/nomarker.sql")
	rig.must(`awk 'c==1 && !done {print "not-a-number\tbroken"; done=1; next} /^COPY public.goose_db_version/ {c=1} {print}' /work/good.sql > /work/badcopy.sql`)
	if !strings.Contains(rig.must("tail -n 5 /work/badcopy.sql"), "dump complete") {
		t.Fatal("badcopy.sql fixture lost its completion line")
	}

	fill := func(dump, exp string) string {
		return fillBlock(t, rb.main, map[string]string{
			"DUMP": dump, "EXPECTED": exp,
			"OLD_OPENWATCH": "/work/old-openwatch.pkg", "OLD_KENSA": "/work/old-kensa-rules.pkg",
			"TOKEN_FILE": "/work/token",
		})
	}
	preInstall := fillBlock(t, rb.preInstall, map[string]string{"TOKEN_FILE": "/work/token"})
	keep := func(oldVersion string) string {
		return fillBlock(t, rb.keepRestored, map[string]string{"OLD_VERSION": oldVersion, "EXPECTED": expected, "TOKEN_FILE": "/work/token"})
	}
	putBack := func(newVersion string) string {
		return fillBlock(t, rb.putBack, map[string]string{"NEW_VERSION": newVersion, "TOKEN_FILE": "/work/token"})
	}
	successMarker := regexp.MustCompile(`(?m)^(ROLLED BACK|RESTORED|KEPT):`)
	installed := func(called string) bool {
		return strings.Contains(called, "dnf install") || strings.Contains(called, "apt-get install")
	}
	logCase := func(label string, code int, called string) {
		t.Helper()
		if strings.Contains(called, token) {
			t.Fatalf("case %s: the API token reached a command line: %q", label, called)
		}
		t.Logf("case %s: exit=%d dbs=[%s] calls=%q", label, code, rig.databases(), strings.TrimSpace(called))
	}
	lastSystemctl := func(called string) string {
		var last string
		for _, l := range strings.Split(called, "\n") {
			if strings.HasPrefix(l, "systemctl ") {
				last = l
			}
		}
		return last
	}

	t.Run("a happy path, dnf", func(t *testing.T) {
		rig.reset()
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", "")
		logCase("a/dnf", code, called)
		if code != 0 || !strings.Contains(out, "rule library loaded") {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
		if !strings.Contains(called, "dnf install -y /work/old-openwatch.pkg /work/old-kensa-rules.pkg") ||
			!strings.Contains(called, "systemctl restart openwatch") ||
			strings.Index(called, "dnf install") > strings.Index(called, "systemctl restart") ||
			!strings.Contains(called, "/api/v1/rules") {
			t.Fatalf("install, restart and rules probe not recorded in order: %q", called)
		}
		if got := rig.query("openwatch", "SELECT max(version_id) FROM goose_db_version"); got != expected {
			t.Fatalf("restored migration version %s, want %s", got, expected)
		}
		foreign := rig.query("openwatch", "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "+
			"WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) <> 'openwatch'")
		if foreign != "0" || rig.isOriginal("openwatch") || !rig.isOriginal("openwatch_pre_rollback") {
			t.Fatalf("foreign-owned %s; want the restored database as openwatch and the original aside", foreign)
		}
	})

	t.Run("a happy path, apt-get when dnf is absent", func(t *testing.T) {
		rig.reset()
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-apt", "")
		logCase("a/apt", code, called)
		if code != 0 || !strings.Contains(called, "apt-get install -y --allow-downgrades /work/old-openwatch.pkg /work/old-kensa-rules.pkg") {
			t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
		}
	})

	// Phase inputs: nothing may change, not even a stop.
	for _, c := range []struct{ label, dump string }{
		{"b missing dump", "/work/missing.sql"},
		{"c1 dump without the completion line", "/work/nomarker.sql"},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			code, out, called := rig.run(fill(c.dump, expected), "stubs-dnf", "")
			logCase(c.label, code, called)
			if code == 0 || called != "" || !strings.Contains(out, "phase: inputs") {
				t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
			}
			if rig.databases() != "openwatch" || !rig.isOriginal("openwatch") {
				t.Fatal("the current database was changed by a block that stopped on its inputs")
			}
		})
	}

	// Phase database: the aside database must be intact, nothing may be
	// installed or started, and the pre-install recovery must put it back.
	for _, c := range []struct {
		label, dump, exp string
		setup, teardown  string
	}{
		{label: "c2 corrupt COPY row, psql fails", dump: "/work/badcopy.sql", exp: expected},
		{label: "d wrong expected migration version", dump: "/work/good.sql", exp: decrement(t, expected)},
		{label: "e an object not owned by openwatch", dump: "/work/good.sql", exp: expected,
			setup:    `runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d template1 -c "CREATE TABLE public.foreign_owned (x int)"`,
			teardown: `runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d template1 -c "DROP TABLE public.foreign_owned"`},
		{label: "i createdb fails after the rename", dump: "/work/good.sql", exp: expected,
			// A session on template1 makes createdb fail: "source database
			// template1 is being accessed by other users".
			setup:    `(runuser -u postgres -- psql -X -d template1 -c 'SELECT pg_sleep(30)' >/dev/null 2>&1 &) ; sleep 1`,
			teardown: `runuser -u postgres -- psql -X -tA -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'template1'" >/dev/null`},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			if c.setup != "" {
				rig.must(c.setup)
			}
			code, out, called := rig.run(fill(c.dump, c.exp), "stubs-dnf", "")
			if c.teardown != "" {
				rig.must(c.teardown)
			}
			logCase(c.label, code, called)
			if code == 0 || installed(called) || strings.Contains(called, "systemctl restart") || strings.Contains(called, "systemctl start") {
				t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
			}
			if !strings.Contains(out, "phase: database") || !strings.Contains(out, "Recover before package installation") {
				t.Fatalf("stop message does not name phase database and its recovery:\n%s", out)
			}
			if !rig.isOriginal("openwatch_pre_rollback") {
				t.Fatal("the aside database is not intact")
			}
			wantBefore := "openwatch,openwatch_pre_rollback"
			if strings.HasPrefix(c.label, "i ") {
				wantBefore = "openwatch_pre_rollback" // no replacement database was created
			}
			if got := rig.databases(); got != wantBefore {
				t.Fatalf("databases after the stop = [%s], want [%s]", got, wantBefore)
			}

			rig.clearCalls()
			rcode, rout, rcalled := rig.run(preInstall, "stubs-dnf", "")
			logCase(c.label+" / pre-install recovery", rcode, rcalled)
			if rcode != 0 || !strings.Contains(rout, "RESTORED") {
				t.Fatalf("pre-install recovery exit %d:\n%s", rcode, rout)
			}
			if !rig.isOriginal("openwatch") || lastSystemctl(rcalled) != "systemctl restart openwatch" ||
				!strings.Contains(rcalled, "/api/v1/rules") {
				t.Fatalf("recovery did not put the original back, restart and probe the rules: %q", rcalled)
			}
			wantAfter := "openwatch,openwatch_failed_restore"
			if strings.HasPrefix(c.label, "i ") {
				wantAfter = "openwatch"
			}
			if got := rig.databases(); got != wantAfter {
				t.Fatalf("databases after recovery = [%s], want [%s]", got, wantAfter)
			}
		})
	}

	t.Run("i2 stop before the rename, then pre-install recovery renames nothing", func(t *testing.T) {
		rig.reset()
		// A session held on openwatch fails the open-connections check, so the
		// block stops in phase database after stopping the service and before
		// the rename.
		rig.must(`(runuser -u postgres -- psql -X -d openwatch -c 'SELECT pg_sleep(30)' >/dev/null 2>&1 &) ; sleep 1`)
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", "")
		rig.must(`runuser -u postgres -- psql -X -tA -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'openwatch'" >/dev/null`)
		logCase("i2 rollback", code, called)
		if code == 0 || !strings.Contains(out, "phase: database") || called != "systemctl stop openwatch\n" {
			t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
		}
		if got := rig.databases(); got != "openwatch" || !rig.isOriginal("openwatch") {
			t.Fatalf("databases [%s]; the original must still be openwatch", got)
		}
		rig.clearCalls()
		rcode, rout, rcalled := rig.run(preInstall, "stubs-dnf", "")
		logCase("i2 pre-install recovery", rcode, rcalled)
		if rcode != 0 || !strings.Contains(rout, "RESTORED") || strings.Contains(rcalled, "systemctl stop") ||
			lastSystemctl(rcalled) != "systemctl restart openwatch" || !strings.Contains(rcalled, "/api/v1/rules") {
			t.Fatalf("recovery exit %d, calls %q, output:\n%s", rcode, rcalled, rout)
		}
		if got := rig.databases(); got != "openwatch" || !rig.isOriginal("openwatch") {
			t.Fatalf("databases [%s]; want the original as openwatch and nothing renamed", got)
		}
	})

	t.Run("ii recovery name already taken", func(t *testing.T) {
		rig.reset()
		code, _, called := rig.run(fill("/work/good.sql", decrement(t, expected)), "stubs-dnf", "")
		logCase("ii rollback", code, called)
		rig.must("runuser -u postgres -- createdb -O openwatch openwatch_failed_restore")
		before := rig.databases()
		rig.clearCalls()
		rcode, rout, rcalled := rig.run(preInstall, "stubs-dnf", "")
		logCase("ii pre-install recovery", rcode, rcalled)
		if rcode == 0 || !strings.Contains(rout, "openwatch_failed_restore is already taken") {
			t.Fatalf("recovery exit %d, want a stop naming the taken name:\n%s", rcode, rout)
		}
		if rcalled != "" {
			t.Fatalf("recovery acted before refusing: %q", rcalled)
		}
		if after := rig.databases(); after != before || rig.isOriginal("openwatch") || !rig.isOriginal("openwatch_pre_rollback") {
			t.Fatalf("databases changed: before [%s] after [%s]", before, after)
		}
	})

	// Phase packages: the block stops the service and swaps nothing; the
	// operator inspects and chooses.
	packagesStop := func(t *testing.T, label, env string) {
		t.Helper()
		rig.reset()
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", env)
		logCase(label, code, called)
		if code == 0 || strings.Contains(out, "ROLLED BACK") {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
		if !strings.Contains(out, "phase: packages") || !strings.Contains(out, "No database was swapped back") ||
			!strings.Contains(out, "Recover after package installation began") {
			t.Fatalf("stop message does not name phase packages and its recovery:\n%s", out)
		}
		if !strings.Contains(called, "dnf install") || lastSystemctl(called) != "systemctl stop openwatch" {
			t.Fatalf("want the install attempted and the service stopped last: %q", called)
		}
		if got := rig.databases(); got != "openwatch,openwatch_pre_rollback" || rig.isOriginal("openwatch") || !rig.isOriginal("openwatch_pre_rollback") {
			t.Fatalf("databases [%s]: a database was swapped automatically", got)
		}
	}

	t.Run("iii package transaction fails, then keep the restored database", func(t *testing.T) {
		packagesStop(t, "iii/keep rollback", "DNF_EXIT=1")
		rig.clearCalls()
		code, out, called := rig.run(keep("0.7.1"), "stubs-dnf", "OW_VERSION=0.7.1")
		logCase("iii/keep recovery", code, called)
		if code != 0 || !strings.Contains(out, "KEPT") || !strings.Contains(called, "rpm -V kensa-rules") ||
			lastSystemctl(called) != "systemctl restart openwatch" {
			t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
		}
		if got := rig.databases(); got != "openwatch,openwatch_pre_rollback" || rig.isOriginal("openwatch") {
			t.Fatalf("databases [%s]; want the restored database kept as openwatch", got)
		}
	})

	t.Run("iii package transaction fails, keep refused while the newer version is installed", func(t *testing.T) {
		packagesStop(t, "iii/keep-refused rollback", "DNF_EXIT=1")
		rig.clearCalls()
		code, _, called := rig.run(keep("0.7.1"), "stubs-dnf", "OW_VERSION=0.8.0")
		logCase("iii/keep-refused recovery", code, called)
		if code == 0 || strings.Contains(called, "systemctl") {
			t.Fatalf("keep-restored ran with the newer version installed: exit %d, calls %q", code, called)
		}
	})

	t.Run("iii package transaction fails, then put the original back", func(t *testing.T) {
		packagesStop(t, "iii/put-back rollback", "DNF_EXIT=1")
		rig.clearCalls()
		code, out, called := rig.run(putBack("0.8.0"), "stubs-dnf", "OW_VERSION=0.8.0")
		logCase("iii/put-back recovery", code, called)
		if code != 0 || !strings.Contains(out, "RESTORED") || lastSystemctl(called) != "systemctl restart openwatch" ||
			!strings.Contains(called, "/api/v1/rules") {
			t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
		}
		if got := rig.databases(); got != "openwatch,openwatch_failed_restore" || !rig.isOriginal("openwatch") {
			t.Fatalf("databases [%s]; want the original back as openwatch", got)
		}
	})

	// Every recovery block proves the rule library loaded before it prints
	// success. Inject each verification failure into each block: it must
	// exit non-zero, print no success marker, stop the service, and leave
	// the databases as that block intends. Nothing is dropped.
	type recoveryPath struct {
		label      string
		rollback   string // env for the rollback run that sets up the state
		rollExp    string
		block      string
		env        string // env the recovery block runs with
		wantDBs    string
		wantOrigOW bool // true when openwatch must be the original database
	}
	paths := []recoveryPath{
		{label: "pre-install", rollExp: decrement(t, expected), block: preInstall,
			wantDBs: "openwatch,openwatch_failed_restore", wantOrigOW: true},
		{label: "keep-restored", rollback: "DNF_EXIT=1", rollExp: expected, block: keep("0.7.1"), env: "OW_VERSION=0.7.1",
			wantDBs: "openwatch,openwatch_pre_rollback", wantOrigOW: false},
		{label: "put-back", rollback: "DNF_EXIT=1", rollExp: expected, block: putBack("0.8.0"), env: "OW_VERSION=0.8.0",
			wantDBs: "openwatch,openwatch_failed_restore", wantOrigOW: true},
	}
	faults := []struct{ label, journal, env string }{
		{label: "a health timeout", env: "HEALTH_EXIT=7"},
		{label: "b scan wiring warning", journal: "kensa scan wiring unavailable — on-demand scans will fail\n"},
		{label: "c rule library warning", journal: "kensa rule library unavailable; /api/v1/rules disabled\n"},
		{label: "d rules answers 503", env: "RULES_CODE=503"},
		{label: "d rules answers 401, token not valid in the selected database", env: "RULES_CODE=401"},
	}
	for _, p := range paths {
		for _, f := range faults {
			p, f := p, f
			t.Run("recovery "+p.label+" "+f.label, func(t *testing.T) {
				rig.reset()
				// Recorded harness failure (PR #888, run 4, 2026-09-30): in one full
				// run the setup rollback for "pre-install / d rules answers 503"
				// stopped before creating the aside, so the recovery found nothing
				// to put back. The setup output was not captured then; this
				// assertion and its message now capture it. A hypothesis (a
				// just-closed session still listed in pg_stat_activity) did not
				// reproduce in 200 tries. See the PR description for later runs.
				code, sout, called := rig.run(fill("/work/good.sql", p.rollExp), "stubs-dnf", p.rollback)
				wantPhase := "phase: database"
				if p.rollback != "" {
					wantPhase = "phase: packages"
				}
				if code == 0 || !strings.Contains(sout, wantPhase) || !rig.isOriginal("openwatch_pre_rollback") {
					t.Fatalf("setup rollback: exit %d, want a stop in %s with the aside intact; calls %q, dbs [%s]\n%s",
						code, wantPhase, called, rig.databases(), sout)
				}
				rig.clearCalls()
				if f.journal != "" {
					if err := os.WriteFile(filepath.Join(work, "journal.txt"), []byte(f.journal), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				rcode, rout, rcalled := rig.run(p.block, "stubs-dnf", strings.TrimSpace(p.env+" "+f.env))
				logCase("recovery "+p.label+" / "+f.label, rcode, rcalled)
				if rcode == 0 || successMarker.MatchString(rout) {
					t.Fatalf("exit %d with a success line or zero exit:\n%s", rcode, rout)
				}
				if !strings.Contains(rout, "stage: verify") || lastSystemctl(rcalled) != "systemctl stop openwatch" ||
					!strings.Contains(rcalled, "systemctl restart openwatch") {
					t.Fatalf("want a verify-stage stop after the restart, service stopped last: %q\n%s", rcalled, rout)
				}
				if got := rig.databases(); got != p.wantDBs || rig.isOriginal("openwatch") != p.wantOrigOW {
					t.Fatalf("databases [%s], openwatch original=%v; want [%s], original=%v",
						got, rig.isOriginal("openwatch"), p.wantDBs, p.wantOrigOW)
				}
				if strings.Contains(rout, token) {
					t.Fatal("the token was printed")
				}
			})
		}
	}

	// Exact version match: keep-restored and put-back compare the second word
	// of the first `openwatch --version` line for equality. A near miss must
	// refuse before touching the service or any database.
	for _, c := range []struct {
		label, installed, want string
		keepBlock              bool
	}{
		{"keep-restored refuses 0.7.10 for 0.7.1", "0.7.10", "0.7.1", true},
		{"keep-restored refuses 0.8.1-rc.2 for 0.8.1", "0.8.1-rc.2", "0.8.1", true},
		{"keep-restored refuses 0.8.1 for 0.8.1-rc.2", "0.8.1", "0.8.1-rc.2", true},
		{"put-back refuses 0.8.10 for 0.8.1", "0.8.10", "0.8.1", false},
		{"put-back refuses 0.8.1-rc.2 for 0.8.1", "0.8.1-rc.2", "0.8.1", false},
		{"put-back refuses 0.8.1 for 0.8.1-rc.2", "0.8.1", "0.8.1-rc.2", false},
	} {
		c := c
		t.Run("version "+c.label, func(t *testing.T) {
			packagesStop(t, "version "+c.label+" rollback", "DNF_EXIT=1")
			before := rig.databases()
			rig.clearCalls()
			block := putBack(c.want)
			if c.keepBlock {
				block = keep(c.want)
			}
			code, out, called := rig.run(block, "stubs-dnf", "OW_VERSION="+c.installed)
			logCase("version "+c.label, code, called)
			if code == 0 || successMarker.MatchString(out) || !strings.Contains(out, "installed openwatch is "+c.installed+", not "+c.want) {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			if called != "openwatch --version\n" {
				t.Fatalf("the block acted beyond reading the version: %q", called)
			}
			if after := rig.databases(); after != before || rig.isOriginal("openwatch") {
				t.Fatalf("databases changed: [%s] -> [%s]", before, after)
			}
		})
	}
	t.Run("version put-back accepts an exact pre-release match", func(t *testing.T) {
		packagesStop(t, "version exact pre-release rollback", "DNF_EXIT=1")
		rig.clearCalls()
		code, out, called := rig.run(putBack("0.8.1-rc.2"), "stubs-dnf", "OW_VERSION=0.8.1-rc.2")
		logCase("version exact pre-release", code, called)
		if code != 0 || !strings.Contains(out, "RESTORED") || !rig.isOriginal("openwatch") {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
	})

	// Request timeouts: every health and rules curl carries --max-time, so a
	// hanging endpoint ends the block within the documented bound. Health:
	// 60 s deadline + 5 s request + 2 s pause = 67 s. Rules: 5 s. The margin
	// covers the database work before the checks.
	const margin = 12 * time.Second
	type timeoutBlock struct {
		label   string
		setup   func(t *testing.T)
		block   string
		env     string
		wantDBs string
		origOW  bool
	}
	timeoutBlocks := []timeoutBlock{
		{label: "rollback", setup: func(t *testing.T) { rig.reset() }, block: fill("/work/good.sql", expected),
			wantDBs: "openwatch,openwatch_pre_rollback", origOW: false},
		{label: "pre-install", setup: func(t *testing.T) {
			rig.reset()
			if code, _, _ := rig.run(fill("/work/good.sql", decrement(t, expected)), "stubs-dnf", ""); code == 0 {
				t.Fatal("setup rollback did not stop")
			}
			rig.clearCalls()
		}, block: preInstall, wantDBs: "openwatch,openwatch_failed_restore", origOW: true},
		{label: "keep-restored", setup: func(t *testing.T) { packagesStop(t, "timeout keep setup", "DNF_EXIT=1"); rig.clearCalls() },
			block: keep("0.7.1"), env: "OW_VERSION=0.7.1", wantDBs: "openwatch,openwatch_pre_rollback", origOW: false},
		{label: "put-back", setup: func(t *testing.T) { packagesStop(t, "timeout put setup", "DNF_EXIT=1"); rig.clearCalls() },
			block: putBack("0.8.0"), env: "OW_VERSION=0.8.0", wantDBs: "openwatch,openwatch_failed_restore", origOW: true},
	}
	for _, b := range timeoutBlocks {
		for _, h := range []struct {
			label, env string
			bound      time.Duration
		}{
			{"health request hangs", "HEALTH_HANG=1 HANG_SECONDS=90", 67 * time.Second},
			{"rules request hangs", "RULES_HANG=1 HANG_SECONDS=40", 5 * time.Second},
		} {
			b, h := b, h
			t.Run("timeout "+b.label+" "+h.label, func(t *testing.T) {
				b.setup(t)
				start := time.Now()
				code, out, called := rig.run(b.block, "stubs-dnf", strings.TrimSpace(b.env+" "+h.env))
				elapsed := time.Since(start)
				logCase("timeout "+b.label+" / "+h.label+" ("+elapsed.Round(time.Second).String()+")", code, called)
				if code == 0 || successMarker.MatchString(out) {
					t.Fatalf("exit %d with a success line or zero exit:\n%s", code, out)
				}
				if elapsed > h.bound+margin {
					t.Fatalf("took %s, want at most %s + %s", elapsed.Round(time.Second), h.bound, margin)
				}
				if got := rig.databases(); got != b.wantDBs || rig.isOriginal("openwatch") != b.origOW {
					t.Fatalf("databases [%s], openwatch original=%v; want [%s], original=%v", got, rig.isOriginal("openwatch"), b.wantDBs, b.origOW)
				}
			})
		}
	}

	// Step 6 failures come after a good restore and install (CP bugs/OW-094).
	for _, c := range []struct{ label, journal, env string }{
		{label: "f/iv scan wiring warning in the journal after the restart",
			journal: "kensa scan wiring unavailable — on-demand scans will fail until the kensa-rules package is installed\n"},
		{label: "g/iv rule library warning in the journal after the restart",
			journal: "kensa rule library unavailable; /api/v1/rules disabled\n"},
		{label: "h/iv rules endpoint answers 503", env: "RULES_CODE=503"},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			if c.journal != "" {
				if err := os.WriteFile(filepath.Join(work, "journal.txt"), []byte(c.journal), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", c.env)
			logCase(c.label, code, called)
			if code == 0 || strings.Contains(out, "ROLLED BACK") || !strings.Contains(out, "phase: packages") {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			if !strings.Contains(called, "systemctl restart openwatch") || lastSystemctl(called) != "systemctl stop openwatch" {
				t.Fatalf("want restart, then the stop handler's stop: %q", called)
			}
			if got := rig.databases(); got != "openwatch,openwatch_pre_rollback" || rig.isOriginal("openwatch") {
				t.Fatalf("databases [%s]: a database was swapped automatically", got)
			}
		})
	}
}

func decrement(t *testing.T, v string) string {
	t.Helper()
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("migration version %q is not a positive integer", v)
	}
	return strconv.Itoa(n - 1)
}
