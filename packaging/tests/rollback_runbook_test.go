// Full-rollback runbook block. UPGRADE_PROCEDURE.md "Full rollback" restores
// the upgrade scriptlet's plain-SQL dump and reinstalls the previous packages.
// It is the only recovery path once a migration has run, so it must stop on
// its own at the first bad input rather than rely on an operator noticing a
// printed error (CP bugs/OW-092).
//
// This test runs the block exactly as the runbook prints it. It extracts the
// fenced block from the Markdown, substitutes only the four input lines the
// operator fills in, and runs it against a real PostgreSQL server, a schema
// built by this tree's migrations, and a dump taken with the scriptlet's own
// pg_dump flags (internal/dbbackup). dnf, apt-get, systemctl, journalctl and
// curl are stubs that record what they were asked to do, so the test can prove
// the previous packages are installed, and the service restarted, only after
// every check passes. The real restart-and-load behavior step 6 guards against
// (CP bugs/OW-094) was observed on a host; here only its checks are exercised.
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

// rollbackBlocks returns the runbook's rollback block and its recovery block.
func rollbackBlocks(t *testing.T, root string) (rollback, recovery string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "docs", "runbooks", "UPGRADE_PROCEDURE.md"))
	if err != nil {
		t.Fatalf("read UPGRADE_PROCEDURE.md: %v", err)
	}
	fenced := regexp.MustCompile("(?s)```bash\n(.*?)```").FindAllStringSubmatch(string(b), -1)
	var rb, rc []string
	for _, m := range fenced {
		switch {
		case strings.Contains(m[1], "ASIDE=openwatch_pre_rollback"):
			rb = append(rb, m[1])
		case strings.Contains(m[1], "openwatch_failed_restore"):
			rc = append(rc, m[1])
		}
	}
	if len(rb) != 1 || len(rc) != 1 {
		t.Fatalf("UPGRADE_PROCEDURE.md has %d rollback and %d recovery blocks, want exactly one of each", len(rb), len(rc))
	}
	return rb[0], rc[0]
}

// fillRollback replaces the five operator-filled input lines. Everything else
// in the block runs byte for byte as the runbook prints it.
func fillRollback(t *testing.T, block string, values map[string]string) string {
	t.Helper()
	out := block
	for _, name := range []string{"DUMP", "EXPECTED", "OLD_OPENWATCH", "OLD_KENSA", "TOKEN_FILE"} {
		re := regexp.MustCompile(`(?m)^  ` + name + `='[^'\n]*<[^'\n]*'$`)
		if n := len(re.FindAllString(out, -1)); n != 1 {
			t.Fatalf("rollback block has %d placeholder lines for %s, want 1", n, name)
		}
		out = re.ReplaceAllLiteralString(out, "  "+name+"='"+values[name]+"'")
	}
	return out
}

func TestUpgrade_FullRollbackRunbookBlock(t *testing.T) {
	root := repoRootForLinks(t)
	rollback, recovery := rollbackBlocks(t, root)

	t.Run("the block is fail-fast and installs only after every check", func(t *testing.T) {
		mustAppear := []string{
			"set -euo pipefail",
			"PSQL=(runuser -u postgres -- psql -X -q -tA -v ON_ERROR_STOP=1)",
			`[[ "$HEAD" == *"-- PostgreSQL database dump"* ]]`,
			`[[ "$TAIL" == *"-- PostgreSQL database dump complete"* ]]`,
			`ALTER DATABASE openwatch RENAME TO $ASIDE`,
			`-1 -d openwatch -c 'SET ROLE openwatch' -f - < "$DUMP"`,
			`[ "$GOT" = "$EXPECTED" ]`,
			`[ "$FOREIGN" = 0 ]`,
			`dnf install -y "$OLD_OPENWATCH" "$OLD_KENSA"`,
			"systemctl restart openwatch",
			`[[ "$LOG" != *"kensa scan wiring unavailable"* ]]`,
			`[[ "$LOG" != *"kensa rule library unavailable"* ]]`,
			`[ "$RULES" = 200 ]`,
			"ROLLED BACK",
		}
		last := -1
		for _, s := range mustAppear {
			i := strings.Index(rollback, s)
			if i < 0 {
				t.Fatalf("rollback block lacks %q", s)
			}
			if i < last {
				t.Fatalf("rollback block has %q out of order: installation must follow every check", s)
			}
			last = i
		}
		for _, forbidden := range []string{"DROP DATABASE", "dropdb", "test -z \"$("} {
			if strings.Contains(rollback, forbidden) || strings.Contains(recovery, forbidden) {
				t.Fatalf("a rollback runbook block contains %q", forbidden)
			}
		}
	})

	t.Run("containers", func(t *testing.T) {
		image := os.Getenv("OPENWATCH_ROLLBACK_IMAGE")
		if image == "" {
			t.Skip("set OPENWATCH_ROLLBACK_IMAGE (for example postgres:16) to run the rollback block against PostgreSQL")
		}
		haveTool(t, "docker")
		runRollbackCases(t, root, image, rollback, recovery)
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

func (r *rollbackRig) dbExists(name string) bool {
	return r.query("postgres", "SELECT count(*) FROM pg_database WHERE datname = '"+name+"'") == "1"
}

// reset builds the "current" database the rollback replaces: the fixture
// schema plus a sentinel row, owned by openwatch. It removes every database a
// previous case left behind, and the stub call log.
func (r *rollbackRig) reset() {
	r.t.Helper()
	for _, db := range []string{"openwatch", "openwatch_pre_rollback", "openwatch_failed_restore"} {
		r.must("runuser -u postgres -- dropdb --if-exists " + db)
	}
	r.must("runuser -u postgres -- createdb -O openwatch openwatch")
	r.must("runuser -u postgres -- psql -X -q -1 -v ON_ERROR_STOP=1 -d openwatch -c 'SET ROLE openwatch' -f /work/good.sql")
	r.must(`runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -d openwatch -c 'SET ROLE openwatch' ` +
		`-c "CREATE TABLE rollback_sentinel (v text)" -c "INSERT INTO rollback_sentinel VALUES ('current')"`)
	r.must("rm -f /work/called /work/journal.txt")
}

// run fills and runs the rollback block with the given stubs directory first
// on PATH and extra environment for the stubs. It returns the exit status, the
// output and the stub call log.
func (r *rollbackRig) run(block, stubs, env string) (int, string, string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.work, "case.sh"), []byte(block), 0o644); err != nil {
		r.t.Fatal(err)
	}
	out, code := r.sh("env " + env + " PATH=/work/" + stubs + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash /work/case.sh")
	called, _ := r.sh("cat /work/called 2>/dev/null")
	return code, out, called
}

func runRollbackCases(t *testing.T, root, image, rollback, recovery string) {
	work := t.TempDir()
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}

	// Build this tree's binary to create a real schema with its migrations.
	build := exec.Command("go", "build", "-o", filepath.Join(work, "openwatch"), "./cmd/openwatch")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build openwatch: %v\n%s", err, out)
	}

	// Stubs: each records its name and arguments. stubs-dnf has dnf, so the
	// block takes the RPM branch; stubs-apt lacks it and shadows apt-get.
	// curl answers the health probe (it has -f) with success and the rules
	// probe (it has -w) with RULES_CODE, default 200. journalctl prints
	// /work/journal.txt when a case wrote one.
	stubBody := map[string]string{
		"systemctl": "#!/bin/sh\necho \"systemctl $*\" >> /work/called\nexit 0\n",
		"dnf":       "#!/bin/sh\necho \"dnf $*\" >> /work/called\nexit 0\n",
		"apt-get":   "#!/bin/sh\necho \"apt-get $*\" >> /work/called\nexit 0\n",
		"journalctl": "#!/bin/sh\necho \"journalctl $*\" >> /work/called\n" +
			"[ -f /work/journal.txt ] && cat /work/journal.txt\nexit 0\n",
		"curl": "#!/bin/sh\necho \"curl $*\" >> /work/called\ncat >/dev/null 2>&1 || :\n" +
			"case \" $* \" in *\" -w \"*) printf '%s' \"${RULES_CODE:-200}\" ;; esac\nexit 0\n",
	}
	for dir, names := range map[string][]string{
		"stubs-dnf": {"systemctl", "dnf", "apt-get", "journalctl", "curl"},
		"stubs-apt": {"systemctl", "apt-get", "journalctl", "curl"},
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
	const token = "owk_rollback-test-not-a-real-token"
	if err := os.WriteFile(filepath.Join(work, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"old-openwatch.pkg", "old-kensa-rules.pkg"} {
		if err := os.WriteFile(filepath.Join(work, f), []byte("previous package stand-in\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	name := "ow-rollback-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
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
	rig.must("OPENWATCH_DATABASE_DSN='postgres://openwatch:openwatch-test-only@127.0.0.1:5432/openwatch?sslmode=disable' /work/openwatch migrate")
	rig.must("PGHOST=127.0.0.1 PGUSER=openwatch PGPASSWORD=openwatch-test-only PGDATABASE=openwatch " +
		"pg_dump --no-owner --no-privileges -f /work/good.sql")
	expected := rig.query("openwatch", "SELECT max(version_id) FROM goose_db_version")
	t.Logf("fixture schema at migration version %s", expected)

	// Damaged dumps. nomarker.sql loses the completion line. badcopy.sql keeps
	// the header and the completion line but corrupts one COPY row, so only
	// psql can catch it.
	rig.must("grep -v '^-- PostgreSQL database dump complete' /work/good.sql > /work/nomarker.sql")
	rig.must(`awk 'c==1 && !done {print "not-a-number\tbroken"; done=1; next} /^COPY public.goose_db_version/ {c=1} {print}' /work/good.sql > /work/badcopy.sql`)
	if strings.Contains(rig.must("tail -n 5 /work/badcopy.sql"), "dump complete") == false {
		t.Fatal("badcopy.sql fixture lost its completion line")
	}

	fill := func(dump, exp string) string {
		return fillRollback(t, rollback, map[string]string{
			"DUMP": dump, "EXPECTED": exp,
			"OLD_OPENWATCH": "/work/old-openwatch.pkg", "OLD_KENSA": "/work/old-kensa-rules.pkg",
			"TOKEN_FILE": "/work/token",
		})
	}
	installed := func(called string) bool {
		return strings.Contains(called, "dnf install") || strings.Contains(called, "apt-get install")
	}
	sentinel := func(db string) string {
		return rig.query(db, "SELECT count(*) FROM rollback_sentinel WHERE v = 'current'")
	}

	type outcome struct {
		code      int
		installed bool
		started   bool
	}
	report := func(label string, code int, called string) outcome {
		o := outcome{code, installed(called), strings.Contains(called, "systemctl restart")}
		if strings.Contains(called, token) {
			t.Fatalf("case %s: the API token reached a command line: %q", label, called)
		}
		t.Logf("case %s: exit=%d installed=%v started=%v calls=%q", label, code, o.installed, o.started, strings.TrimSpace(called))
		return o
	}

	t.Run("a happy path, dnf", func(t *testing.T) {
		rig.reset()
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", "")
		o := report("a/dnf", code, called)
		if code != 0 || !strings.Contains(out, "rule library loaded") {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
		if !strings.Contains(called, "dnf install -y /work/old-openwatch.pkg /work/old-kensa-rules.pkg") || !o.started {
			t.Fatalf("package install or restart not recorded: %q", called)
		}
		if strings.Index(called, "dnf install") > strings.Index(called, "systemctl restart") ||
			!strings.Contains(called, "/api/v1/rules") {
			t.Fatalf("restart must follow the install, and the rules probe must run: %q", called)
		}
		if got := rig.query("openwatch", "SELECT max(version_id) FROM goose_db_version"); got != expected {
			t.Fatalf("restored migration version %s, want %s", got, expected)
		}
		foreign := rig.query("openwatch", "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "+
			"WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) <> 'openwatch'")
		if foreign != "0" {
			t.Fatalf("%s objects in public are not owned by openwatch", foreign)
		}
		if sentinel("openwatch_pre_rollback") != "1" {
			t.Fatal("the aside database lost its data")
		}
	})

	t.Run("a happy path, apt-get when dnf is absent", func(t *testing.T) {
		rig.reset()
		code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-apt", "")
		report("a/apt", code, called)
		if code != 0 || !strings.Contains(called, "apt-get install -y --allow-downgrades /work/old-openwatch.pkg /work/old-kensa-rules.pkg") {
			t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
		}
	})

	// Failures before the rename: nothing may change, not even a stop.
	for _, c := range []struct{ label, dump string }{
		{"b missing dump", "/work/missing.sql"},
		{"c1 dump without the completion line", "/work/nomarker.sql"},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			code, out, called := rig.run(fill(c.dump, expected), "stubs-dnf", "")
			o := report(c.label, code, called)
			if code == 0 || o.installed || o.started || strings.Contains(called, "systemctl stop") {
				t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
			}
			if !strings.Contains(out, "STOPPED at line") {
				t.Fatalf("no STOPPED message:\n%s", out)
			}
			if rig.dbExists("openwatch_pre_rollback") || sentinel("openwatch") != "1" {
				t.Fatal("the current database was changed by a block that stopped on its inputs")
			}
		})
	}

	// Failures after the rename: the aside database must be intact, and the
	// recovery block must put it back.
	for _, c := range []struct {
		label, dump, exp string
		setup, teardown  string
	}{
		{label: "c2 corrupt COPY row, psql fails", dump: "/work/badcopy.sql", exp: expected},
		{label: "d wrong expected migration version", dump: "/work/good.sql", exp: decrement(t, expected)},
		{label: "e an object not owned by openwatch", dump: "/work/good.sql", exp: expected,
			setup:    `runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d template1 -c "CREATE TABLE public.foreign_owned (x int)"`,
			teardown: `runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d template1 -c "DROP TABLE public.foreign_owned"`},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			if c.setup != "" {
				rig.must(c.setup)
				defer rig.must(c.teardown)
			}
			code, out, called := rig.run(fill(c.dump, c.exp), "stubs-dnf", "")
			o := report(c.label, code, called)
			if code == 0 || o.installed || o.started {
				t.Fatalf("exit %d, calls %q, output:\n%s", code, called, out)
			}
			if !strings.Contains(out, "STOPPED at line") {
				t.Fatalf("no STOPPED message:\n%s", out)
			}
			if sentinel("openwatch_pre_rollback") != "1" {
				t.Fatal("the aside database is not intact")
			}
			if err := os.WriteFile(filepath.Join(work, "recover.sh"), []byte(recovery), 0o644); err != nil {
				t.Fatal(err)
			}
			rout, rcode := rig.sh("env PATH=/work/stubs-dnf:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash /work/recover.sh")
			if rcode != 0 || !strings.Contains(rout, "RESTORED") {
				t.Fatalf("recovery block exit %d:\n%s", rcode, rout)
			}
			if sentinel("openwatch") != "1" || rig.dbExists("openwatch_pre_rollback") || !rig.dbExists("openwatch_failed_restore") {
				t.Fatal("recovery did not put the original database back as openwatch")
			}
			t.Logf("case %s: recovery block exit=0; original database back as openwatch", c.label)
		})
	}

	// Step 6 failures come after a good restore and install (CP bugs/OW-094):
	// the block must still exit non-zero and must not print ROLLED BACK.
	for _, c := range []struct{ label, journal, env string }{
		{label: "f scan wiring warning in the journal after the restart",
			journal: "kensa scan wiring unavailable — on-demand scans will fail until the kensa-rules package is installed\n"},
		{label: "g rule library warning in the journal after the restart",
			journal: "kensa rule library unavailable; /api/v1/rules disabled\n"},
		{label: "h rules endpoint answers 503", env: "RULES_CODE=503"},
	} {
		t.Run(c.label, func(t *testing.T) {
			rig.reset()
			if c.journal != "" {
				if err := os.WriteFile(filepath.Join(work, "journal.txt"), []byte(c.journal), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			code, out, called := rig.run(fill("/work/good.sql", expected), "stubs-dnf", c.env)
			o := report(c.label, code, called)
			if code == 0 || strings.Contains(out, "ROLLED BACK") || !strings.Contains(out, "STOPPED at line") {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			if !o.installed || !o.started {
				t.Fatalf("a step 6 case must reach the install and the restart: %q", called)
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
