// @spec release-upgrade
//
// AC traceability (this file):
//
//	AC-01  TestCommand_PasswordNeverInArgv
//	AC-02  TestDumpFileName_DeterministicAndSanitized

package dbbackup

import (
	"strings"
	"testing"
)

// @ac AC-01
// AC-01: the pg_dump command carries connection params (incl. the password)
// in the environment only — NEVER in argv, where `ps` would expose it.
func TestCommand_PasswordNeverInArgv(t *testing.T) {
	t.Run("release-upgrade/AC-01", func(t *testing.T) {
		const secret = "s3cr3t-p@ss"
		dsn := "postgres://owuser:" + secret + "@db.example:6543/owdb?sslmode=disable"
		cmd, err := Command(dsn, "/var/lib/openwatch/backups/x.sql")
		if err != nil {
			t.Fatalf("Command: %v", err)
		}
		// Password must not appear anywhere in argv.
		argv := strings.Join(cmd.Args, " ")
		if strings.Contains(argv, secret) {
			t.Errorf("password leaked into argv: %q", argv)
		}
		// Connection params must be in the env instead.
		joinEnv := strings.Join(cmd.Env, "\n")
		for _, want := range []string{
			"PGPASSWORD=" + secret,
			"PGHOST=db.example",
			"PGPORT=6543",
			"PGUSER=owuser",
			"PGDATABASE=owdb",
			"PGSSLMODE=disable", // sslmode=disable -> nil TLS -> mapped back
		} {
			if !strings.Contains(joinEnv, want) {
				t.Errorf("env missing %q", want)
			}
		}
		// pg_dump must write to the file, not stdout.
		if !strings.Contains(argv, "-f /var/lib/openwatch/backups/x.sql") {
			t.Errorf("pg_dump not directed at the output file: %q", argv)
		}
	})
}

// @ac AC-02
// AC-02: backup filenames are deterministic given (version, stamp) and
// sanitize unsafe characters in the version token.
func TestDumpFileName_DeterministicAndSanitized(t *testing.T) {
	t.Run("release-upgrade/AC-02", func(t *testing.T) {
		got := DumpFileName("0.2.0-rc.8", "20260616T010203Z")
		want := "openwatch-pre-upgrade-0.2.0-rc.8-20260616T010203Z.sql"
		if got != want {
			t.Errorf("DumpFileName = %q, want %q", got, want)
		}
		// Unsafe characters (slashes, spaces) are replaced.
		if name := DumpFileName("v1/2 3", "S"); strings.ContainsAny(name, "/ ") {
			t.Errorf("unsafe chars survived: %q", name)
		}
		// Empty version falls back to a non-empty token.
		if name := DumpFileName("", "S"); !strings.Contains(name, "unknown") {
			t.Errorf("empty version not defaulted: %q", name)
		}
	})
}
