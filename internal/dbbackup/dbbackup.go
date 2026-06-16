// Package dbbackup creates a plain-SQL pg_dump of the OpenWatch database,
// used as the pre-upgrade restore point before migrations run.
//
// The cardinal rule: connection parameters (especially the password) go to
// pg_dump via PG* environment variables, NEVER on the command line — so the
// password never appears in the process argv (visible in `ps`). This mirrors
// how the rest of the codebase keeps credentials out of argv.
package dbbackup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// dumpArgs are the pg_dump flags shared by Command and Run. --no-owner /
// --no-privileges keep the dump restorable regardless of the target role
// layout (the restore path is `psql < file`); -f writes to the file.
func dumpArgs(outPath string) []string {
	return []string{"--no-owner", "--no-privileges", "-f", outPath}
}

// dumpEnv translates dsn into the PG* environment pg_dump reads, so no
// connection parameter (least of all the password) ends up in argv.
func dumpEnv(dsn string) ([]string, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("dbbackup: parse dsn: %w", err)
	}
	cc := cfg.ConnConfig
	env := append(os.Environ(),
		"PGHOST="+cc.Host,
		"PGPORT="+strconv.Itoa(int(cc.Port)),
		"PGUSER="+cc.User,
		"PGPASSWORD="+cc.Password,
		"PGDATABASE="+cc.Database,
	)
	// pgxpool leaves TLSConfig nil for sslmode=disable; map that back so
	// pg_dump doesn't attempt TLS against a non-TLS local Postgres. When TLS
	// IS configured we leave PGSSLMODE unset (pg_dump defaults to prefer).
	if cc.TLSConfig == nil {
		env = append(env, "PGSSLMODE=disable")
	}
	return env, nil
}

// DumpFileName returns the backup filename for a dump taken at stamp (an
// already-formatted timestamp, e.g. "20260616T010203Z") for version. Pure,
// so the caller owns the clock and tests are deterministic.
func DumpFileName(version, stamp string) string {
	v := version
	if v == "" {
		v = "unknown"
	}
	safe := make([]rune, 0, len(v))
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			safe = append(safe, r)
		default:
			safe = append(safe, '_')
		}
	}
	return fmt.Sprintf("openwatch-pre-upgrade-%s-%s.sql", string(safe), stamp)
}

// Command builds the pg_dump command writing a plain-SQL dump to outPath.
// Connection parameters live in cmd.Env (PG*), NONE in cmd.Args — the tests
// pin that the password never reaches argv.
func Command(dsn, outPath string) (*exec.Cmd, error) {
	env, err := dumpEnv(dsn)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("pg_dump", dumpArgs(outPath)...)
	cmd.Env = env
	return cmd, nil
}

// Run writes a dump to dir (created if absent) and returns the file path.
// The caller supplies version + stamp for the filename.
func Run(ctx context.Context, dsn, dir, version, stamp string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("dbbackup: mkdir %s: %w", dir, err)
	}
	out := filepath.Join(dir, DumpFileName(version, stamp))
	env, err := dumpEnv(dsn)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "pg_dump", dumpArgs(out)...)
	cmd.Env = env
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("dbbackup: pg_dump failed: %w: %s", err, string(combined))
	}
	return out, nil
}
