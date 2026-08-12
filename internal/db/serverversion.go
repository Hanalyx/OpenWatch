// Server-version preflight for the migration path.
//
// WHY THIS EXISTS: nothing in the binary checked what PostgreSQL it was
// talking to. Two versions of that problem showed up during a v0.7.0 install
// on RHEL 9, which defaults to PostgreSQL 13:
//
//  1. Below the hard floor the schema simply does not build. gen_random_uuid()
//     became a built-in in PostgreSQL 13; three migrations use it as a column
//     DEFAULT. On 12 or older the operator gets "function gen_random_uuid()
//     does not exist" partway through a migration run, which names a function
//     rather than a version and leaves the schema half-applied.
//
//  2. Between the hard floor and the supported floor the schema builds, but
//     the version is old enough to carry behavior the install guide does not
//     account for. PostgreSQL 13 defaults password_encryption to md5 where 14
//     and later default to scram-sha-256, so a role created by following the
//     guide could not authenticate against the pg_hba.conf rules the same
//     guide supplied.
//
// Those are different failures and deserve different answers, so this reports
// them separately. Documentation cannot enforce a floor; a released binary
// can, and says so once, in terms naming the version.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// MinServerVersionNum is the HARD floor, below which migrations cannot
	// succeed. 13 is set by gen_random_uuid() as a built-in. Raising this is
	// a breaking change for existing deployments, so it tracks what the SQL
	// actually requires, not what the project prefers to support.
	MinServerVersionNum = 130000

	// SupportedServerVersionNum is the lowest version a NEW install should
	// target. Deliberately higher than the hard floor: PostgreSQL 14 reaches
	// end of life in November 2026, and a release that ships before then
	// still runs past it. Below this the binary warns and continues, so an
	// existing deployment is never bricked by a policy change.
	SupportedServerVersionNum = 150000
)

// ServerVersion reports the connected server's version as a PostgreSQL
// version number (major*10000 + minor), for example 150018 for 15.18.
func ServerVersion(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var num int
	// server_version_num is stable across releases; parsing the
	// server_version string is not, since it carries vendor suffixes such as
	// "15.18 (Debian 15.18-1.pgdg120+1)".
	//
	// current_setting with an explicit ::int rather than SHOW: every GUC comes
	// back as text regardless of its underlying type, so SHOW cannot scan into
	// an int and fails with a type error at runtime.
	const q = `SELECT current_setting('server_version_num')::int`
	if err := pool.QueryRow(ctx, q).Scan(&num); err != nil {
		return 0, fmt.Errorf("db: read server_version_num: %w", err)
	}
	return num, nil
}

// FormatServerVersion renders a version number as major.minor for humans.
func FormatServerVersion(num int) string {
	return fmt.Sprintf("%d.%d", num/10000, num%10000)
}

// CheckServerVersion enforces the hard floor and reports whether the server is
// merely below the supported floor.
//
// Returns an error only when the server cannot run the schema at all. The
// second return is a non-empty advisory when the server is usable but older
// than a new install should target; callers print it and continue.
func CheckServerVersion(ctx context.Context, pool *pgxpool.Pool) (advisory string, err error) {
	num, err := ServerVersion(ctx, pool)
	if err != nil {
		return "", err
	}
	if num < MinServerVersionNum {
		return "", belowFloorError(num)
	}
	if num < SupportedServerVersionNum {
		return belowSupportedAdvisory(num), nil
	}
	return "", nil
}

// belowFloorError builds the refusal. Split out from CheckServerVersion so the
// wording is testable without an old server to connect to, which is the only
// way it would otherwise be exercised.
func belowFloorError(num int) error {
	return fmt.Errorf(
		"db: PostgreSQL %s is too old: OpenWatch requires %s or newer "+
			"(gen_random_uuid must be built in). Upgrade the server, or point "+
			"OPENWATCH_DATABASE_DSN at a supported instance",
		FormatServerVersion(num), FormatServerVersion(MinServerVersionNum))
}

// belowSupportedAdvisory builds the warning for a server that works but is
// older than a new install should target. It names the md5 default explicitly
// because that is the failure this whole check came out of, and the symptom
// (authentication rejected) points at the role rather than at the version.
func belowSupportedAdvisory(num int) string {
	return fmt.Sprintf(
		"PostgreSQL %s is below the supported minimum %s. Migrations will run, "+
			"but this version is not a supported target for a new install. Note that "+
			"PostgreSQL 13 defaults password_encryption to md5 while the install guide "+
			"configures pg_hba.conf for scram-sha-256; if role authentication fails, "+
			"check the stored hash format",
		FormatServerVersion(num), FormatServerVersion(SupportedServerVersionNum))
}
