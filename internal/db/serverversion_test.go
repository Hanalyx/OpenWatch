// @spec system-db
//
//	AC-13  TestServerVersion_PreflightEnforcesFloorAndAdvises
package db

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// @ac AC-13
// AC-13: the version preflight enforces the hard floor and advises separately
// on the supported floor.
//
// The two thresholds are deliberately different lines and the test pins both.
// Collapsing them would either brick an existing deployment on an older server
// (if the supported floor were enforced) or let a migration run start on a
// server that cannot build the schema (if only the supported floor warned).
func TestServerVersion_PreflightEnforcesFloorAndAdvises(t *testing.T) {
	t.Run("system-db/AC-13", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()

		// ServerVersion reads the integer GUC, so it never has to parse a
		// vendor-suffixed version string.
		num, err := ServerVersion(ctx, pool)
		if err != nil {
			t.Fatalf("ServerVersion: %v", err)
		}
		if num < 100000 || num > 999999 {
			t.Errorf("server_version_num = %d, want a 6-digit PostgreSQL version number", num)
		}

		// The test database is a supported version, so the preflight is silent.
		advisory, err := CheckServerVersion(ctx, pool)
		if err != nil {
			t.Errorf("CheckServerVersion on %s: unexpected error %v",
				FormatServerVersion(num), err)
		}
		if num >= SupportedServerVersionNum && advisory != "" {
			t.Errorf("advisory on supported version %s = %q, want empty",
				FormatServerVersion(num), advisory)
		}

		// The thresholds are ordered, and the hard floor is the one the SQL
		// actually requires. If someone raises MinServerVersionNum to match
		// the supported floor, existing deployments stop migrating.
		if MinServerVersionNum > SupportedServerVersionNum {
			t.Errorf("MinServerVersionNum %d must not exceed SupportedServerVersionNum %d",
				MinServerVersionNum, SupportedServerVersionNum)
		}
		if MinServerVersionNum != 130000 {
			t.Errorf("MinServerVersionNum = %d, want 130000: the floor is set by "+
				"gen_random_uuid becoming a built-in in PostgreSQL 13, so it moves "+
				"only when the migrations' SQL requirements move", MinServerVersionNum)
		}

		// Both messages must name the version, because the failure they
		// replace named a missing function instead and sent operators looking
		// at the wrong thing.
		if got := FormatServerVersion(130000); got != "13.0" {
			t.Errorf("FormatServerVersion(130000) = %q, want \"13.0\"", got)
		}
		if got := FormatServerVersion(150018); got != "15.18" {
			t.Errorf("FormatServerVersion(150018) = %q, want \"15.18\"", got)
		}
	})
}

// @ac AC-13
// AC-13 (message content): the operator-facing strings name the version found
// and the version needed. Asserted separately from the live-database case so
// the wording is pinned even where no old server is available to connect to.
func TestServerVersion_MessagesNameVersions(t *testing.T) {
	t.Run("system-db/AC-13", func(t *testing.T) {
		// Below the hard floor: an error naming both versions.
		err := belowFloorError(120000)
		if err == nil {
			t.Fatal("expected an error below the hard floor")
		}
		for _, want := range []string{"12.0", "13.0"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("hard-floor error %q does not name %q", err.Error(), want)
			}
		}

		// Between floors: an advisory naming both versions and the md5 trap
		// that motivated the check.
		adv := belowSupportedAdvisory(130023)
		for _, want := range []string{"13.23", "15.0", "md5"} {
			if !strings.Contains(adv, want) {
				t.Errorf("advisory %q does not mention %q", adv, want)
			}
		}
	})
}
