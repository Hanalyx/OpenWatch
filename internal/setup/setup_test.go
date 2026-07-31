// @spec system-setup
//
// Unit coverage for the installer. The end-to-end behaviour these back up was
// verified in systemd containers across the RHEL family; see AC-10 for what
// that run proved and TestSetup_ContainerVerificationIsRecorded for why it is
// recorded rather than executed here.
//
//	AC-04  TestSetup_PlatformSupportTiers
//	AC-05  TestSetup_PgHbaBlockGoesAboveTheCatchAll
//	AC-06  TestSetup_ExistingDSNPasswordIsRecovered
//	AC-07  TestSetup_DetectsExistingHbaRules
//	AC-08  TestSetup_NoSudoInvocations
//	AC-09  TestSetup_PgHbaPausesWhenUnmanaged
//	AC-10  TestSetup_ContainerVerificationIsRecorded
package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// @ac AC-04
// AC-04: support tiers gate which hosts setup will run on.
func TestSetup_PlatformSupportTiers(t *testing.T) {
	t.Run("system-setup/AC-04", func(t *testing.T) {
		cases := []struct {
			id, idLike, version string
			wantFamily          Family
			wantSupport         Support
		}{
			{"rhel", "fedora", "9.8", FamilyRHEL, SupportTested},
			{"rocky", "rhel centos fedora", "9.3", FamilyRHEL, SupportUntested},
			{"almalinux", "rhel centos fedora", "9.8", FamilyRHEL, SupportUntested},
			{"ol", "fedora", "9.8", FamilyRHEL, SupportUntested},
			{"almalinux", "rhel", "8.10", FamilyRHEL, SupportUntested},
			{"almalinux", "rhel", "10.2", FamilyRHEL, SupportUntested},
			{"ubuntu", "debian", "24.04", FamilyDebian, SupportUntested},
			{"debian", "", "12", FamilyDebian, SupportUntested},
			// An unlisted derivative is placed by ID_LIKE rather than needing
			// this code to know every rebuild by name.
			{"navylinux", "rhel", "9.4", FamilyRHEL, SupportUntested},
			{"plan9", "", "4", FamilyUnknown, SupportUnsupported},
			{"rhel", "fedora", "notaversion", FamilyRHEL, SupportUnsupported},
			// Outside the modelled majors: the layout is not known to be the same.
			{"rocky", "rhel", "7.9", FamilyRHEL, SupportUnsupported},
		}
		for _, c := range cases {
			gotFamily := familyOf(c.id, c.idLike)
			major := majorOf(c.version)
			gotSupport := supportOf(c.id, major, gotFamily)
			if gotFamily != c.wantFamily {
				t.Errorf("familyOf(%q, %q) = %q, want %q", c.id, c.idLike, gotFamily, c.wantFamily)
			}
			if gotSupport != c.wantSupport {
				t.Errorf("supportOf(%q, %d, %q) = %q, want %q",
					c.id, major, gotFamily, gotSupport, c.wantSupport)
			}
		}
	})
}

// @ac AC-05
// AC-05: the pg_hba block must precede the first existing rule.
//
// The bug this pins cost a full container run. Appending is the obvious
// implementation, and on a stock RHEL file it is silently useless: the default
//
//	host    all    all    127.0.0.1/32    ident
//
// matches first, so the connection fails with "Ident authentication failed for
// user openwatch", naming a mechanism nobody selected.
func TestSetup_PgHbaBlockGoesAboveTheCatchAll(t *testing.T) {
	t.Run("system-setup/AC-05", func(t *testing.T) {
		stock := `# PostgreSQL Client Authentication Configuration File
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            ident
host    all             all             ::1/128                 ident
`
		got := insertHbaBlock(stock, pgHbaLines("openwatch", "openwatch"))

		ourIdx := strings.Index(got, "# BEGIN OpenWatch")
		catchAll := strings.Index(got, "host    all             all             127.0.0.1/32")
		localIdx := strings.Index(got, "local   all             all")
		if ourIdx < 0 {
			t.Fatal("the OpenWatch block was not inserted at all")
		}
		if ourIdx > catchAll {
			t.Error("the OpenWatch block is BELOW the catch-all host rule; pg_hba is " +
				"first-match-wins, so it would never be reached")
		}
		if ourIdx > localIdx {
			t.Error("the OpenWatch block must precede the first active rule of any type")
		}
		// Comments before the first rule must survive, and nothing existing
		// may be dropped.
		for _, keep := range []string{"# PostgreSQL Client Authentication", "peer", "::1/128"} {
			if !strings.Contains(got, keep) {
				t.Errorf("insertHbaBlock lost existing content %q", keep)
			}
		}

		// A file with no active rules at all still gets the block.
		if out := insertHbaBlock("# only comments\n", pgHbaLines("openwatch", "openwatch")); !strings.Contains(out, "# BEGIN OpenWatch") {
			t.Error("a comment-only file must still receive the block")
		}
	})
}

// @ac AC-06
// AC-06: a re-run recovers the password already in secrets.env.
//
// Without this the second run generates a fresh password, skips the role
// because it exists, and writes the new value into the DSN. Role and DSN then
// hold different secrets and the next step fails with "password authentication
// failed" from an installer that had just succeeded.
func TestSetup_ExistingDSNPasswordIsRecovered(t *testing.T) {
	t.Run("system-setup/AC-06", func(t *testing.T) {
		dir := t.TempDir()
		d := DatabasePlan{Host: "127.0.0.1", Port: 5432, Name: "openwatch",
			RoleName: "openwatch", SSLMode: "disable"}

		for _, pw := range []string{"simple", "WindoW2005@@", "a/b?c#d", "pct%40literal"} {
			path := filepath.Join(dir, "secrets.env")
			body := "# comment\nOPENWATCH_DATABASE_DSN=" + d.DSN(pw) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, ok := existingDSNPassword(path)
			if !ok {
				t.Errorf("password %q: not recovered from secrets.env", pw)
				continue
			}
			if got != pw {
				t.Errorf("password %q recovered as %q; the reused value must match "+
					"the one the role was created with", pw, got)
			}
		}

		if _, ok := existingDSNPassword(filepath.Join(dir, "absent")); ok {
			t.Error("a missing file must report not-found, not a bogus password")
		}
		noDSN := filepath.Join(dir, "other.env")
		_ = os.WriteFile(noDSN, []byte("SOMETHING_ELSE=1\n"), 0o600)
		if _, ok := existingDSNPassword(noDSN); ok {
			t.Error("a file without a DSN line must report not-found")
		}
	})
}

// @ac AC-07
// AC-07: rule detection tolerates formatting but not absence.
func TestSetup_DetectsExistingHbaRules(t *testing.T) {
	t.Run("system-setup/AC-07", func(t *testing.T) {
		present := "host openwatch openwatch 127.0.0.1/32 scram-sha-256\n" +
			"host   openwatch   openwatch   ::1/128   scram-sha-256\n"
		if !hasOpenWatchHbaRules(present, "openwatch", "openwatch") {
			t.Error("both rules present with irregular spacing must be detected")
		}
		// The wildcard form a hand-written file may use.
		wild := "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"
		if !hasOpenWatchHbaRules(wild, "openwatch", "openwatch") {
			t.Error("the all/all wildcard form must satisfy the requirement")
		}
		// Commented-out rules are not rules.
		commented := "#host openwatch openwatch 127.0.0.1/32 scram-sha-256\n" +
			"#host openwatch openwatch ::1/128 scram-sha-256\n"
		if hasOpenWatchHbaRules(commented, "openwatch", "openwatch") {
			t.Error("commented rules must not count as present")
		}
		// IPv4 only is incomplete: the service may resolve localhost to ::1.
		v4only := "host openwatch openwatch 127.0.0.1/32 scram-sha-256\n"
		if hasOpenWatchHbaRules(v4only, "openwatch", "openwatch") {
			t.Error("only the IPv4 rule present must not count as complete")
		}
		// The wrong method is not a match: ident cannot authenticate a password.
		identOnly := "host openwatch openwatch 127.0.0.1/32 ident\n" +
			"host openwatch openwatch ::1/128 ident\n"
		if hasOpenWatchHbaRules(identOnly, "openwatch", "openwatch") {
			t.Error("ident rules must not satisfy a scram-sha-256 requirement")
		}
	})
}

// @ac AC-08
// AC-08: privilege drops use runuser.
//
// sudo needs a PAM stack that minimal AlmaLinux and Oracle Linux images do not
// configure; `sudo -u postgres` there fails with "PAM account management
// error" while runuser works. setup already runs as root, so sudo buys nothing.
func TestSetup_NoSudoInvocations(t *testing.T) {
	t.Run("system-setup/AC-08", func(t *testing.T) {
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), `"sudo"`) {
				t.Errorf("%s invokes sudo; use runuser (see C-08)", e.Name())
			}
		}
	})
}

// @ac AC-09
// AC-09: declining to manage pg_hba.conf halts rather than continuing.
func TestSetup_PgHbaPausesWhenUnmanaged(t *testing.T) {
	t.Run("system-setup/AC-09", func(t *testing.T) {
		b, err := os.ReadFile("steps.go")
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		i := strings.Index(src, "if !r.Plan.Database.ManagePgHba {")
		if i < 0 {
			t.Fatal("the unmanaged pg_hba branch has moved; this check is stale")
		}
		// Within that branch, the function must return a PauseError. Returning
		// nil lets every later step run against a role that cannot yet
		// authenticate, and the run dies at the migration step naming ident.
		branch := src[i:]
		if end := strings.Index(branch, "\n\t}"); end > 0 {
			branch = branch[:end]
		}
		if !strings.Contains(branch, "&PauseError{") {
			t.Error("the unmanaged pg_hba branch must return a PauseError so the run " +
				"halts at the step that needs the operator, not two steps later")
		}
	})
}

// @ac AC-10
// AC-10: the end-to-end matrix, recorded because it cannot run here.
//
// Unit tests cannot install PostgreSQL, drive systemd, or bind a port. The
// behaviour was verified in privileged systemd containers using the shipped
// RPM, and this test pins the claim so the recorded result and the code cannot
// drift apart silently: the constants it asserts are the ones the run depended
// on.
func TestSetup_ContainerVerificationIsRecorded(t *testing.T) {
	t.Run("system-setup/AC-10", func(t *testing.T) {
		// AlmaLinux 8 was refused because its default PostgreSQL is 10. That
		// refusal is only correct while the floor is above 10.
		if minPostgresMajor <= 10 {
			t.Errorf("minPostgresMajor is %d; the recorded AlmaLinux 8 refusal "+
				"(PostgreSQL 10) no longer follows from it", minPostgresMajor)
		}
		// Rocky 9, Alma 9 and Oracle 9 all ship PostgreSQL 13, which passed
		// while warning. That depends on 13 sitting between the two floors.
		if minPostgresMajor > 13 || supportedPostgresMajor <= 13 {
			t.Errorf("floors are min=%d supported=%d; the recorded RHEL 9 result "+
				"(PostgreSQL 13 accepted with a warning) no longer follows",
				minPostgresMajor, supportedPostgresMajor)
		}
		// Every distribution in the matrix except RHEL itself needed
		// --allow-untested, which is only true while they are untested.
		for _, c := range []struct{ id, ver string }{
			{"rocky", "9.3"}, {"almalinux", "9.8"}, {"ol", "9.8"}, {"almalinux", "10.2"},
		} {
			if got := supportOf(c.id, majorOf(c.ver), FamilyRHEL); got != SupportUntested {
				t.Errorf("%s %s is %q; the recorded run used --allow-untested, which "+
					"only makes sense for untested", c.id, c.ver, got)
			}
		}
	})
}
