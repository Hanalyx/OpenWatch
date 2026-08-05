// @spec system-setup
//
// Unit coverage for the installer. The end-to-end behavior these back up was
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
//	AC-11  TestSetup_LiveVerificationIsRecorded
//	AC-12  TestSetup_RoleSQLForcesScram
//	AC-13  TestSetup_NoCredentialInPlanOrReceipt + TestSetup_ArtifactFileModes
//	AC-14  TestSetup_NonInteractivePromptSourceIsRefused
//	AC-15  TestSetup_ProvisionedClusterManagesPgHba
//	AC-16  TestSetup_PostgresFloorExcludesEndOfLife
package setup

import (
	"encoding/json"
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
			{"almalinux", "rhel", "10.2", FamilyRHEL, SupportTested},
			// RHEL 10 shares the major but has no job; it must not inherit.
			{"rhel", "fedora", "10.0", FamilyRHEL, SupportUntested},
			{"ubuntu", "debian", "24.04", FamilyDebian, SupportTested},
			// 24.10 shares the major and is a different release CI never runs.
			{"ubuntu", "debian", "24.10", FamilyDebian, SupportUntested},
			{"ubuntu", "debian", "22.04", FamilyDebian, SupportUntested},
			{"debian", "", "12", FamilyDebian, SupportTested},
			{"debian", "", "11", FamilyDebian, SupportUntested},
			// An unlisted derivative is placed by ID_LIKE rather than needing
			// this code to know every rebuild by name.
			{"navylinux", "rhel", "9.4", FamilyRHEL, SupportUntested},
			{"plan9", "", "4", FamilyUnknown, SupportUnsupported},
			{"rhel", "fedora", "notaversion", FamilyRHEL, SupportUnsupported},
			// Outside the modeled majors: the layout is not known to be the same.
			{"rocky", "rhel", "7.9", FamilyRHEL, SupportUnsupported},
		}
		for _, c := range cases {
			gotFamily := familyOf(c.id, c.idLike)
			major := majorOf(c.version)
			gotSupport := supportOf(c.id, c.version, major, gotFamily)
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
		i := strings.Index(src, "if !manage {")
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
// behavior was verified in privileged systemd containers using the shipped
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
		// The recorded runs accepted the distribution default, PostgreSQL 13,
		// with a warning. That is no longer the behavior: 13 is end of life
		// and now below the floor, and setup enables a supported module stream
		// rather than installing the default. The rest of the record still
		// holds; this clause does not, and AC-16 owns the floor.
		if minPostgresMajor <= 13 {
			t.Errorf("minPostgresMajor is %d; the floor must exclude the end-of-life 13",
				minPostgresMajor)
		}
		// Every distribution in the matrix except RHEL itself needed
		// --allow-untested, which is only true while they are untested.
		// AlmaLinux 10 is deliberately absent: the recorded run used
		// --allow-untested, but a CI job now installs on almalinux:10 on
		// every push, so it is tested and AC-04 owns that claim. The rest of
		// the recorded matrix is still untested and still needed the flag.
		for _, c := range []struct{ id, ver string }{
			{"rocky", "9.3"}, {"almalinux", "9.8"}, {"ol", "9.8"},
		} {
			if got := supportOf(c.id, c.ver, majorOf(c.ver), FamilyRHEL); got != SupportUntested {
				t.Errorf("%s %s is %q; the recorded run used --allow-untested, which "+
					"only makes sense for untested", c.id, c.ver, got)
			}
		}
	})
}

// @ac AC-11
// AC-11: the live RHEL 9.8 result, recorded with the assumptions it rests on.
//
// The run that produced it went from no cluster to a signed-in administrator in
// one invocation, and a second invocation left that administrator able to log
// in. Both depend on facts this test can still check: that RHEL 9 is a tested
// platform needing no override, and that the default plan does not rotate a
// generated password by regenerating it on every run.
func TestSetup_LiveVerificationIsRecorded(t *testing.T) {
	t.Run("system-setup/AC-11", func(t *testing.T) {
		if got := supportOf("rhel", "9.8", 9, FamilyRHEL); got != SupportTested {
			t.Errorf("RHEL 9 is %q; the live run used no --allow-untested, which only "+
				"holds while it is tested", got)
		}
		// The reuse path is what kept the administrator able to log in after the
		// second run. It only engages for a generated password.
		p := DefaultPlan(Platform{ID: "rhel", Major: 9, Family: FamilyRHEL})
		if p.Database.Password.Source != SecretGenerate {
			t.Errorf("default database password source is %q; the recorded re-run "+
				"result depends on the generate-then-reuse path", p.Database.Password.Source)
		}
		// The live host listened on the wildcard, and the summary URL has to be
		// something an operator can open. "i" was the kernel hostname there.
		if got := hostnameOr("0.0.0.0"); got == "" || got == "0.0.0.0" {
			t.Errorf("hostnameOr(0.0.0.0) = %q, want a usable address", got)
		}
	})
}

// @ac AC-12
// AC-12: the role is hashed scram-sha-256 whatever the server default is.
//
// PostgreSQL 13 defaults password_encryption to md5 and RHEL 9 still ships 13,
// so a role created without the SET cannot authenticate against the
// scram-sha-256 pg_hba rules this same installer writes. The failure surfaces
// two steps later as "password authentication failed", which reads as a wrong
// password rather than a wrong hash.
func TestSetup_RoleSQLForcesScram(t *testing.T) {
	t.Run("system-setup/AC-12", func(t *testing.T) {
		// Both verbs matter: ALTER is the path taken for a role found already
		// hashed md5, which is exactly the role that must be re-hashed.
		for _, verb := range []string{"CREATE ROLE", "ALTER ROLE"} {
			sql := roleSQL(verb, "openwatch", "pw")
			if !strings.HasPrefix(sql, "SET password_encryption = 'scram-sha-256';") {
				t.Errorf("%s: %q does not set password_encryption first", verb, sql)
			}
			// One statement, one session. Splitting them lets the SET land in a
			// session that no longer exists when the role is created.
			if strings.Contains(sql, "\n") || !strings.Contains(sql, "; "+verb+" ") {
				t.Errorf("%s: the SET and the role mutation must share one session: %q", verb, sql)
			}
		}
		// The password is a quoted literal, not an identifier: passwords are the
		// one input that cannot be restricted to plain identifiers.
		if got := roleSQL("CREATE ROLE", "openwatch", "it's"); !strings.HasSuffix(got, `'it''s'`) {
			t.Errorf("password literal is not quote-doubled: %q", got)
		}
	})
}

// @ac AC-13
// AC-13: no credential value reaches the plan or the receipt.
//
// This is what makes a plan safe to commit or attach to a ticket and a receipt
// safe to hand to support. Secret describes where a credential comes from; the
// resolved value lives on Run and is never copied into either structure.
func TestSetup_NoCredentialInPlanOrReceipt(t *testing.T) {
	t.Run("system-setup/AC-13", func(t *testing.T) {
		const dbPw = "db-secret-Ic4WdA"
		const adminPw = "admin-secret-Zq7Lme"

		r := &Run{
			Plan:          DefaultPlan(Platform{ID: "rhel", Major: 9, Family: FamilyRHEL}),
			DBPassword:    dbPw,
			AdminPassword: adminPw,
		}
		r.record("database-role", "create role", "openwatch", "")
		r.record("secrets-env", "write", secretsEnvPath, "")

		planJSON, err := json.Marshal(r.Plan)
		if err != nil {
			t.Fatal(err)
		}
		receiptJSON, err := json.Marshal(newReceipt(r, "0.7.0"))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ what, body string }{
			{"plan", string(planJSON)},
			{"receipt", string(receiptJSON)},
		} {
			for _, credential := range []string{dbPw, adminPw} {
				if strings.Contains(c.body, credential) {
					t.Errorf("the %s carries a credential value (see C-02)", c.what)
				}
			}
		}

		// The structural half: Secret has no field able to hold a value, so a
		// future field cannot reintroduce the leak without failing here.
		b, err := os.ReadFile("plan.go")
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		const typeDecl = "type Secret struct {"
		i := strings.Index(src, typeDecl)
		if i < 0 {
			t.Fatal("the Secret type has moved; this check is stale")
		}
		decl := src[i+len(typeDecl):]
		if end := strings.Index(decl, "\n}"); end > 0 {
			decl = decl[:end]
		}
		for _, field := range []string{"Value", "Password", "Secret "} {
			if strings.Contains(decl, field) {
				t.Errorf("Secret declares %q; it must record the source, never the value", field)
			}
		}
	})
}

// @ac AC-13
// AC-13 (companion): the modes those two artifacts are written with.
//
// Content and permission are the same question asked twice: who can read what
// the run left behind. The values below were a lint finding before they were a
// requirement, which is precisely why they are pinned here.
func TestSetup_ArtifactFileModes(t *testing.T) {
	t.Run("system-setup/AC-13", func(t *testing.T) {
		// Root-only. Neither file has a reader that is not root, and setup
		// writes them as root into paths the operator chooses, so anything
		// wider is a default nobody asked for.
		for _, c := range []struct{ file, call string }{
			{"execute.go", "os.WriteFile(ReceiptPath, append(b, '\\n'), 0o600)"},
			{"../../cmd/openwatch/setup.go", "os.WriteFile(*savePlan, append([]byte(header), b...), 0o600)"},
		} {
			body, err := os.ReadFile(c.file)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), c.call) {
				t.Errorf("%s no longer writes its artifact 0600; the call this pins is %q",
					c.file, c.call)
			}
		}
		// secrets.env is the exception, and it is one on purpose: the service
		// reads the DSN as the openwatch group. Pinned so that a later sweep
		// toward 0600 everywhere cannot break the service silently.
		steps, err := os.ReadFile("steps.go")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(steps), `r.writeFile(s.ID(), secretsEnvPath, []byte(content), 0o640)`) {
			t.Error("secrets.env is no longer written 0640; the service user must be able " +
				"to read the DSN, and the file is chowned root:openwatch for that reason")
		}
	})
}

// @ac AC-14
// AC-14: a run that cannot prompt is refused in preflight.
//
// `--yes` advertises accepting every default, and the default admin password
// source is an interactive prompt, so `openwatch setup --yes` alone could never
// succeed. It used to fail at secret resolution, after the plan had printed,
// which reads as a late surprise rather than a flag mistake. The plan still
// renders; what changed is that the reason now appears as the first preflight
// check rather than as an error after everything.
func TestSetup_NonInteractivePromptSourceIsRefused(t *testing.T) {
	t.Run("system-setup/AC-14", func(t *testing.T) {
		rhel := Platform{ID: "rhel", Major: 9, Family: FamilyRHEL}

		// The default plan, non-interactively: refused, naming the flag.
		c, bad := credentialSourceCheck(DefaultPlan(rhel), false)
		if !bad {
			t.Fatal("the default plan is not obtainable without a prompt; it must be refused")
		}
		if !c.Fatal || c.OK {
			t.Errorf("check must be a fatal failure, got OK=%v Fatal=%v", c.OK, c.Fatal)
		}
		if !strings.Contains(c.Detail, "--admin-password-from") {
			t.Errorf("the message must name the flag that fixes it: %q", c.Detail)
		}

		// The same plan interactively: the prompt is available, so no refusal.
		if _, bad := credentialSourceCheck(DefaultPlan(rhel), true); bad {
			t.Error("an interactive run can prompt; it must not be refused")
		}

		// Non-interactive with a resolvable source: allowed.
		p := DefaultPlan(rhel)
		p.Admin.Password = Secret{Source: SecretFile, Ref: "/root/pw"} // pragma: allowlist secret
		if _, bad := credentialSourceCheck(p, false); bad {
			t.Error("a file-sourced admin password needs no prompt; it must not be refused")
		}

		// The database password is checked too, not just the admin one.
		p = DefaultPlan(rhel)
		p.Admin.Password = Secret{Source: SecretGenerate, Length: 32} // pragma: allowlist secret
		p.Database.Password = Secret{Source: SecretPrompt}            // pragma: allowlist secret
		c, bad = credentialSourceCheck(p, false)
		if !bad {
			t.Fatal("a prompt-sourced database password must be refused too")
		}
		if !strings.Contains(c.Detail, "--db-password-from") {
			t.Errorf("the message must name the database flag: %q", c.Detail)
		}
	})
}

// @ac AC-15
// AC-15: a cluster this run provisioned is managed without being asked.
//
// The opt-in default protects a PostgreSQL that predates OpenWatch. It does
// not reach one setup installed seconds earlier, where the documented
// one-command install would otherwise stop and ask the operator to paste two
// lines into a file setup just created.
func TestSetup_ProvisionedClusterManagesPgHba(t *testing.T) {
	t.Run("system-setup/AC-15", func(t *testing.T) {
		// Nothing recorded: the cluster was already there.
		r := &Run{Plan: DefaultPlan(Platform{ID: "rhel", Major: 9, Family: FamilyRHEL})}
		if r.provisionedCluster() {
			t.Error("a run that recorded no postgres work did not provision the cluster")
		}

		// Installing PostgreSQL counts, and so does initialising the cluster
		// on a host where the package was already present.
		for _, c := range []struct{ step, action string }{
			{"postgres-install", "install"},
			{"postgres-cluster", "initdb"},
		} {
			r := &Run{}
			r.record(c.step, c.action, "postgresql", "")
			if !r.provisionedCluster() {
				t.Errorf("%s/%s must count as provisioning the cluster", c.step, c.action)
			}
		}

		// Enabling an existing cluster's service is not provisioning it: the
		// data directory, and whatever else authenticates against it, predate
		// this run.
		r = &Run{}
		r.record("postgres-cluster", "enable", "postgresql.service", "")
		if r.provisionedCluster() {
			t.Error("merely starting an existing cluster must not count as provisioning it")
		}
	})
}

// @ac AC-16
// AC-16: the floor is a support statement, so it excludes dead versions.
//
// The dates are the reason this is pinned rather than left to judgment.
// PostgreSQL 13 left support in November 2025 and 14 does so in November 2026,
// so a floor at either ships regulated customers an unsupported database. The
// distribution default is not an argument: RHEL 9's is still 13.
func TestSetup_PostgresFloorExcludesEndOfLife(t *testing.T) {
	t.Run("system-setup/AC-16", func(t *testing.T) {
		// Upstream end-of-life majors as of this release. Update deliberately,
		// with the date, when one more falls off.
		const lastEOLMajor = 14 // 14 reaches EOL 2026-11
		if minPostgresMajor <= lastEOLMajor {
			t.Errorf("minPostgresMajor is %d, which is end of life or reaches it "+
				"within this release's life; the floor must be above %d",
				minPostgresMajor, lastEOLMajor)
		}
		// What setup stands up must not be merely acceptable, or every install
		// starts one major from needing attention.
		if preferredPostgresMajor <= minPostgresMajor {
			t.Errorf("preferred %d is not newer than the floor %d; a fresh install "+
				"should not land on the oldest still-supported version",
				preferredPostgresMajor, minPostgresMajor)
		}

		// The refusal has to tell an operator what to do. A floor that only
		// says no turns into a support ticket.
		b, err := os.ReadFile("steps.go")
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, want := range []string{"pg_upgrade", "dnf module", "no longer receives security fixes"} {
			if !strings.Contains(src, want) {
				t.Errorf("the below-floor refusal does not mention %q", want)
			}
		}
		// Never in place: changing a cluster's major version is the operator's
		// call, and doing it silently under their data is unrecoverable.
		if !strings.Contains(src, "setup will not change its major") {
			t.Error("the refusal must say setup will not change the cluster's major version")
		}
	})
}
