// The steps `openwatch setup` performs, in order.
//
// Each step answers three questions independently: is it already done
// (Status), what would doing it mean (Describe), and do it (Apply). Keeping
// Status separate is what makes the whole run idempotent and what lets the
// plan be shown before anything is touched.
package setup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PostgreSQL floors. These mirror internal/db: the hard floor is what the
// migrations actually require (gen_random_uuid became a built-in in 13), the
// supported floor is policy (14 reaches end of life in November 2026, inside
// this release's service life). setup checks before installing so the operator
// finds out at the start rather than at the migration step.
const (
	// minPostgresMajor is a support floor, not a compatibility floor. The
	// schema runs on 13, but 13 reached end of life in November 2025 and 14
	// does so in November 2026. Hanalyx ships third-party software into
	// regulated estates; standing up an unsupported database as part of an
	// install is not defensible there, whatever the distribution's default is.
	// 15 is supported until November 2027 and is the lowest stream el9 offers.
	minPostgresMajor = 15
	// preferredPostgresMajor is what setup installs when it provisions. Newer
	// than the floor on purpose: an install done today should not need
	// revisiting in a year. Supported until November 2028.
	preferredPostgresMajor = 16
)

// StepStatus is the result of a step's idempotence check.
type StepStatus struct {
	// Done means the desired state already holds; Apply will be skipped.
	Done bool
	// Detail is shown in the plan, e.g. "already exists" or the version found.
	Detail string
}

// Step is one unit of the install.
type Step interface {
	ID() string
	// Describe says what applying it would do, for the plan.
	Describe(p Plan) string
	// Status reports whether it is already satisfied. Must not mutate.
	Status(ctx context.Context, p Plan) StepStatus
	// Apply performs it.
	Apply(ctx context.Context, r *Run) error
}

// Steps returns the ordered steps for a plan. Order matters and is not
// configurable: the database must exist before migrations, migrations before
// the admin user, and the service starts last so it never boots against a
// schema that is not there.
func Steps(p Plan) []Step {
	var s []Step
	if p.Database.Mode == DBProvision {
		s = append(s, stepPostgresInstall{}, stepPostgresCluster{})
	}
	s = append(s,
		stepPostgresVersion{},
		stepRole{},
		stepDatabase{},
		stepPgHba{},
		stepSecretsEnv{},
	)
	if p.Migrate {
		s = append(s, stepMigrate{})
	}
	s = append(s, stepAdmin{}, stepFirewall{}, stepService{}, stepVerify{})
	return s
}

// ---------------------------------------------------------------- postgres

type stepPostgresInstall struct{}

func (stepPostgresInstall) ID() string { return "postgres-install" }

func (stepPostgresInstall) Describe(p Plan) string {
	if p.Platform.Family == FamilyDebian {
		return "install PostgreSQL (apt-get install postgresql)"
	}
	return fmt.Sprintf("install PostgreSQL %d (dnf module enable postgresql:%d, then dnf install postgresql-server)", preferredPostgresMajor, preferredPostgresMajor)
}

func (stepPostgresInstall) Status(ctx context.Context, p Plan) StepStatus {
	if v := postgresMajor(ctx); v > 0 {
		return StepStatus{Done: true, Detail: fmt.Sprintf("PostgreSQL %d already installed", v)}
	}
	return StepStatus{}
}

func (s stepPostgresInstall) Apply(ctx context.Context, r *Run) error {
	if r.Plan.Platform.Family == FamilyDebian {
		if err := r.mutate(ctx, s.ID(), "apt-get update", "apt-get", "update"); err != nil {
			return err
		}
		if err := r.mutate(ctx, s.ID(), "install postgresql", "apt-get", "install", "-y",
			"postgresql"); err != nil {
			return err
		}
	} else {
		// Bare postgresql-server on el9 resolves to the non-modular 13, which
		// is end of life. The supported versions are module streams, so one
		// has to be selected before installing or the install quietly lands on
		// a database nobody upstream supports any more.
		//
		// An operator who has already enabled a stream has made a choice, and
		// setup does not overrule it; the version check afterwards enforces the
		// floor either way. `module` is absent on distributions without
		// modularity (and on el10), so a failure here is not fatal: fall
		// through, install, and let the version check speak.
		if !postgresStreamEnabled(ctx) {
			stream := fmt.Sprintf("postgresql:%d", preferredPostgresMajor)
			if err := r.mutate(ctx, s.ID(), "enable "+stream, "dnf", "module", "enable",
				"-y", stream); err != nil {
				r.logf("    could not enable %s (%v); installing the distribution default",
					stream, err)
			} else {
				r.record(s.ID(), "module enable", stream, "")
			}
		}
		if err := r.mutate(ctx, s.ID(), "install postgresql-server", "dnf", "install", "-y",
			"postgresql-server"); err != nil {
			return err
		}
	}
	r.record(s.ID(), "install", "postgresql", "")
	return nil
}

type stepPostgresCluster struct{}

func (stepPostgresCluster) ID() string { return "postgres-cluster" }

func (stepPostgresCluster) Describe(p Plan) string {
	if p.Platform.Family == FamilyDebian {
		return "enable and start postgresql (Debian initialises the cluster on install)"
	}
	return "initialise the data directory and enable postgresql"
}

func (stepPostgresCluster) Status(ctx context.Context, p Plan) StepStatus {
	if postgresReachable(ctx) {
		return StepStatus{Done: true, Detail: "cluster is running"}
	}
	return StepStatus{}
}

func (s stepPostgresCluster) Apply(ctx context.Context, r *Run) error {
	// RHEL ships an uninitialised data directory; Debian initialises on
	// install. initdb is only safe when the directory is genuinely empty, so
	// this checks rather than relying on the family alone.
	if r.Plan.Platform.Family == FamilyRHEL && !postgresDataDirInitialised() {
		if err := r.mutate(ctx, s.ID(), "initdb", "postgresql-setup", "--initdb"); err != nil {
			return err
		}
		r.record(s.ID(), "initdb", "/var/lib/pgsql/data", "")
	}
	if err := r.mutate(ctx, s.ID(), "enable postgresql", "systemctl", "enable", "--now", "postgresql"); err != nil {
		return err
	}
	r.record(s.ID(), "enable", "postgresql.service", "")
	if r.DryRun {
		return nil
	}
	// systemctl returns once the unit is active, which is not the same as the
	// server accepting connections. The gap is small enough that a fast host
	// wins the race and a slower one does not, which is the worst kind of
	// difference: the next step fails with "cannot determine the PostgreSQL
	// server version" on some distributions and not others, from identical
	// code. Wait for the socket rather than trusting the unit state.
	var last cmdResult
	for i := 0; i < 30; i++ {
		last = psql(ctx, "SELECT 1")
		if last.Err == nil {
			return nil
		}
		// A server that is up but refusing this connection is a different
		// problem from one that has not started, and the remedies share
		// nothing. Reporting the first as the second sends the operator to
		// `systemctl status`, which says active, and the trail ends there.
		if diag := diagnosePsqlRefusal(last); diag != "" {
			return fmt.Errorf("%s: %s", s.ID(), diag)
		}
		sleep(ctx, 1)
	}
	return fmt.Errorf("%s: postgresql started but did not accept connections within 30s; "+
		"check `systemctl status postgresql` and `journalctl -u postgresql`. Last error: %s",
		s.ID(), firstLine(last.Stderr))
}

type stepPostgresVersion struct{}

func (stepPostgresVersion) ID() string { return "postgres-version" }

func (stepPostgresVersion) Describe(Plan) string {
	return fmt.Sprintf("verify PostgreSQL >= %d (%d is end of life)", minPostgresMajor, minPostgresMajor-1)
}

func (stepPostgresVersion) Status(ctx context.Context, p Plan) StepStatus {
	v := postgresMajor(ctx)
	switch {
	case v == 0:
		return StepStatus{}
	case v < minPostgresMajor:
		return StepStatus{Detail: fmt.Sprintf("PostgreSQL %d is BELOW the supported minimum %d (end of life)", v, minPostgresMajor)}
	case v < minPostgresMajor:
		return StepStatus{Detail: fmt.Sprintf("PostgreSQL %d is BELOW the supported minimum %d (end of life)", v, minPostgresMajor)}
	default:
		return StepStatus{Done: true, Detail: fmt.Sprintf("PostgreSQL %d", v)}
	}
}

func (s stepPostgresVersion) Apply(ctx context.Context, r *Run) error {
	v := postgresMajor(ctx)
	if v == 0 {
		return fmt.Errorf("%s: cannot determine the PostgreSQL server version", s.ID())
	}
	if v < minPostgresMajor {
		return fmt.Errorf(
			"%s: PostgreSQL %d is below the supported minimum of %d.\n"+
				"    PostgreSQL %d no longer receives security fixes upstream, so OpenWatch "+
				"will not build an install on it.\n"+
				"    This cluster already holds data, so setup will not change its major "+
				"version: switching streams under an existing cluster needs pg_upgrade and "+
				"is your decision, not the installer's.\n"+
				"    On RHEL and derivatives:\n"+
				"      sudo dnf module list postgresql          # see the streams offered\n"+
				"      sudo dnf module switch-to postgresql:%d  # then pg_upgrade the cluster\n"+
				"    On Debian and Ubuntu, install the newer server package and migrate with "+
				"pg_upgradecluster.",
			s.ID(), v, minPostgresMajor, v, preferredPostgresMajor)
	}
	return nil
}

type stepRole struct{}

func (stepRole) ID() string { return "database-role" }

func (stepRole) Describe(p Plan) string {
	verb := map[SecretSource]string{
		SecretGenerate: "a generated", SecretPrompt: "an operator-supplied",
		SecretEnv: "an environment-supplied", SecretFile: "a file-supplied",
	}[p.Database.Password.Source]
	return fmt.Sprintf("create role %q with %s password, hashed scram-sha-256",
		p.Database.RoleName, verb)
}

// Status never reports Done, deliberately.
//
// The role's password and the password inside the DSN this run will write must
// be the same value, and the only way to guarantee that from any starting state
// is to set both every time. Skipping the role because it "already exists"
// leaves whatever password it happened to have, which need not be the one about
// to be written to secrets.env; the result is "password authentication failed
// for user openwatch" from an installer that just reported success. ALTER ROLE
// with the same password is harmless, so converging always is cheaper than
// detecting divergence.
//
// The reported detail still distinguishes the cases, because an md5-hashed role
// is worth naming: it can never authenticate against the scram-sha-256 rules
// this installer also writes.
func (stepRole) Status(ctx context.Context, p Plan) StepStatus {
	res := psql(ctx, fmt.Sprintf(
		"SELECT substring(rolpassword,1,13) FROM pg_authid WHERE rolname=%s", sqlLiteral(p.Database.RoleName)))
	switch {
	case res.Err != nil || res.Stdout == "":
		return StepStatus{}
	case strings.HasPrefix(strings.ToLower(res.Stdout), "md5"):
		return StepStatus{Detail: "exists but hashed md5; will be re-set as scram-sha-256"}
	default:
		return StepStatus{Detail: "exists; password will be set to match the DSN"}
	}
}

func (s stepRole) Apply(ctx context.Context, r *Run) error {
	name := r.Plan.Database.RoleName
	exists := psql(ctx, fmt.Sprintf("SELECT 1 FROM pg_roles WHERE rolname=%s", sqlLiteral(name)))
	verb := "CREATE ROLE"
	if exists.Err == nil && strings.TrimSpace(exists.Stdout) == "1" {
		verb = "ALTER ROLE"
	}
	sql := roleSQL(verb, name, r.DBPassword)
	if err := r.psqlMutate(ctx, s.ID(), strings.ToLower(verb), sql); err != nil {
		return err
	}
	r.record(s.ID(), strings.ToLower(verb), name, "")
	return nil
}

// roleSQL builds the role mutation.
//
// password_encryption is SET in the same session, so the hash format does not
// depend on the server default. That default changed from md5 to scram-sha-256
// in PostgreSQL 14, and RHEL 9 still ships 13, so relying on it produces a role
// that cannot authenticate against the pg_hba rules this installer also writes.
// The same statement re-hashes a role that was found already hashed md5,
// because the verb is ALTER ROLE in that case and the SET still applies.
func roleSQL(verb, name, password string) string {
	return fmt.Sprintf("SET password_encryption = 'scram-sha-256'; %s %s WITH LOGIN PASSWORD %s",
		verb, name, sqlLiteral(password))
}

type stepDatabase struct{}

func (stepDatabase) ID() string { return "database" }

func (stepDatabase) Describe(p Plan) string {
	return fmt.Sprintf("create database %q owned by %q", p.Database.Name, p.Database.RoleName)
}

func (stepDatabase) Status(ctx context.Context, p Plan) StepStatus {
	res := psql(ctx, fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname=%s", sqlLiteral(p.Database.Name)))
	if res.Err == nil && strings.TrimSpace(res.Stdout) == "1" {
		return StepStatus{Done: true, Detail: "database exists"}
	}
	return StepStatus{}
}

func (s stepDatabase) Apply(ctx context.Context, r *Run) error {
	sql := fmt.Sprintf("CREATE DATABASE %s OWNER %s", r.Plan.Database.Name, r.Plan.Database.RoleName)
	if err := r.psqlMutate(ctx, s.ID(), "create database", sql); err != nil {
		return err
	}
	r.record(s.ID(), "create", "database "+r.Plan.Database.Name, "")
	return nil
}

// ------------------------------------------------------------------ pg_hba

type stepPgHba struct{}

func (stepPgHba) ID() string { return "pg-hba" }

func (stepPgHba) Describe(p Plan) string {
	// The plan is what the operator reads before consenting, so it has to
	// describe the rule rather than guess the outcome: whether this run will
	// provision the cluster is not known until the earlier steps have run.
	switch {
	case p.Database.NoManagePgHba:
		return "check pg_hba.conf for the required host rules and print them if missing (--no-manage-pg-hba: never editing)"
	case p.Database.ManagePgHba:
		return "write the OpenWatch host rules to pg_hba.conf, after backing it up"
	default:
		return "write the OpenWatch host rules to pg_hba.conf if this run provisions the cluster, after backing it up; on a PostgreSQL that was already here, print them instead (--manage-pg-hba writes them)"
	}
}

func (stepPgHba) Status(ctx context.Context, p Plan) StepStatus {
	path := pgHbaPath(ctx)
	if path == "" {
		return StepStatus{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return StepStatus{}
	}
	if hasOpenWatchHbaRules(string(b), p.Database.Name, p.Database.RoleName) {
		return StepStatus{Done: true, Detail: "rules already present in " + path}
	}
	return StepStatus{Detail: "rules missing from " + path}
}

func (s stepPgHba) Apply(ctx context.Context, r *Run) error {
	path := pgHbaPath(ctx)
	if path == "" {
		return fmt.Errorf("%s: cannot locate pg_hba.conf", s.ID())
	}
	lines := pgHbaLines(r.Plan.Database.Name, r.Plan.Database.RoleName)

	// Manage it without being asked when this run provisioned the cluster.
	//
	// The opt-in default protects a PostgreSQL that predates OpenWatch and
	// serves other things: a bad pg_hba edit removes access the operator
	// already had. That reasoning does not reach a cluster setup installed and
	// initialised in this same run, where nothing else uses it and there is no
	// prior access to lose. Requiring a flag there is friction guarding
	// against a risk that cannot exist, and it leaves the documented
	// one-command install needing a manual step on exactly the fresh hosts it
	// is aimed at. Same argument as C-13 makes for the firewall.
	//
	// --no-manage-pg-hba still declines it, and an existing cluster still has
	// to be opted in explicitly.
	manage := r.Plan.Database.ManagePgHba
	if !manage && r.provisionedCluster() && !r.Plan.Database.NoManagePgHba {
		r.logf("    managing pg_hba.conf: this run provisioned the cluster")
		manage = true
	}

	if !manage {
		// Editing this file by hand is how an operator locks themselves out of
		// local postgres access, and doing it automatically carries the same
		// risk, so setup asks rather than assumes.
		r.logf("    pg_hba.conf needs these lines. Add them ABOVE any catch-all")
		r.logf("    'host all all' rule (pg_hba is first-match-wins), then reload:")
		r.logf("")
		for _, l := range lines {
			r.logf("      %s", l)
		}
		r.logf("")
		r.logf("      sudo systemctl reload postgresql")
		r.logf("")
		r.logf("    Re-run setup afterwards, or pass --manage-pg-hba to have setup do it.")
		// Halt rather than continue. Every later step authenticates as this
		// role, so proceeding guarantees a failure at the migration step whose
		// message names the role and not the missing rules.
		return &PauseError{Step: s.ID(), Reason: "pg_hba.conf needs the rules above before " +
			"the database role can authenticate"}
	}

	existing, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: read %s: %w", s.ID(), path, err)
	}
	updated := insertHbaBlock(string(existing), lines)
	if err := r.writeFile(s.ID(), path, []byte(updated), 0o600); err != nil {
		return err
	}
	if err := r.mutate(ctx, s.ID(), "reload postgresql", "systemctl", "reload", "postgresql"); err != nil {
		// A pg_hba.conf that does not parse leaves PostgreSQL refusing every
		// connection, so put the original back rather than leave the operator
		// locked out of a database they could previously reach.
		if !r.DryRun {
			_ = os.WriteFile(path, existing, 0o600)
			r.logf("    reload failed; pg_hba.conf restored to its previous contents")
		}
		return err
	}
	return nil
}

// ------------------------------------------------------------- app config

type stepSecretsEnv struct{}

func (stepSecretsEnv) ID() string { return "secrets-env" }

func (stepSecretsEnv) Describe(Plan) string {
	return "write /etc/openwatch/secrets.env with the database DSN (0640 root:openwatch)"
}

func (stepSecretsEnv) Status(ctx context.Context, p Plan) StepStatus {
	b, err := os.ReadFile(secretsEnvPath)
	if err != nil {
		return StepStatus{}
	}
	if strings.Contains(string(b), "OPENWATCH_DATABASE_DSN=") {
		return StepStatus{Done: false, Detail: "exists and will be rewritten (previous file backed up)"}
	}
	return StepStatus{}
}

func (s stepSecretsEnv) Apply(ctx context.Context, r *Run) error {
	// The DSN is assembled by DatabasePlan.DSN, which percent-encodes the
	// password. Hand-assembling it is how a password containing '@' silently
	// changes what the URI means.
	content := fmt.Sprintf("OPENWATCH_DATABASE_DSN=%s\n", r.Plan.Database.DSN(r.DBPassword))
	if err := os.MkdirAll(filepath.Dir(secretsEnvPath), 0o750); err != nil && !r.DryRun {
		return fmt.Errorf("%s: %w", s.ID(), err)
	}
	if err := r.writeFile(s.ID(), secretsEnvPath, []byte(content), 0o640); err != nil {
		return err
	}
	if r.DryRun {
		return nil
	}
	return r.mutate(ctx, s.ID(), "chown secrets.env", "chown", "root:openwatch", secretsEnvPath)
}

type stepMigrate struct{}

func (stepMigrate) ID() string { return "migrate" }

func (stepMigrate) Describe(Plan) string { return "apply database migrations" }

func (stepMigrate) Status(ctx context.Context, p Plan) StepStatus {
	res := psqlIn(ctx, p.Database.Name, "SELECT max(version_id) FROM goose_db_version")
	if res.Err == nil && res.Stdout != "" && res.Stdout != "0" {
		return StepStatus{Detail: "schema at version " + res.Stdout + "; pending migrations will be applied"}
	}
	return StepStatus{}
}

func (s stepMigrate) Apply(ctx context.Context, r *Run) error {
	return r.mutate(ctx, s.ID(), "openwatch migrate", "runuser", "-u", "openwatch", "--",
		"env", "OPENWATCH_DATABASE_DSN="+r.Plan.Database.DSN(r.DBPassword),
		openwatchBin, "migrate")
}

type stepAdmin struct{}

func (stepAdmin) ID() string { return "admin-user" }

func (stepAdmin) Describe(p Plan) string {
	return fmt.Sprintf("create the first admin user %q (%s)", p.Admin.Username, p.Admin.Email)
}

func (stepAdmin) Status(ctx context.Context, p Plan) StepStatus {
	res := psqlIn(ctx, p.Database.Name,
		fmt.Sprintf("SELECT 1 FROM users WHERE username=%s AND deleted_at IS NULL",
			sqlLiteral(p.Admin.Username)))
	// A missing users table means migrations have not run yet, which is not
	// an error at plan time: the migrate step precedes this one.
	if res.Err == nil && strings.TrimSpace(res.Stdout) == "1" {
		return StepStatus{Done: true, Detail: "user already exists"}
	}
	return StepStatus{}
}

func (s stepAdmin) Apply(ctx context.Context, r *Run) error {
	return r.mutate(ctx, s.ID(), "create-admin", "runuser", "-u", "openwatch", "--",
		"env", "OPENWATCH_DATABASE_DSN="+r.Plan.Database.DSN(r.DBPassword),
		openwatchBin, "create-admin",
		"--username", r.Plan.Admin.Username,
		"--email", r.Plan.Admin.Email,
		"--password", r.AdminPassword)
}

type stepFirewall struct{}

func (stepFirewall) ID() string { return "firewall" }

func (stepFirewall) Describe(p Plan) string {
	if !p.Service.OpenFirewall {
		return fmt.Sprintf("report whether port %d is reachable through the firewall "+
			"(not changing it; --no-firewall was passed)", p.Service.ListenPort)
	}
	return fmt.Sprintf("allow inbound %d/tcp through the host firewall", p.Service.ListenPort)
}

func (stepFirewall) Status(ctx context.Context, p Plan) StepStatus {
	switch {
	case !firewalldActive():
		return StepStatus{Done: true, Detail: "no active host firewall to configure"}
	case firewalldAllowsPort(ctx, p.Service.ListenPort):
		return StepStatus{Done: true, Detail: fmt.Sprintf("firewalld already allows %d/tcp", p.Service.ListenPort)}
	default:
		return StepStatus{Detail: fmt.Sprintf("firewalld is active and does NOT allow %d/tcp", p.Service.ListenPort)}
	}
}

// Apply opens the port the service listens on.
//
// WHY THIS IS A STEP AT ALL: without it the installer finishes, reports the API
// healthy, and prints a URL nobody can open. The health check runs over
// loopback, where the firewall does not apply, so a fully firewalled host looks
// identical to a working one. That was observed on a live RHEL 9.8 install:
// every internal check passed and the service was unreachable from any other
// machine with "No route to host".
//
// Opening it is default rather than opt-in, unlike the pg_hba edit. The two
// risks are not comparable: a pg_hba mistake removes access the operator
// already had, whereas allowing the port a web application listens on is the
// access they asked for by installing it. The plan states it before it happens
// and --no-firewall declines it.
func (s stepFirewall) Apply(ctx context.Context, r *Run) error {
	port := r.Plan.Service.ListenPort
	if !firewalldActive() {
		return nil
	}
	if !r.Plan.Service.OpenFirewall {
		r.logf("    firewalld is active and does not allow %d/tcp, so the service will", port)
		r.logf("    not be reachable from other hosts. To allow it:")
		r.logf("")
		r.logf("      sudo firewall-cmd --permanent --add-port=%d/tcp", port)
		r.logf("      sudo firewall-cmd --reload")
		return nil
	}
	if err := r.mutate(ctx, s.ID(), "add firewall port", "firewall-cmd",
		"--permanent", fmt.Sprintf("--add-port=%d/tcp", port)); err != nil {
		return err
	}
	if err := r.mutate(ctx, s.ID(), "reload firewalld", "firewall-cmd", "--reload"); err != nil {
		return err
	}
	r.record(s.ID(), "allow", fmt.Sprintf("%d/tcp", port), "")
	return nil
}

type stepService struct{}

func (stepService) ID() string { return "service" }

func (stepService) Describe(p Plan) string {
	what := "enable openwatch.service"
	if p.Service.StartNow {
		what = "enable and start openwatch.service"
	}
	if p.Service.BindCapability {
		what += fmt.Sprintf("; port %d is privileged, so add AmbientCapabilities=CAP_NET_BIND_SERVICE", p.Service.ListenPort)
	}
	return what
}

func (stepService) Status(ctx context.Context, p Plan) StepStatus {
	if serviceActive("openwatch") {
		return StepStatus{Done: false, Detail: "already running; will be restarted"}
	}
	return StepStatus{}
}

func (s stepService) Apply(ctx context.Context, r *Run) error {
	if r.Plan.Service.BindCapability {
		dir := "/etc/systemd/system/openwatch.service.d"
		if err := os.MkdirAll(dir, 0o755); err != nil && !r.DryRun {
			return fmt.Errorf("%s: %w", s.ID(), err)
		}
		drop := "[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
		if err := r.writeFile(s.ID(), filepath.Join(dir, "10-bind-privileged-port.conf"),
			[]byte(drop), 0o644); err != nil {
			return err
		}
		if err := r.mutate(ctx, s.ID(), "daemon-reload", "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	verb := "enable"
	args := []string{"enable", "openwatch"}
	if r.Plan.Service.StartNow {
		verb = "enable --now"
		args = []string{"enable", "--now", "openwatch"}
	}
	if err := r.mutate(ctx, s.ID(), "systemctl "+verb, "systemctl", args...); err != nil {
		return err
	}
	r.record(s.ID(), verb, "openwatch.service", "")
	return nil
}

type stepVerify struct{}

func (stepVerify) ID() string { return "verify" }

func (stepVerify) Describe(p Plan) string {
	return fmt.Sprintf("confirm the API answers on https://%s:%d/api/v1/health",
		p.Service.ListenHost, p.Service.ListenPort)
}

func (stepVerify) Status(context.Context, Plan) StepStatus { return StepStatus{} }

// Apply proves the install rather than declaring it finished. An installer
// that ends with "done" when the service is not actually serving is worse than
// one that fails, because the failure surfaces later and further away.
func (s stepVerify) Apply(ctx context.Context, r *Run) error {
	if r.DryRun || !r.Plan.Service.StartNow {
		return nil
	}
	// Loopback deliberately: this proves the service is serving and reached
	// its database. It does NOT prove the host is reachable from elsewhere,
	// because the firewall does not apply to loopback. The firewall step above
	// owns that, and this reports what remains unproven rather than implying
	// more than it checked.
	url := fmt.Sprintf("https://127.0.0.1:%d/api/v1/health", r.Plan.Service.ListenPort)
	var last string
	for i := 0; i < 15; i++ {
		res := run(ctx, "curl", "-sk", "--max-time", "5", url)
		if res.Err == nil && strings.Contains(res.Stdout, `"status"`) {
			r.logf("    %s", firstLine(res.Stdout))
			if !strings.Contains(res.Stdout, `"db_connected":true`) {
				return fmt.Errorf("%s: the service is up but reports db_connected=false; "+
					"check the DSN in %s", s.ID(), secretsEnvPath)
			}
			if firewalldActive() && !firewalldAllowsPort(ctx, r.Plan.Service.ListenPort) {
				r.logf("    NOTE: checked over loopback only. firewalld does not allow %d/tcp,",
					r.Plan.Service.ListenPort)
				r.logf("    so this service is not reachable from any other host.")
			}
			return nil
		}
		last = firstLine(res.Stdout + res.Stderr)
		sleep(ctx, 2)
	}
	return fmt.Errorf("%s: %s did not become healthy; last response %q. "+
		"Check `systemctl status openwatch` and `journalctl -u openwatch -n 50`",
		s.ID(), url, last)
}

// -------------------------------------------------------------- detection

const (
	secretsEnvPath = "/etc/openwatch/secrets.env" //nolint:gosec // G101: a file path, not a credential
	openwatchBin   = "/usr/bin/openwatch"
)

// postgresMajor returns the running server's major version, or 0 when it
// cannot be determined. Uses server_version_num, which is stable, rather than
// the version string, which carries vendor suffixes.
func postgresMajor(ctx context.Context) int {
	res := psql(ctx, "SELECT current_setting('server_version_num')")
	if res.Err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return 0
	}
	return n / 10000
}

// diagnosePsqlRefusal turns a connection rejection into an actionable
// sentence, or returns "" when the failure is not a rejection.
//
// setup reaches PostgreSQL as the postgres superuser over the local socket for
// every check it makes, so a pg_hba.conf without a local rule disables the
// installer completely. That file having been edited by hand is exactly how
// this state arises, and the raw error names a socket rather than the rule.
func diagnosePsqlRefusal(res cmdResult) string {
	msg := res.Stderr + res.Stdout
	switch {
	case strings.Contains(msg, "no pg_hba.conf entry"):
		return "PostgreSQL is running but refuses local superuser connections: " +
			"pg_hba.conf has no rule for local connections by the postgres user. " +
			"setup needs that access for every check it makes. Add the line " +
			"`local   all   all   peer` above the other rules in pg_hba.conf, run " +
			"`systemctl reload postgresql`, and run setup again. This state usually " +
			"follows a hand-edit that replaced the file's default rules rather than " +
			"adding to them"
	case strings.Contains(msg, "authentication failed"):
		return "PostgreSQL is running but rejected the postgres superuser's " +
			"credentials. Check the local rule's method in pg_hba.conf; peer is " +
			"expected for the postgres user"
	default:
		return ""
	}
}

// roleExists reports whether the login role is already present.
func roleExists(ctx context.Context, name string) bool {
	res := psql(ctx, fmt.Sprintf("SELECT 1 FROM pg_roles WHERE rolname=%s", sqlLiteral(name)))
	return res.Err == nil && strings.TrimSpace(res.Stdout) == "1"
}

// firewalldActive reports whether firewalld is managing the host. ufw is not
// handled: Debian-family support is untested, and guessing at a firewall is
// worse than reporting it.
func firewalldActive() bool { return serviceActive("firewalld") }

// firewalldAllowsPort reports whether inbound traffic to the port is already
// permitted, by port or by a service definition covering it.
func firewalldAllowsPort(ctx context.Context, port int) bool {
	want := fmt.Sprintf("%d/tcp", port)
	res := run(ctx, "firewall-cmd", "--list-ports")
	if res.Err == nil {
		for _, f := range strings.Fields(res.Stdout) {
			if f == want {
				return true
			}
		}
	}
	// A service definition (for example https on 443) can cover the port
	// without it appearing in --list-ports.
	if res := run(ctx, "firewall-cmd", "--list-all"); res.Err == nil &&
		strings.Contains(res.Stdout, want) {
		return true
	}
	return false
}

func postgresReachable(ctx context.Context) bool {
	return psql(ctx, "SELECT 1").Err == nil
}

// postgresDataDirInitialised reports whether the RHEL data directory already
// holds a cluster. initdb against a populated directory fails, and running it
// against one that merely looks empty would destroy nothing but waste time.
func postgresDataDirInitialised() bool {
	_, err := os.Stat("/var/lib/pgsql/data/PG_VERSION")
	return err == nil
}

// pgHbaPath asks the server where its configuration lives rather than guessing.
// The path differs by family (RHEL /var/lib/pgsql/data, Debian
// /etc/postgresql/<major>/main) and Debian can host several clusters at once,
// so the running server is the only reliable source.
func pgHbaPath(ctx context.Context) string {
	if res := psql(ctx, "SHOW hba_file"); res.Err == nil && res.Stdout != "" {
		return strings.TrimSpace(res.Stdout)
	}
	for _, candidate := range []string{"/var/lib/pgsql/data/pg_hba.conf"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func pgHbaLines(dbName, roleName string) []string {
	return []string{
		fmt.Sprintf("host    %-12s %-12s 127.0.0.1/32    scram-sha-256", dbName, roleName),
		fmt.Sprintf("host    %-12s %-12s ::1/128         scram-sha-256", dbName, roleName),
	}
}

// insertHbaBlock places the rules ABOVE the first existing authentication
// rule, never at the end of the file.
//
// pg_hba.conf is first-match-wins, and the stock RHEL file contains
//
//	host    all    all    127.0.0.1/32    ident
//
// so a block appended to the end is unreachable: ident matches first and the
// connection fails with "Ident authentication failed for user openwatch",
// naming a mechanism the operator never chose. Appending is the intuitive
// implementation and it silently does nothing useful.
func insertHbaBlock(content string, lines []string) string {
	block := []string{"# BEGIN OpenWatch (added by `openwatch setup`)"}
	block = append(block, lines...)
	block = append(block, "# END OpenWatch", "")

	src := strings.Split(content, "\n")
	insertAt := -1
	for i, line := range src {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		// The first active connection-type rule; everything below it is
		// shadowed for the tuples we care about.
		if f[0] == "local" || f[0] == "host" || f[0] == "hostssl" || f[0] == "hostnossl" {
			insertAt = i
			break
		}
	}
	if insertAt < 0 {
		return content + "\n" + strings.Join(block, "\n")
	}
	out := make([]string, 0, len(src)+len(block))
	out = append(out, src[:insertAt]...)
	out = append(out, block...)
	out = append(out, src[insertAt:]...)
	return strings.Join(out, "\n")
}

// hasOpenWatchHbaRules reports whether both loopback rules are present and
// uncommented. Deliberately tolerant of whitespace, since an operator may have
// reformatted them.
func hasOpenWatchHbaRules(content, dbName, roleName string) bool {
	var v4, v6 bool
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "host" {
			continue
		}
		matchesDB := f[1] == dbName || f[1] == "all"
		matchesRole := f[2] == roleName || f[2] == "all"
		if !matchesDB || !matchesRole || f[4] != "scram-sha-256" {
			continue
		}
		switch f[3] {
		case "127.0.0.1/32":
			v4 = true
		case "::1/128":
			v6 = true
		}
	}
	return v4 && v6
}

// postgresStreamEnabled reports whether a postgresql module stream is already
// selected on this host.
//
// An operator who enabled a stream has chosen a version deliberately, and an
// installer that overrules that would be changing a decision it did not make.
// The version check enforces the floor regardless of who chose.
func postgresStreamEnabled(ctx context.Context) bool {
	res := run(ctx, "dnf", "module", "list", "--enabled", "postgresql")
	if res.Err != nil {
		return false
	}
	return strings.Contains(res.Stdout, "postgresql")
}
