// The setup plan: one object, three ways to fill it.
//
// Express fills it from detection plus defaults, guided fills it by prompting
// with those same values pre-filled, and unattended fills it from a file. All
// three then run identical validation and identical steps. That is deliberate:
// the alternative is a "quick install" path and a "real install" path that
// drift, where the automated one is exercised least and breaks quietly.
//
// NO SECRETS ARE STORED HERE. Every credential is a source, never a value, so
// a plan file is safe to commit, attach to a ticket, or send to support. It is
// also what makes fleet replay work: run guided once, save the plan, apply it
// unattended everywhere else.
package setup

import (
	"fmt"
	"net/url"
	"strings"
)

// PlanAPIVersion is bumped when the schema changes incompatibly, so an old
// saved plan is rejected with a version message rather than mis-parsed.
const PlanAPIVersion = "openwatch.hanalyx.com/v1alpha1"

// SecretSource says where a credential comes from at apply time.
type SecretSource string

const (
	// SecretGenerate mints a random value. The default for the database role,
	// because a generated password is built into the DSN by the same code that
	// creates the role, so the two cannot disagree and the operator never has
	// to think about URI encoding.
	SecretGenerate SecretSource = "generate"
	// SecretPrompt reads it interactively.
	SecretPrompt SecretSource = "prompt"
	// SecretEnv reads it from an environment variable named by SecretRef.
	SecretEnv SecretSource = "env"
	// SecretFile reads it from the file named by SecretRef.
	SecretFile SecretSource = "file"
)

// Secret describes how to obtain a credential without recording it.
type Secret struct {
	Source SecretSource `yaml:"source"`
	// Ref names the env var or file path for the env/file sources.
	Ref string `yaml:"ref,omitempty"`
	// Length is the generated length; ignored for other sources.
	Length int `yaml:"length,omitempty"`
}

// DatabaseMode selects how much of PostgreSQL's lifecycle setup owns.
type DatabaseMode string

const (
	// DBProvision installs PostgreSQL if absent, initializes the cluster,
	// starts it, and creates the role and database.
	DBProvision DatabaseMode = "provision"
	// DBExisting connects to a PostgreSQL that already runs, creating only
	// the role and database if they are missing.
	DBExisting DatabaseMode = "existing"
)

// DatabasePlan is everything about reaching and owning the database.
type DatabasePlan struct {
	Mode     DatabaseMode `yaml:"mode"`
	Host     string       `yaml:"host"`
	Port     int          `yaml:"port"`
	Name     string       `yaml:"name"`
	RoleName string       `yaml:"role_name"`
	Password Secret       `yaml:"password"`
	// SSLMode is forced to at least "require" when Host is not loopback; a
	// remote database over cleartext is not something to allow by accident.
	SSLMode string `yaml:"sslmode"`
	// ManagePgHba is opt-in. Editing pg_hba.conf is the single most effective
	// way to lock an operator out of their own database, so the default is to
	// print the required lines and re-check rather than to write them.
	ManagePgHba bool `yaml:"manage_pg_hba"`
	// NoManagePgHba declines the edit even when this run provisioned the
	// cluster, which is otherwise managed without asking.
	NoManagePgHba bool `yaml:"no_manage_pg_hba,omitempty"`
}

// ServicePlan covers the unit and how it listens.
type ServicePlan struct {
	ListenHost string `yaml:"listen_host"`
	ListenPort int    `yaml:"listen_port"`
	// BindCapability is DERIVED from ListenPort, never authored: a port below
	// 1024 needs CAP_NET_BIND_SERVICE because the service runs unprivileged.
	BindCapability bool `yaml:"bind_capability"`
	EnableOnBoot   bool `yaml:"enable_on_boot"`
	StartNow       bool `yaml:"start_now"`
	// OpenFirewall allows inbound traffic to ListenPort. Default true: the
	// health check runs over loopback, where the firewall does not apply, so
	// without this an install can report itself healthy while being
	// unreachable from every other machine.
	OpenFirewall bool `yaml:"open_firewall"`
}

// AdminPlan is the first login.
type AdminPlan struct {
	Username string `yaml:"username"`
	Email    string `yaml:"email"`
	Password Secret `yaml:"password"`
}

// Plan is the whole intent. Platform is detected rather than authored and is
// re-detected on apply.
type Plan struct {
	APIVersion string       `yaml:"apiVersion"`
	Platform   Platform     `yaml:"platform"`
	Database   DatabasePlan `yaml:"database"`
	Service    ServicePlan  `yaml:"service"`
	Admin      AdminPlan    `yaml:"admin"`
	Migrate    bool         `yaml:"migrate"`
}

// DefaultPlan returns the plan a bare `openwatch setup` would apply on this
// host. Guided mode renders these as pre-filled answers, so holding Enter and
// running --yes produce the same result.
func DefaultPlan(p Platform) Plan {
	return Plan{
		APIVersion: PlanAPIVersion,
		Platform:   p,
		Database: DatabasePlan{
			Mode:     DBProvision,
			Host:     "127.0.0.1",
			Port:     5432,
			Name:     "openwatch",
			RoleName: "openwatch",
			Password: Secret{Source: SecretGenerate, Length: 32},
			SSLMode:  "disable",
			// Opt-in by design; see DatabasePlan.ManagePgHba.
			ManagePgHba: false,
		},
		Service: ServicePlan{
			ListenHost:   "0.0.0.0",
			ListenPort:   8443,
			EnableOnBoot: true,
			StartNow:     true,
			OpenFirewall: true,
		},
		Admin: AdminPlan{
			Username: "admin",
			Email:    "admin@example.com",
			Password: Secret{Source: SecretPrompt},
		},
		Migrate: true,
	}
}

// IsLoopback reports whether the database lives on this machine.
func (d DatabasePlan) IsLoopback() bool {
	return d.Host == "127.0.0.1" || d.Host == "::1" || d.Host == "localhost"
}

// Derive recomputes the fields that follow from other answers. Called after
// every edit in guided mode so the operator sees a consequence at the moment
// of the choice rather than when the service fails to start.
func (p *Plan) Derive() {
	p.APIVersion = PlanAPIVersion
	p.Service.BindCapability = p.Service.ListenPort > 0 && p.Service.ListenPort < 1024
	// A non-loopback database must not be reached in cleartext. Upgrading
	// silently would be its own surprise, so Validate reports it; this only
	// fixes the default nobody edited.
	if !p.Database.IsLoopback() && p.Database.SSLMode == "disable" {
		p.Database.SSLMode = "require"
	}
	if p.Database.Password.Source == SecretGenerate && p.Database.Password.Length <= 0 {
		p.Database.Password.Length = 32
	}
}

// DSN builds the connection string for a resolved password.
//
// The password is passed raw and encoded here, by net/url, which is the whole
// point: a DSN is a URI, and a password containing '@' or '/' silently changes
// what the URI means. Hand-assembling this string is how an install ends up
// authenticating as something other than what the operator typed.
func (d DatabasePlan) DSN(password string) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(d.RoleName, password),
		Host:   fmt.Sprintf("%s:%d", d.Host, d.Port),
		Path:   "/" + d.Name,
	}
	q := u.Query()
	q.Set("sslmode", d.SSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// Validate reports every problem at once, so an operator fixes one round of
// answers instead of discovering them one prompt at a time.
func (p Plan) Validate() []error {
	var errs []error
	if p.APIVersion != PlanAPIVersion {
		errs = append(errs, fmt.Errorf("plan apiVersion is %q, this binary understands %q",
			p.APIVersion, PlanAPIVersion))
	}
	switch p.Database.Mode {
	case DBProvision, DBExisting:
	default:
		errs = append(errs, fmt.Errorf("database.mode is %q, want provision or existing", p.Database.Mode))
	}
	if p.Database.Mode == DBProvision && !p.Database.IsLoopback() {
		errs = append(errs, fmt.Errorf(
			"database.mode is provision but host is %q: setup only provisions a local "+
				"PostgreSQL. Use mode existing for a remote server", p.Database.Host))
	}
	if p.Database.Port < 1 || p.Database.Port > 65535 {
		errs = append(errs, fmt.Errorf("database.port %d is out of range", p.Database.Port))
	}
	if !validIdent(p.Database.Name) {
		errs = append(errs, fmt.Errorf("database.name %q must be a plain identifier "+
			"(letters, digits, underscore, not starting with a digit)", p.Database.Name))
	}
	if !validIdent(p.Database.RoleName) {
		errs = append(errs, fmt.Errorf("database.role_name %q must be a plain identifier", p.Database.RoleName))
	}
	switch p.Database.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		errs = append(errs, fmt.Errorf("database.sslmode %q is not a PostgreSQL sslmode", p.Database.SSLMode))
	}
	if !p.Database.IsLoopback() && p.Database.SSLMode == "disable" {
		errs = append(errs, fmt.Errorf(
			"database.sslmode is disable for remote host %q: credentials would cross "+
				"the network in cleartext", p.Database.Host))
	}
	if p.Service.ListenPort < 1 || p.Service.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("service.listen_port %d is out of range", p.Service.ListenPort))
	}
	if p.Admin.Username == "" {
		errs = append(errs, fmt.Errorf("admin.username is empty"))
	}
	if !strings.Contains(p.Admin.Email, "@") {
		errs = append(errs, fmt.Errorf("admin.email %q is not an address", p.Admin.Email))
	}
	errs = append(errs, validateSecret("database.password", p.Database.Password)...)
	errs = append(errs, validateSecret("admin.password", p.Admin.Password)...)
	return errs
}

func validateSecret(field string, s Secret) []error {
	switch s.Source {
	case SecretGenerate:
		if s.Length > 0 && s.Length < 16 {
			return []error{fmt.Errorf("%s.length %d is too short; use at least 16", field, s.Length)}
		}
	case SecretPrompt:
	case SecretEnv, SecretFile:
		if s.Ref == "" {
			return []error{fmt.Errorf("%s.source is %q but ref is empty", field, s.Source)}
		}
	default:
		return []error{fmt.Errorf("%s.source %q is not generate, prompt, env, or file", field, s.Source)}
	}
	return nil
}

// validIdent guards the identifiers that reach SQL. Role and database names
// are interpolated into CREATE statements, which cannot be parameterised, so
// they are restricted to a character set that needs no quoting rather than
// escaped. Rejecting the input is safer than trusting an escape.
func validIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
