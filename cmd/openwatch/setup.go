// `openwatch setup`: detect, plan, confirm, apply, prove, record.
//
// One plan object, three ways to fill it. Guided prompts with the detected
// values pre-filled, --yes takes them as-is, and --plan reads a saved file.
// All three then run identical validation and identical steps, so the
// unattended path is exercised by the same code a human just reviewed rather
// than being a separate, rarely-tested implementation.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Hanalyx/openwatch/internal/setup"
	"github.com/Hanalyx/openwatch/internal/version"
)

func cmdSetup(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		yes           = fs.Bool("yes", false, "accept every default without prompting")
		dryRun        = fs.Bool("dry-run", false, "show the plan and change nothing")
		planPath      = fs.String("plan", "", "apply a saved plan file (implies non-interactive)")
		savePlan      = fs.String("save-plan", "", "write the resolved plan to this path and exit")
		allowUntested = fs.Bool("allow-untested", false, "proceed on a platform CI does not cover")
		managePgHba   = fs.Bool("manage-pg-hba", false, "let setup edit pg_hba.conf (backed up, validated, rolled back on failure)")
		dbMode        = fs.String("db-mode", "", "provision | existing (default provision)")
		dbHost        = fs.String("db-host", "", "database host (default 127.0.0.1)")
		dbPort        = fs.Int("db-port", 0, "database port (default 5432)")
		dbName        = fs.String("db-name", "", "database name (default openwatch)")
		dbRole        = fs.String("db-role", "", "database role (default openwatch)")
		listenPort    = fs.Int("listen-port", 0, "HTTPS port (default 8443)")
		adminUser     = fs.String("admin-username", "", "first admin username (default admin)")
		adminEmail    = fs.String("admin-email", "", "first admin email")
		adminPwFrom   = fs.String("admin-password-from", "", "where the admin password comes from: prompt | generate | env:NAME | file:PATH")
		dbPwFrom      = fs.String("db-password-from", "", "where the database password comes from: generate | prompt | env:NAME | file:PATH")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	out := func(format string, a ...any) { fmt.Fprintf(stdout, format+"\n", a...) }
	ctx := context.Background()

	platform := setup.DetectPlatform()

	// Fill the plan: from a file, or from defaults plus flags.
	var plan setup.Plan
	if *planPath != "" {
		b, err := os.ReadFile(*planPath)
		if err != nil {
			fmt.Fprintf(stderr, "openwatch setup: read plan: %v\n", err)
			return 1
		}
		if err := yaml.Unmarshal(b, &plan); err != nil {
			fmt.Fprintf(stderr, "openwatch setup: parse plan: %v\n", err)
			return 1
		}
		// The platform is re-detected, never taken from the file: a plan saved
		// on one distro must not be applied to another on the strength of its
		// own say-so.
		if plan.Platform.ID != "" && plan.Platform.ID != platform.ID {
			fmt.Fprintf(stderr, "openwatch setup: plan was captured on %q but this host is %q; "+
				"re-run guided setup here, or edit the plan deliberately\n", plan.Platform.ID, platform.ID)
			return 1
		}
		plan.Platform = platform
	} else {
		plan = setup.DefaultPlan(platform)
	}

	applyFlagOverrides(&plan, flagOverrides{
		managePgHba: *managePgHba, dbMode: *dbMode, dbHost: *dbHost, dbPort: *dbPort,
		dbName: *dbName, dbRole: *dbRole, listenPort: *listenPort,
		adminUser: *adminUser, adminEmail: *adminEmail,
		adminPwFrom: *adminPwFrom, dbPwFrom: *dbPwFrom,
	}, fs)

	interactive := !*yes && *planPath == "" && isTerminal(os.Stdin)
	if interactive {
		if err := promptPlan(&plan, stdout, os.Stdin); err != nil {
			fmt.Fprintf(stderr, "openwatch setup: %v\n", err)
			return 1
		}
	}
	plan.Derive()

	if errs := plan.Validate(); len(errs) > 0 {
		fmt.Fprintln(stderr, "openwatch setup: the plan is not valid:")
		for _, e := range errs {
			fmt.Fprintf(stderr, "  - %v\n", e)
		}
		return 1
	}

	if *savePlan != "" {
		b, err := yaml.Marshal(plan)
		if err != nil {
			fmt.Fprintf(stderr, "openwatch setup: marshal plan: %v\n", err)
			return 1
		}
		header := "# OpenWatch setup plan. Contains no secrets: each credential records\n" +
			"# only where it comes from. Apply with: openwatch setup --plan <file>\n"
		if err := os.WriteFile(*savePlan, append([]byte(header), b...), 0o644); err != nil {
			fmt.Fprintf(stderr, "openwatch setup: write plan: %v\n", err)
			return 1
		}
		out("plan written to %s", *savePlan)
		return 0
	}

	checks := setup.Preflight(ctx, plan, *allowUntested)
	planned := setup.Resolve(ctx, plan)
	setup.RenderPlan(out, plan, checks, planned)

	if bad := setup.FatalFailures(checks); len(bad) > 0 {
		fmt.Fprintln(stderr, "openwatch setup: preflight failed:")
		for _, c := range bad {
			fmt.Fprintf(stderr, "  - %s: %s\n", c.Name, c.Detail)
		}
		return 1
	}

	if *dryRun {
		out("Dry run: nothing was changed.")
		return 0
	}

	if interactive && !confirm(stdout, os.Stdin, "Proceed?") {
		out("Aborted; nothing was changed.")
		return 1
	}

	r := &setup.Run{Plan: plan, Out: out}
	var prompt func(string) (string, error)
	if interactive {
		prompt = func(label string) (string, error) { return readSecret(stdout, os.Stdin, label) }
	}
	if err := setup.ResolveSecrets(ctx, r, prompt); err != nil {
		fmt.Fprintf(stderr, "openwatch setup: %v\n", err)
		return 1
	}

	out("")
	if err := setup.Execute(ctx, r, planned); err != nil {
		receipt, _ := setup.WriteReceipt(r, version.Version)
		// A pause is the operator's own choice coming due, not a fault, and
		// saying "failed" for it would send them looking for a bug.
		var pause *setup.PauseError
		if errors.As(err, &pause) {
			out("")
			out("Setup paused: %s", pause.Reason)
			out("Everything before this step is done. Complete the manual step above,")
			out("then run `openwatch setup` again to continue from here.")
			if receipt != "" {
				out("Progress recorded at %s", receipt)
			}
			return 3
		}
		fmt.Fprintf(stderr, "\nopenwatch setup: %v\n", err)
		if receipt != "" {
			fmt.Fprintf(stderr, "Partial run recorded at %s; setup is idempotent, so fix the "+
				"cause and run it again.\n", receipt)
		}
		return 1
	}

	receipt, err := setup.WriteReceipt(r, version.Version)
	if err != nil {
		out("warning: could not write the receipt: %v", err)
	}
	setup.RenderSummary(out, r, receipt)
	return 0
}

type flagOverrides struct {
	managePgHba            bool
	dbMode, dbHost, dbName string
	dbRole                 string
	dbPort, listenPort     int
	adminUser, adminEmail  string
	adminPwFrom, dbPwFrom  string
}

// parseSecretSpec turns a --*-password-from value into a Secret.
//
// Unattended installs need a way to supply credentials that is not a prompt,
// and the alternatives are worse: a --password flag lands the value in the
// process table and shell history, where any user on the box can read it.
// env: and file: keep it out of both.
func parseSecretSpec(spec string) (setup.Secret, error) {
	switch {
	case spec == "generate":
		return setup.Secret{Source: setup.SecretGenerate, Length: 32}, nil
	case spec == "prompt":
		return setup.Secret{Source: setup.SecretPrompt}, nil
	case strings.HasPrefix(spec, "env:"):
		return setup.Secret{Source: setup.SecretEnv, Ref: strings.TrimPrefix(spec, "env:")}, nil
	case strings.HasPrefix(spec, "file:"):
		return setup.Secret{Source: setup.SecretFile, Ref: strings.TrimPrefix(spec, "file:")}, nil
	default:
		return setup.Secret{}, fmt.Errorf("password source %q must be generate, prompt, env:NAME, or file:PATH", spec)
	}
}

// applyFlagOverrides applies only the flags actually passed, so a flag left
// alone never clobbers a value that came from a plan file.
func applyFlagOverrides(p *setup.Plan, o flagOverrides, fs *flag.FlagSet) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["manage-pg-hba"] {
		p.Database.ManagePgHba = o.managePgHba
	}
	if set["db-mode"] {
		p.Database.Mode = setup.DatabaseMode(o.dbMode)
	}
	if set["db-host"] {
		p.Database.Host = o.dbHost
	}
	if set["db-port"] {
		p.Database.Port = o.dbPort
	}
	if set["db-name"] {
		p.Database.Name = o.dbName
	}
	if set["db-role"] {
		p.Database.RoleName = o.dbRole
	}
	if set["listen-port"] {
		p.Service.ListenPort = o.listenPort
	}
	if set["admin-username"] {
		p.Admin.Username = o.adminUser
	}
	if set["admin-email"] {
		p.Admin.Email = o.adminEmail
	}
	if set["admin-password-from"] {
		if sec, err := parseSecretSpec(o.adminPwFrom); err == nil {
			p.Admin.Password = sec
		}
	}
	if set["db-password-from"] {
		if sec, err := parseSecretSpec(o.dbPwFrom); err == nil {
			p.Database.Password = sec
		}
	}
}

// promptPlan walks the plan by section rather than field, so the default path
// is a few keystrokes while every value stays reachable. Each section shows
// what it will do; Enter accepts, "e" opens it.
func promptPlan(p *setup.Plan, out *os.File, in *os.File) error {
	r := bufio.NewReader(in)

	fmt.Fprintf(out, "\nDatabase\n")
	fmt.Fprintf(out, "  mode      %s\n", p.Database.Mode)
	fmt.Fprintf(out, "  host:port %s:%d\n", p.Database.Host, p.Database.Port)
	fmt.Fprintf(out, "  database  %s\n", p.Database.Name)
	fmt.Fprintf(out, "  role      %s (password: %s)\n", p.Database.RoleName, p.Database.Password.Source)
	if ask(out, r, "  [Enter] accept, [e] edit: ") == "e" {
		p.Database.Mode = setup.DatabaseMode(askDefault(out, r, "  mode (provision|existing)", string(p.Database.Mode)))
		p.Database.Host = askDefault(out, r, "  host", p.Database.Host)
		p.Database.Port = askInt(out, r, "  port", p.Database.Port)
		p.Database.Name = askDefault(out, r, "  database name", p.Database.Name)
		p.Database.RoleName = askDefault(out, r, "  role name", p.Database.RoleName)
		if ask(out, r, "  supply the role password yourself instead of generating one? [y/N] ") == "y" {
			p.Database.Password = setup.Secret{Source: setup.SecretPrompt}
		}
	}

	fmt.Fprintf(out, "\nService\n")
	fmt.Fprintf(out, "  listen    %s:%d\n", p.Service.ListenHost, p.Service.ListenPort)
	if ask(out, r, "  [Enter] accept, [e] edit: ") == "e" {
		p.Service.ListenHost = askDefault(out, r, "  listen host", p.Service.ListenHost)
		p.Service.ListenPort = askInt(out, r, "  listen port", p.Service.ListenPort)
		p.Derive()
		if p.Service.BindCapability {
			fmt.Fprintf(out, "  note: port %d is privileged, so setup will add\n", p.Service.ListenPort)
			fmt.Fprintf(out, "        AmbientCapabilities=CAP_NET_BIND_SERVICE to the unit.\n")
		}
	}

	fmt.Fprintf(out, "\nAdministrator\n")
	fmt.Fprintf(out, "  username  %s\n", p.Admin.Username)
	fmt.Fprintf(out, "  email     %s\n", p.Admin.Email)
	if ask(out, r, "  [Enter] accept, [e] edit: ") == "e" {
		p.Admin.Username = askDefault(out, r, "  username", p.Admin.Username)
		p.Admin.Email = askDefault(out, r, "  email", p.Admin.Email)
	}
	fmt.Fprintln(out)
	return nil
}

func ask(out *os.File, r *bufio.Reader, prompt string) string {
	fmt.Fprint(out, prompt)
	line, _ := r.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line))
}

func askDefault(out *os.File, r *bufio.Reader, label, def string) string {
	fmt.Fprintf(out, "%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	if v := strings.TrimSpace(line); v != "" {
		return v
	}
	return def
}

func askInt(out *os.File, r *bufio.Reader, label string, def int) int {
	for {
		v := askDefault(out, r, label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		fmt.Fprintf(out, "  %q is not a number\n", v)
	}
}

func confirm(out *os.File, in *os.File, prompt string) bool {
	r := bufio.NewReader(in)
	answer := ask(out, r, prompt+" [y/N] ")
	return answer == "y" || answer == "yes"
}

// readSecret reads a credential. It does not disable terminal echo, and says
// so: silently pretending input is hidden when it is not would be worse than
// stating it plainly.
func readSecret(out *os.File, in *os.File, label string) (string, error) {
	fmt.Fprintf(out, "%s (input is visible): ", label)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	v := strings.TrimSpace(line)
	if v == "" {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	return v, nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
