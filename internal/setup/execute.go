// Preflight, plan rendering, execution, and the receipt.
//
// The shape is deliberate and borrowed from tools that change infrastructure:
// detect, show what will happen, ask, then act, then prove it worked and write
// down what was touched. OpenWatch is a compliance product, so "what did the
// installer change on this host" is a question its own buyers' auditors ask.
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReceiptPath is where the record of an applied run lands.
const ReceiptPath = "/var/lib/openwatch/setup-receipt.json"

// Check is one preflight result.
type Check struct {
	Name string
	OK   bool
	// Fatal marks a failure that stops the run; a non-fatal failure is a
	// warning the operator should see but can proceed past.
	Fatal  bool
	Detail string
}

// credentialSourceCheck refuses a run that cannot obtain a credential it
// will need.
//
// The default plan reads the admin password from an interactive prompt, so a
// run that cannot prompt is doomed from the start. Left to itself it fails at
// ResolveSecrets, which is after the full plan has been rendered: the operator
// reads twelve steps and then an error about step zero. Worse, --yes advertises
// itself as accepting every default, and accepting the default admin password
// source is exactly what makes it fail.
//
// The fix is refusal here rather than a silent generate. There is no
// password-reset command, so a generated admin password that the operator
// never sees produces an account nobody can log into, and printing a
// credential to stdout to avoid that is not an improvement. An unattended
// install has to say where its credentials come from.
func credentialSourceCheck(p Plan, interactive bool) (Check, bool) {
	if interactive {
		return Check{}, false
	}
	for _, c := range []struct {
		what, flag string
		src        SecretSource
	}{
		{"admin password", "--admin-password-from", p.Admin.Password.Source},
		{"database password", "--db-password-from", p.Database.Password.Source},
	} {
		if c.src == SecretPrompt {
			return Check{
				Name:  c.what + " source",
				OK:    false,
				Fatal: true,
				Detail: "this run cannot prompt (--yes, --plan, or stdin is not a " +
					"terminal) but the " + c.what + " comes from an interactive " +
					"prompt. Pass " + c.flag + " with generate, env:NAME or file:PATH",
			}, true
		}
	}
	return Check{}, false
}

// Preflight inspects the host before anything is planned. It never mutates.
//
// AllowUntested lets a recognized-but-unverified distro proceed: refusing
// outright would block Rocky and Alma users running identical paths, while
// claiming to support them would be a promise CI does not keep.
//
// Interactive says whether this run can prompt, which decides whether a
// prompt-sourced credential is obtainable.
func Preflight(ctx context.Context, p Plan, allowUntested, interactive bool) []Check {
	var out []Check

	if c, bad := credentialSourceCheck(p, interactive); bad {
		out = append(out, c)
	}

	root := os.Geteuid() == 0
	rootCheck := Check{Name: "running as root", OK: root, Fatal: true}
	if !root {
		rootCheck.Detail = "setup installs packages, writes to /etc/openwatch, and manages " +
			"systemd units. Re-run with sudo"
	}
	out = append(out, rootCheck)

	switch p.Platform.Support {
	case SupportTested:
		out = append(out, Check{Name: "platform " + p.Platform.String(), OK: true, Detail: "tested"})
	case SupportUntested:
		out = append(out, Check{
			Name: "platform " + p.Platform.String(), OK: allowUntested, Fatal: true,
			Detail: "recognised but NOT covered by CI. Re-run with --allow-untested to proceed, " +
				"and please report the result",
		})
	default:
		out = append(out, Check{
			Name: "platform " + p.Platform.String(), OK: false, Fatal: true,
			Detail: "unsupported: setup does not know this distribution's PostgreSQL layout",
		})
	}

	_, binErr := os.Stat(openwatchBin)
	binCheck := Check{Name: "openwatch binary installed", OK: binErr == nil, Fatal: true}
	if binErr != nil {
		binCheck.Detail = openwatchBin + " not found. Install the package first: setup " +
			"configures OpenWatch, it does not install it"
	}
	out = append(out, binCheck)

	// A port held by openwatch itself is not a conflict: that is a re-run.
	free := portFree(p.Service.ListenPort)
	ours := serviceActive("openwatch")
	portCheck := Check{
		Name:  fmt.Sprintf("port %d available", p.Service.ListenPort),
		OK:    free || ours,
		Fatal: true,
	}
	switch {
	case !portCheck.OK:
		portCheck.Detail = "another process is listening; choose a different port with " +
			"--listen-port, or stop it"
	case ours && !free:
		portCheck.Detail = "held by the running openwatch service (this is a re-run)"
	}
	out = append(out, portCheck)

	// A fapolicyd host denies execution of anything absent from its trust
	// database, which is built from the package database. A packaged install
	// is fine; a hand-copied binary is not, and the failure looks like a
	// permission error rather than a policy one.
	if p.Platform.Fapolicyd {
		out = append(out, Check{
			Name: "fapolicyd is active", OK: true,
			Detail: "packaged installs are trusted; a hand-copied binary would be denied",
		})
	}

	// A FIPS host running a non-FIPS build defeats the point of the host.
	if p.Platform.FIPS {
		out = append(out, Check{
			Name: "kernel FIPS mode enabled", OK: true,
			Detail: "install the FIPS build (openwatch-fips) if this host has FIPS obligations; " +
				"note md5 password authentication cannot work here, which is why setup " +
				"always hashes scram-sha-256",
		})
	}

	if p.Platform.SELinux == "enforcing" {
		out = append(out, Check{Name: "SELinux enforcing", OK: true,
			Detail: "the packaged install ships with the file contexts it needs"})
	}
	return out
}

// FatalFailures returns the checks that block the run.
func FatalFailures(checks []Check) []Check {
	var bad []Check
	for _, c := range checks {
		if !c.OK && c.Fatal {
			bad = append(bad, c)
		}
	}
	return bad
}

// PlannedStep pairs a step with its current status, so the rendered plan can
// distinguish what will happen from what is already true.
type PlannedStep struct {
	Step   Step
	Status StepStatus
}

// Resolve inspects every step without mutating, producing the plan to show.
func Resolve(ctx context.Context, p Plan) []PlannedStep {
	steps := Steps(p)
	out := make([]PlannedStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, PlannedStep{Step: s, Status: s.Status(ctx, p)})
	}
	return out
}

// RenderPlan writes the human-facing plan.
func RenderPlan(w func(string, ...any), p Plan, checks []Check, planned []PlannedStep) {
	w("OpenWatch setup: %s", p.Platform.String())
	w("")
	w("Preflight")
	for _, c := range checks {
		mark := "ok"
		if !c.OK {
			mark = "FAIL"
			if !c.Fatal {
				mark = "warn"
			}
		}
		w("  [%-4s] %s", mark, c.Name)
		if !c.OK || c.Detail != "" {
			w("           %s", c.Detail)
		}
	}
	w("")
	w("Plan")
	n := 0
	for _, ps := range planned {
		if ps.Status.Done {
			w("  [skip] %s", ps.Status.Detail)
			continue
		}
		n++
		w("  %2d. %s", n, ps.Step.Describe(p))
		if ps.Status.Detail != "" {
			w("      (%s)", ps.Status.Detail)
		}
	}
	if n == 0 {
		w("  nothing to do; this host is already configured")
	}
	w("")
	w("Database   %s@%s:%d/%s (sslmode=%s)",
		p.Database.RoleName, p.Database.Host, p.Database.Port, p.Database.Name, p.Database.SSLMode)
	w("Service    https://%s:%d/", p.Service.ListenHost, p.Service.ListenPort)
	w("Admin      %s <%s>", p.Admin.Username, p.Admin.Email)
	w("")
}

// PauseError stops the run for a manual step the operator chose to own,
// rather than for a failure.
//
// The distinction is not cosmetic. Without it, declining to manage pg_hba.conf
// means setup writes the DSN, then fails at the migration step with "Ident
// authentication failed for user openwatch" -- an error two steps downstream of
// its cause, naming the role rather than the host-based authentication rules.
// Halting at the step that needs the operator keeps the message next to the
// problem, and because every step is idempotent, re-running afterwards
// continues from here.
type PauseError struct {
	Step   string
	Reason string
}

func (e *PauseError) Error() string {
	return fmt.Sprintf("%s: %s", e.Step, e.Reason)
}

// Execute applies the steps that are not already satisfied.
func Execute(ctx context.Context, r *Run, planned []PlannedStep) error {
	for _, ps := range planned {
		if ps.Status.Done {
			r.logf("  [skip] %s", ps.Step.ID())
			continue
		}
		r.logf("  [ run] %s", ps.Step.ID())
		if err := ps.Step.Apply(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// Receipt is the record of an applied run. It holds no secrets: the resolved
// plan records how each credential was obtained, never what it was.
type Receipt struct {
	AppliedAt string   `json:"applied_at"`
	Version   string   `json:"openwatch_version"`
	Platform  Platform `json:"platform"`
	Plan      Plan     `json:"plan"`
	Changes   []Change `json:"changes"`
	URL       string   `json:"url"`
}

// newReceipt assembles the record from the run. Split out from WriteReceipt so
// the no-secrets property (C-02) can be asserted against the real thing rather
// than against a hand-built copy of it.
func newReceipt(r *Run, version string) Receipt {
	return Receipt{
		AppliedAt: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
		Platform:  r.Plan.Platform,
		Plan:      r.Plan,
		Changes:   r.Changes,
		URL:       fmt.Sprintf("https://%s:%d/", hostnameOr(r.Plan.Service.ListenHost), r.Plan.Service.ListenPort),
	}
}

// WriteReceipt records what happened, for support and for audit.
func WriteReceipt(r *Run, version string) (string, error) {
	if r.DryRun {
		return "", nil
	}
	rec := newReceipt(r, version)
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(ReceiptPath), 0o750); err != nil {
		return "", err
	}
	// Root-only. The receipt carries no credential (C-02), but it does name
	// every path the installer touched, and nothing reads it as the service
	// user, so there is no reason to widen it.
	if err := os.WriteFile(ReceiptPath, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	return ReceiptPath, nil
}

// RenderSummary prints what an operator needs after a successful run.
func RenderSummary(w func(string, ...any), r *Run, receipt string) {
	w("")
	w("Done.")
	w("")
	w("  URL       https://%s:%d/", hostnameOr(r.Plan.Service.ListenHost), r.Plan.Service.ListenPort)
	w("  Admin     %s <%s>", r.Plan.Admin.Username, r.Plan.Admin.Email)
	w("  Database  %s@%s:%d/%s", r.Plan.Database.RoleName, r.Plan.Database.Host,
		r.Plan.Database.Port, r.Plan.Database.Name)
	if len(r.Changes) > 0 {
		w("")
		w("  Changed:")
		for _, c := range r.Changes {
			line := fmt.Sprintf("    %-10s %s %s", c.Step, c.Action, c.Target)
			if c.Backup != "" {
				line += fmt.Sprintf("  (backup: %s)", c.Backup)
			}
			w("%s", line)
		}
	}
	if receipt != "" {
		w("")
		w("  Receipt: %s", receipt)
	}
}

// hostnameOr renders the address an operator should actually browse to.
//
// A wildcard listen address is not usable in a URL, so it has to be resolved
// to something. os.Hostname alone is not enough: it returns the kernel's
// transient hostname, which on a real RHEL host was observed to be the single
// letter "i" while the static hostname was a proper FQDN. Printing
// https://i:8443/ helps nobody. Prefer a routable address, which is what the
// operator will type, and fall back through the hostname to loopback.
func hostnameOr(listen string) string {
	if listen != "0.0.0.0" && listen != "::" && listen != "" {
		return listen
	}
	if ip := primaryIP(); ip != "" {
		return ip
	}
	if h, err := os.Hostname(); err == nil && strings.Contains(h, ".") {
		return h
	}
	return "127.0.0.1"
}

// primaryIP returns the address the host would use to reach the outside world,
// found without sending anything: a UDP "connection" only selects a route.
func primaryIP() string {
	c, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer c.Close()
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil && !addr.IP.IsLoopback() {
		return addr.IP.String()
	}
	return ""
}

func portFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// ResolveSecrets fills the run's credentials from their declared sources. It
// is the only place a secret enters the process, and nothing here writes one
// to the plan, the receipt, or the log.
func ResolveSecrets(ctx context.Context, r *Run, prompt func(label string) (string, error)) error {
	var err error
	if r.DBPassword, err = resolveDBPassword(ctx, r.Plan, prompt); err != nil {
		return err
	}
	if r.AdminPassword, err = resolveSecret("admin password", r.Plan.Admin.Password, prompt); err != nil {
		return err
	}
	return nil
}

// resolveDBPassword reuses the password already in secrets.env when the role
// exists and the plan asks for a generated one.
//
// Without this, a second run generates a fresh password, skips the role step
// because the role already exists, and writes the new password into the DSN.
// The role then holds the old password and the DSN the new one, and the next
// step fails with "password authentication failed for user openwatch" -- the
// same symptom as a mistyped password, from an installer that had just
// succeeded. Reuse also means re-running setup does not silently rotate a
// credential that other things may depend on.
func resolveDBPassword(ctx context.Context, p Plan, prompt func(string) (string, error)) (string, error) {
	if p.Database.Password.Source == SecretGenerate {
		if pw, ok := existingDSNPassword(secretsEnvPath); ok && roleExists(ctx, p.Database.RoleName) {
			return pw, nil
		}
	}
	return resolveSecret("database password", p.Database.Password, prompt)
}

// existingDSNPassword recovers the password from a previously written
// secrets.env. Parsed as a URI rather than by string surgery, so a password
// containing reserved characters is decoded the same way the server decodes it.
func existingDSNPassword(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		raw, found := strings.CutPrefix(line, "OPENWATCH_DATABASE_DSN=")
		if !found {
			continue
		}
		u, err := url.Parse(strings.Trim(raw, `"'`))
		if err != nil || u.User == nil {
			return "", false
		}
		if pw, set := u.User.Password(); set && pw != "" {
			return pw, true
		}
	}
	return "", false
}

func resolveSecret(label string, s Secret, prompt func(string) (string, error)) (string, error) {
	switch s.Source {
	case SecretGenerate:
		return generatePassword(s.Length)
	case SecretPrompt:
		if prompt == nil {
			return "", fmt.Errorf("%s: source is prompt but this run is non-interactive; "+
				"use source generate, env, or file", label)
		}
		return prompt(label)
	case SecretEnv:
		v, ok := os.LookupEnv(s.Ref)
		if !ok || v == "" {
			return "", fmt.Errorf("%s: environment variable %s is unset or empty", label, s.Ref)
		}
		return v, nil
	case SecretFile:
		b, err := os.ReadFile(s.Ref)
		if err != nil {
			return "", fmt.Errorf("%s: read %s: %w", label, s.Ref, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	default:
		return "", fmt.Errorf("%s: unknown source %q", label, s.Source)
	}
}
