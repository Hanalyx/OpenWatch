// Execution context and command helpers for `openwatch setup`.
//
// Every mutation the installer makes goes through Run, so that three things
// are true without each step remembering to do them: the command is recorded
// for the receipt, --dry-run performs no writes, and a step that has already
// been applied is skipped rather than repeated.
//
// Idempotence is not a nicety here. The most common moment to run setup is
// after a previous attempt failed part-way, which is exactly when a
// fresh-machine-only installer is useless.
package setup

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Change records one mutation for the receipt, so an operator (or an auditor)
// can answer "what did this touch" without reconstructing it from logs.
type Change struct {
	Step   string `json:"step"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Backup string `json:"backup,omitempty"`
}

// Run carries everything a step needs and everything it produces.
type Run struct {
	Plan Plan
	// DryRun performs detection and planning but no writes.
	DryRun bool
	// Secrets resolved at apply time. Never serialised anywhere.
	DBPassword    string
	AdminPassword string

	// Changes accumulates what actually happened.
	Changes []Change
	// Out receives progress lines.
	Out func(format string, args ...any)
}

func (r *Run) logf(format string, args ...any) {
	if r.Out != nil {
		r.Out(format, args...)
	}
}

func (r *Run) record(step, action, target, backup string) {
	r.Changes = append(r.Changes, Change{Step: step, Action: action, Target: target, Backup: backup})
}

// provisionedCluster reports whether THIS run brought PostgreSQL up, rather
// than finding it already there.
//
// It decides whether editing pg_hba.conf needs the operator's blessing. The
// caution exists to protect a cluster that predates OpenWatch and serves other
// things; a cluster this run installed or initialised seconds ago has no such
// history and no access to lose.
func (r *Run) provisionedCluster() bool {
	for _, c := range r.Changes {
		if c.Step == "postgres-install" || (c.Step == "postgres-cluster" && c.Action == "initdb") {
			return true
		}
	}
	return false
}

// cmdResult is the outcome of one external command.
type cmdResult struct {
	Stdout string
	Stderr string
	Err    error
}

// run executes a command, capturing both streams. It does NOT respect DryRun:
// callers use it for detection (which must run in dry-run) and use mutate()
// for changes.
func run(ctx context.Context, name string, args ...string) cmdResult {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err}
}

// mutate runs a state-changing command, or reports what it would run when
// DryRun is set. Every write in the installer goes through here.
func (r *Run) mutate(ctx context.Context, step, what string, name string, args ...string) error {
	if r.DryRun {
		r.logf("    would run: %s %s", name, strings.Join(args, " "))
		return nil
	}
	res := run(ctx, name, args...)
	if res.Err != nil {
		detail := res.Stderr
		if detail == "" {
			detail = res.Stdout
		}
		return fmt.Errorf("%s: %s failed: %v: %s", step, what, res.Err, firstLine(detail))
	}
	return nil
}

// psql runs SQL as the PostgreSQL superuser over the local socket.
//
// runuser rather than sudo. setup already runs as root, so there is no
// privilege to acquire, and sudo drags in a PAM stack that is not guaranteed
// to be configured: on minimal AlmaLinux and Oracle Linux images `sudo -u
// postgres` fails with "PAM account management error: Authentication service
// cannot retrieve authentication info" while runuser works. It also removes a
// dependency on sudo being installed at all.
//
// Deliberately invoked from a directory the postgres user can read: running it
// from root's home produces "could not change directory to /root: Permission
// denied" on every call, which is harmless but reads as a failure and has sent
// more than one operator down the wrong path.
func psql(ctx context.Context, sql string) cmdResult {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "runuser", "-u", "postgres", "--", "psql", "-tAqc", sql)
	cmd.Dir = "/tmp"
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err}
}

// psqlIn runs SQL against a NAMED database as the superuser.
//
// psql without -d connects to the "postgres" maintenance database. The cluster
// objects (roles, databases, settings) live there, but the application's own
// tables do not, so an idempotence check for a row in the openwatch database
// has to say so. Getting this wrong is silent: the query errors with "relation
// does not exist", the step reads that as not-yet-done, and re-running the
// installer tries to create something that is already there.
func psqlIn(ctx context.Context, database, sql string) cmdResult {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "runuser", "-u", "postgres", "--", "psql", "-d", database, "-tAqc", sql)
	cmd.Dir = "/tmp"
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err}
}

// psqlMutate runs superuser SQL honouring DryRun.
func (r *Run) psqlMutate(ctx context.Context, step, what, sql string) error {
	if r.DryRun {
		r.logf("    would run SQL: %s", firstLine(sql))
		return nil
	}
	if res := psql(ctx, sql); res.Err != nil {
		detail := res.Stderr
		if detail == "" {
			detail = res.Stdout
		}
		return fmt.Errorf("%s: %s failed: %s", step, what, firstLine(detail))
	}
	return nil
}

// writeFile writes a file with an explicit mode, honouring DryRun, backing up
// any existing content first so a mistake is recoverable.
func (r *Run) writeFile(step, path string, content []byte, mode os.FileMode) error {
	if r.DryRun {
		r.logf("    would write %s (mode %#o, %d bytes)", path, mode, len(content))
		return nil
	}
	backup := ""
	if existing, err := os.ReadFile(path); err == nil {
		backup = fmt.Sprintf("%s.bak-%s", path, timestamp())
		if err := os.WriteFile(backup, existing, 0o600); err != nil {
			return fmt.Errorf("%s: back up %s: %w", step, path, err)
		}
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("%s: write %s: %w", step, path, err)
	}
	// WriteFile does not apply the mode to an existing file.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("%s: chmod %s: %w", step, path, err)
	}
	r.record(step, "write", path, backup)
	return nil
}

// generatePassword returns a random password from an alphabet chosen to avoid
// shell and URI trouble entirely.
//
// The DSN builder encodes correctly regardless (see DatabasePlan.DSN), so this
// is belt and braces: a generated password also ends up in systemd's
// EnvironmentFile, gets pasted into terminals by operators debugging, and
// appears in support tickets. Excluding quotes, backslashes and the URI
// reserved set removes a class of confusion that is not worth the entropy.
func generatePassword(n int) (string, error) {
	if n <= 0 {
		n = 32
	}
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_."
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

func timestamp() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// sqlLiteral quotes a string for inclusion in SQL, doubling embedded quotes.
// Used only for passwords: identifiers are restricted by validIdent instead,
// because rejecting a hostile identifier is safer than escaping one.
func sqlLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sleep waits, but returns early if the context is cancelled so a Ctrl-C
// during the verify poll is responsive.
func sleep(ctx context.Context, seconds int) {
	t := time.NewTimer(time.Duration(seconds) * time.Second)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
