// @spec api-remediation
//
// Outcome-vocabulary coverage. These are pure mapping tests (no DB), so unlike
// service_test.go they are not DSN-gated.
//
//	AC-09  TestOutcome_StagedIsDistinctAndReversible
//	AC-10  TestOutcome_RemainingKensaStatusesMapOneToOne
//	AC-11  TestOutcome_UnknownStatusFailsClosed
package remediation

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-09
// AC-09: staged is its own terminal outcome, it counts as a host mutation, and
// it stays rollback-eligible. The bug this pins: Kensa v0.8.0 introduced
// `staged` (persist layer written, runtime not converged, HOST CHANGED) and
// OpenWatch mapped it through a default branch to "failed", told the operator
// "No host change was committed", journalled it as 'skipped', and then refused
// rollback because rollback required 'executed'.
func TestOutcome_StagedIsDistinctAndReversible(t *testing.T) {
	t.Run("api-remediation/AC-09", func(t *testing.T) {
		staged := ExecTxn{TxnID: uuid.New(), Status: "staged"}

		got, known := OutcomeOf(staged)
		if !known {
			t.Fatal("staged must be a recognised Kensa status")
		}
		if got != StatusStaged {
			t.Fatalf("staged mapped to %q, want %q", got, StatusStaged)
		}
		if got == StatusFailed {
			t.Error("staged must never map to failed: the host WAS changed")
		}

		// The host was mutated, so the operator has something to consider.
		if !got.HostMutated() {
			t.Error("staged must report HostMutated: the persist layer was written")
		}

		// Rollback must stay reachable; Kensa captured pre-state and reverses
		// a staged drop-in byte-perfect.
		if !got.RollbackEligible() {
			t.Error("staged must be rollback-eligible or the change is stranded on the host")
		}

		// The journal must record the real outcome, not the old 'skipped'
		// catch-all, or the evidence trail disagrees with the request.
		if p := phaseResult(staged); p != "staged" {
			t.Errorf("phase_result for staged = %q, want %q", p, "staged")
		}

		// The operator-facing sentence must not claim nothing happened.
		reason := outcomeReason(StatusStaged)
		if reason == outcomeReason(StatusFailed) {
			t.Error("staged must not reuse the failure message")
		}
		for _, forbidden := range []string{"No host change was committed"} {
			if strings.Contains(reason, forbidden) {
				t.Errorf("staged message must not claim no change was made: %q", reason)
			}
		}
	})
}

// @ac AC-10
// AC-10: the remaining Kensa statuses each map to their own request status and
// journal value, so "failed" stops meaning five different things. In particular
// rolled_back (Kensa auto-restored pre-state, host untouched) is NOT a failure
// of the same kind as errored, and it must not be reported as one.
func TestOutcome_RemainingKensaStatusesMapOneToOne(t *testing.T) {
	t.Run("api-remediation/AC-10", func(t *testing.T) {
		cases := []struct {
			kensa     string
			unchanged bool
			want      Status
			wantPhase string
			mutated   bool
		}{
			{"committed", false, StatusExecuted, "committed", true},
			{"rolled_back", true, StatusReverted, "reverted", false},
			{"recovered", true, StatusReverted, "reverted", false},
			{"partially_applied", false, StatusPartiallyApplied, "partially_applied", true},

			// errored maps the same either way. HostUnchanged is carried for
			// evidence but does NOT drive severity: it is a bool, so false is
			// ambiguous between "proved mutated" and "field never set", and an
			// errored transaction synthesised for an unreachable host arrives
			// with it unset. Escalating on that would send an operator to
			// inspect a host nothing touched.
			{"errored", true, StatusFailed, "skipped", false},
			{"errored", false, StatusFailed, "skipped", false},

			// rollback_failed: applied, then the reversal could not be
			// machine-verified. Kensa calls this "an unconfirmed state", which
			// is the most severe thing it reports. It must never read as a
			// plain failure, which an operator reasonably skims as "nothing
			// happened". This is the status that sat unmapped until
			// kensa-agent pointed it out.
			{"rollback_failed", false, StatusPartiallyApplied, "partially_applied", true},
		}
		for _, c := range cases {
			txn := ExecTxn{TxnID: uuid.New(), Status: c.kensa, HostUnchanged: c.unchanged}
			got, known := OutcomeOf(txn)
			if !known {
				t.Errorf("%s: must be a recognised Kensa status", c.kensa)
			}
			label := c.kensa
			if c.kensa == "errored" {
				label = fmt.Sprintf("errored(HostUnchanged=%v)", c.unchanged)
			}
			if got != c.want {
				t.Errorf("%s mapped to %q, want %q", label, got, c.want)
			}
			if got.HostMutated() != c.mutated {
				t.Errorf("%s HostMutated = %v, want %v", label, got.HostMutated(), c.mutated)
			}
			if p := phaseResult(txn); p != c.wantPhase {
				t.Errorf("%s phase_result = %q, want %q", label, p, c.wantPhase)
			}
		}

		// The distinction that matters most for the operator: an auto-revert
		// (safety net worked, host untouched) must not collapse into the same
		// status as an errored run.
		reverted, _ := OutcomeOf(ExecTxn{Status: "rolled_back"})
		errored, _ := OutcomeOf(ExecTxn{Status: "errored", HostUnchanged: true})
		if reverted == errored {
			t.Error("rolled_back and errored must not share a status: one left the host clean, the other did not")
		}

		// A refusal (engine declined without touching the host) is its own
		// outcome once Kensa gives us a signal for it.
		refused, known := OutcomeOf(ExecTxn{Status: "rolled_back", Refused: true})
		if !known || refused != StatusNotApplied {
			t.Errorf("a refused transaction must map to not_applied, got %q", refused)
		}
		if refused.HostMutated() {
			t.Error("not_applied must not report the host as mutated")
		}
	})
}

// @ac AC-11
// AC-11 (NEGATIVE PATH): an unrecognised Kensa status must not be silently
// absorbed. This is the guard whose absence caused the staged defect: a
// `default:` branch quietly swallowed a brand-new terminal state. The mapper
// must report the status as unknown so the caller logs it, and must fail
// CLOSED, never to a success-shaped outcome.
func TestOutcome_UnknownStatusFailsClosed(t *testing.T) {
	t.Run("api-remediation/AC-11", func(t *testing.T) {
		// Stand-in for whatever Kensa adds next.
		future := ExecTxn{TxnID: uuid.New(), Status: "quarantined_pending_attestation"}

		got, known := OutcomeOf(future)
		if known {
			t.Fatal("an unrecognised Kensa status must be reported as unknown, not silently mapped")
		}
		if got != StatusFailed {
			t.Errorf("unknown status must fail closed to %q, got %q", StatusFailed, got)
		}

		// Fail-closed means: never a success-shaped outcome, and never one that
		// claims the host is fine when we do not know that.
		for _, forbidden := range []Status{StatusExecuted, StatusStaged, StatusReverted, StatusNotApplied} {
			if got == forbidden {
				t.Errorf("unknown status must not map to %q", forbidden)
			}
		}
		if got.HostMutated() {
			t.Error("an unknown outcome must not assert the host was mutated; we do not know")
		}

		// Every status the CURRENT Kensa api package can produce must be
		// recognized. Read them out of the MODULE SOURCE, not from our own
		// constants.
		//
		// The first version of this loop iterated the kensa* constants
		// declared in this package, which made it vacuous: it asserted that
		// the statuses we already knew about were the statuses we already knew
		// about. It passed while `rollback_failed` sat unmapped, and
		// kensa-agent had to point that out. A self-referential completeness
		// check is worse than none, because it reports coverage it does not
		// have.
		for _, st := range kensaStatusesFromModule(t) {
			if _, ok := OutcomeOf(ExecTxn{Status: st}); !ok {
				t.Errorf("Kensa declares TransactionStatus %q and OutcomeOf does not map it; "+
					"add it explicitly rather than letting the default branch absorb it", st)
			}
		}
	})
}

// kensaStatusesFromModule parses every TransactionStatus constant out of the
// Kensa module source currently pinned in go.mod. Reading the real enum is the
// whole point: anything derived from our own constants cannot detect a status
// we failed to notice.
func kensaStatusesFromModule(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/Hanalyx/kensa").Output()
	if err != nil {
		t.Skipf("cannot locate the kensa module: %v", err)
	}
	path := filepath.Join(strings.TrimSpace(string(out)), "api", "transaction.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cannot read %s: %v", path, err)
	}
	re := regexp.MustCompile(`Status[A-Za-z]+\s+TransactionStatus\s*=\s*"([a-z_]+)"`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		got = append(got, m[1])
	}
	if len(got) == 0 {
		t.Fatalf("parsed no TransactionStatus constants from %s; the parser or the upstream shape changed", path)
	}
	return got
}
