// @spec api-remediation
//
//	AC-14  TestRemediation_AlreadyCompliantIsNotAChange
package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-14
// AC-14: an already-compliant run must not offer a rollback.
//
// Kensa reports committed when a rule was already passing, which on its own is
// indistinguishable from a real fix. Reading that as a change marked the
// request executed, badged the rule fixed, and offered Roll back for a
// transaction that mutated nothing and captured no state to restore. Kensa
// never persisted such a record, so the rollback would act against a capture
// that does not describe a change.
func TestRemediation_AlreadyCompliantIsNotAChange(t *testing.T) {
	t.Run("api-remediation/AC-14", func(t *testing.T) {
		already := ExecTxn{
			TxnID:            uuid.Must(uuid.NewV7()),
			Status:           "committed",
			AlreadyCompliant: true,
		}
		real := ExecTxn{
			TxnID:  uuid.Must(uuid.NewV7()),
			Status: "committed",
		}

		got, known := OutcomeOf(already)
		if !known {
			t.Fatal("an already-compliant commit must be a recognised outcome")
		}
		if got != StatusNotApplied {
			t.Errorf("already-compliant maps to %q, want %q; %q keeps the Roll back button",
				got, StatusNotApplied, got)
		}

		// The distinction is the whole point: a real commit is still executed.
		if g, _ := OutcomeOf(real); g != StatusExecuted {
			t.Errorf("a real commit maps to %q, want %q", g, StatusExecuted)
		}

		// not_applied is deliberately outside the rollback-eligible set. If
		// this ever changes, the affordance returns and this test is the only
		// thing standing between an operator and a rollback of nothing.
		if StatusNotApplied == StatusExecuted || StatusNotApplied == StatusStaged {
			t.Error("not_applied must stay distinct from the rollback-eligible statuses")
		}
	})
}

// @ac AC-14
// AC-14 (companion): the operator is told why, not just that nothing happened.
func TestRemediation_AlreadyCompliantExplainsItself(t *testing.T) {
	t.Run("api-remediation/AC-14", func(t *testing.T) {
		final, reason := rollUpOutcome(context.Background(), []ExecTxn{{
			TxnID:            uuid.Must(uuid.NewV7()),
			Status:           "committed",
			AlreadyCompliant: true,
		}})
		if final != StatusNotApplied {
			t.Fatalf("roll-up produced %q, want %q", final, StatusNotApplied)
		}
		// "The engine declined to apply this rule" is true of a refusal and
		// wrong here: nothing declined, the host was already correct.
		if strings.Contains(reason, "declined") {
			t.Errorf("already-compliant reused the refusal wording: %q", reason)
		}
		for _, want := range []string{"already satisfied", "nothing to roll back"} {
			if !strings.Contains(strings.ToLower(reason), want) {
				t.Errorf("reason %q does not say %q", reason, want)
			}
		}

		// A refusal keeps its own sentence.
		_, refusedReason := rollUpOutcome(context.Background(), []ExecTxn{{
			TxnID: uuid.Must(uuid.NewV7()), Status: "committed", Refused: true,
		}})
		if !strings.Contains(refusedReason, "declined") {
			t.Errorf("a refusal should still read as a refusal: %q", refusedReason)
		}
	})
}
