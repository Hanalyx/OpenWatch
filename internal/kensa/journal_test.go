// @spec api-remediation
//
//	AC-12  TestKensa_JournalSurvivesTheBoundary
package kensa

import (
	"testing"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	"github.com/google/uuid"
)

// @ac AC-12
// AC-12: the per-phase journal survives mapping.
//
// This is the regression that made remediation a black box. mapTxns kept five
// fields and threw the rest away, and txnEvidence recorded len(t.Steps) -- the
// COUNT of steps -- so a failed remediation could say "reverted, host
// unchanged" and nothing else, while Kensa's own explanation sat in
// StepResult.Detail, a field its documentation describes as suitable for UI.
func TestKensa_JournalSurvivesTheBoundary(t *testing.T) {
	t.Run("api-remediation/AC-12", func(t *testing.T) {
		committed := time.Now()
		in := []kensaapi.TransactionResult{{
			TransactionID: uuid.Must(uuid.NewV7()),
			Status:        kensaapi.StatusRolledBack,
			StartedAt:     committed.Add(-2 * time.Second),
			FinishedAt:    committed,
			CommittedAt:   &committed,
			Steps: []kensaapi.StepResult{
				{StepIndex: 0, Mechanism: "config_set", Capturable: true, Success: true,
					Detail: "captured /etc/login.defs PASS_MAX_DAYS 99999"},
				{StepIndex: 1, Mechanism: "config_set", Capturable: true, Success: false,
					Detail: "validate failed: PASS_MAX_DAYS still 99999 after apply"},
				{StepIndex: 2, Mechanism: "service_enabled", Capturable: false,
					Success: true, Stranded: true, Staged: true,
					Detail: "auditd immutable (enabled 2); persisted, reboot required"},
			},
			PreStates: []kensaapi.PreState{
				{StepIndex: 0, Mechanism: "config_set", Capturable: true,
					Data: map[string]any{"line": "PASS_MAX_DAYS 99999"}},
				{StepIndex: 2, Mechanism: "service_enabled", Capturable: false},
			},
		}}

		got := mapTxns(in)
		if len(got) != 1 {
			t.Fatalf("mapTxns returned %d transactions, want 1", len(got))
		}
		txn := got[0]

		if len(txn.Steps) != 3 {
			t.Fatalf("carried %d steps, want 3; the journal is being dropped again",
				len(txn.Steps))
		}

		// The reason a remediation failed is the whole point.
		want := "validate failed: PASS_MAX_DAYS still 99999 after apply"
		if txn.Steps[1].Detail != want {
			t.Errorf("step 1 detail = %q, want %q", txn.Steps[1].Detail, want)
		}
		if txn.Steps[1].Success {
			t.Error("the failing step is reported as successful")
		}

		// Flags an operator cannot infer from the outcome alone: a stranded
		// step is NOT reversed by rollback, and a staged one means the running
		// host has not converged even though the change was written.
		if !txn.Steps[2].Stranded {
			t.Error("stranded lost; rollback will not reverse that step and nobody would know")
		}
		if !txn.Steps[2].Staged {
			t.Error("staged lost; a re-scan will report the rule failing with no explanation")
		}
		if txn.Steps[2].Capturable {
			t.Error("capturable lost; this is what makes a rule non-rollbackable")
		}

		// The capture: what the host looked like before anything changed.
		if len(txn.PreStates) != 2 {
			t.Fatalf("carried %d pre-states, want 2", len(txn.PreStates))
		}
		if txn.PreStates[0].Data["line"] != "PASS_MAX_DAYS 99999" {
			t.Errorf("pre-state data = %v, want the captured line verbatim",
				txn.PreStates[0].Data)
		}
		// Carried, not interpreted. A non-capturable step is a marker with no
		// data, and must still appear so the gap is visible.
		if txn.PreStates[1].Capturable || len(txn.PreStates[1].Data) != 0 {
			t.Error("a non-capturable pre-state must be carried as an empty marker")
		}

		if txn.StartedAt.IsZero() || txn.FinishedAt.IsZero() || txn.CommittedAt.IsZero() {
			t.Error("phase timings lost; the journal cannot show how long anything took")
		}
	})
}
