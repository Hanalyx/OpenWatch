// @spec api-remediation
//
//	AC-15  TestKensa_PreStateSummaryIsDerivedNotDecoded
package kensa

import (
	"os"
	"strings"
	"testing"

	kensaapi "github.com/Hanalyx/kensa/api"
)

// @ac AC-15
// AC-15: the capture is rendered by Kensa, never decoded here.
//
// The whole point of features/KN-OW-016 was that OpenWatch must not read
// mechanism-specific Data keys. Writing this test proved the argument: with
// Kensa's own list of key names in hand, guesses at config_set's layout still
// produced "prior state not captured", because the describer reads different
// keys than the names suggest. A TypeScript or Go decoder here would have been
// wrong on day one and would drift silently after.
func TestKensa_PreStateSummaryIsDerivedNotDecoded(t *testing.T) {
	t.Run("api-remediation/AC-15", func(t *testing.T) {
		// Non-capturable steps get a marker, not an empty string, so the UI
		// can distinguish "this mechanism cannot capture" from "no summary".
		got := mapPreStates([]kensaapi.PreState{
			{StepIndex: 0, Mechanism: "service_enabled", Capturable: false},
		})
		if len(got) != 1 {
			t.Fatalf("mapped %d pre-states, want 1", len(got))
		}
		if got[0].Summary == "" {
			t.Error("a non-capturable step must carry a marker, not an empty summary")
		}
		if got[0].Capturable {
			t.Error("capturable must survive the mapping")
		}

		// Data is carried verbatim alongside the summary. The summary is for
		// the screen; Data is what an auditor reads and what rollback needs.
		withData := mapPreStates([]kensaapi.PreState{{
			StepIndex: 1, Mechanism: "file_permissions", Capturable: true,
			Data: map[string]any{"path": "/etc/shadow", "mode": "0640"},
		}})
		if withData[0].Data["path"] != "/etc/shadow" {
			t.Error("Data must be carried verbatim, not replaced by the summary")
		}
		if withData[0].Summary == "" {
			t.Error("a capturable step with data should render a summary")
		}

		// This package must not read mechanism-specific keys to build display
		// text. Kensa owns that; we would drift against 24 private layouts.
		src := readSource(t, "remediatefunc.go")
		for _, forbidden := range []string{`Data["prior_line"]`, `Data["prior_value"]`, `Data["content"]`} {
			if strings.Contains(src, forbidden) {
				t.Errorf("this package decodes %s; that belongs to the handler", forbidden)
			}
		}
	})
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
