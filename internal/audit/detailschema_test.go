// @spec system-audit-emission
//
// AC traceability (this file):
//
//	AC-17  TestDetailSchema_IsEnforced
package audit

import (
	"context"
	"encoding/json"
	"testing"
)

// @ac AC-17
// AC-17: the declared detail_schema is read and enforced.
//
// Before this, scripts/gen-audit-events.go parsed detail_schema into a struct
// field and emitted nothing from it, so 80 events declared a detail contract
// that nothing checked. The generated-code pipeline made the declaration read
// as enforcement while enforcing nothing, which is the shape this codebase
// keeps producing.
func TestDetailSchema_IsEnforced(t *testing.T) {
	t.Run("system-audit-emission/AC-17", func(t *testing.T) {
		// The generator emits a key set for every event that declares one, and
		// for no event that does not. Asserting the counts match keeps a
		// silently-dropped schema from passing: if the template stopped
		// emitting DetailKeys, every count below would be zero and the
		// subset checks would all pass vacuously.
		declared := 0
		for _, m := range Metadata {
			if len(m.DetailKeys) > 0 {
				declared++
			}
		}
		if declared == 0 {
			t.Fatal("no event carries DetailKeys; the generator is not emitting " +
				"detail_schema, so every check below would pass against nothing")
		}

		// A code that declares a schema, chosen from the registry rather than
		// hardcoded so this does not rot when events.yaml changes.
		var withSchema Code
		var keys []string
		for c, m := range Metadata {
			if len(m.DetailKeys) > 0 {
				withSchema, keys = c, m.DetailKeys
				break
			}
		}

		ctx := context.Background()

		// A subset of the declared keys is not a violation. An event that
		// carries a key only on some outcomes is normal, and demanding every
		// declared key would push emitters to send nulls.
		before := DetailViolations()
		checkDetailSchema(ctx, withSchema, mustJSON(t, map[string]any{keys[0]: "x"}))
		if got := DetailViolations(); got != before {
			t.Errorf("a subset of declared keys counted as a violation: %d -> %d", before, got)
		}

		// An undeclared key is a violation.
		before = DetailViolations()
		checkDetailSchema(ctx, withSchema, mustJSON(t, map[string]any{"definitely_not_declared": 1}))
		if got := DetailViolations(); got != before+1 {
			t.Errorf("an undeclared key did not count as a violation: %d -> %d, want %d",
				before, got, before+1)
		}

		// An event declaring no schema is never checked, so an absent
		// declaration and an empty one behave alike.
		var noSchema Code
		for c, m := range Metadata {
			if len(m.DetailKeys) == 0 {
				noSchema = c
				break
			}
		}
		if noSchema == "" {
			t.Skip("every event declares a schema; nothing to check here")
		}
		before = DetailViolations()
		checkDetailSchema(ctx, noSchema, mustJSON(t, map[string]any{"anything": true}))
		if got := DetailViolations(); got != before {
			t.Errorf("an event with no declared schema was checked: %d -> %d", before, got)
		}
	})
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
