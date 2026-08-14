// @spec system-policy
//
// AC traceability:
//   AC-14  TestPolicyAuditDetailsMatchDeclaredSchema

package policy

import (
	"context"
	"reflect"
	"testing"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// @ac AC-14
// AC-14: each policy event's declared detail_schema matches what its emitter
// sends, in both directions.
//
// C-06, C-07 and C-08 name the keys each event must carry, and audit/events.yaml
// disagreed with all three: policy.loaded declared policy_version and sent
// new_version, policy.applied declared decision and sent outcome, and
// policy.invalid declared nothing at all. See CP bugs/OW-021.
//
// The runtime check from bugs/OW-018 catches only one direction, emitted keys
// that are not declared. It cannot see a declared key nothing sends, which is
// the direction that produces consumers waiting for a field that never arrives.
// Asserting the exact key set catches both.
func TestPolicyAuditDetailsMatchDeclaredSchema(t *testing.T) {
	t.Run("system-policy/AC-14", func(t *testing.T) {
		// The expected sets come from the spec constraints, not from
		// events.yaml, so this fails if the declaration drifts from the
		// contract rather than agreeing with whatever it currently says.
		want := map[audit.Code][]string{
			audit.PolicyLoaded:  {"new_version", "policy_type", "previous_version", "warnings"},
			audit.PolicyInvalid: {"attempted_version", "errors", "policy_type"},
			audit.PolicyApplied: {"detail", "outcome", "policy_type", "policy_version", "reason"},
		}
		for code, keys := range want {
			meta, ok := audit.Metadata[code]
			if !ok {
				t.Errorf("%s is not in the audit registry", code)
				continue
			}
			if !reflect.DeepEqual(meta.DetailKeys, keys) {
				t.Errorf("%s DetailKeys = %v, want %v", code, meta.DetailKeys, keys)
			}
		}

		// And the emitters agree. Every policy event goes through the
		// runtime check, so a violation here means the code and the
		// declaration parted company even though the declaration still
		// matches the spec.
		before := audit.DetailViolations()
		ctx := context.Background()
		emitLoaded(ctx, TypeAlertThresholds, "1.1.0", "1.0.0", []string{"a warning"})
		emitInvalid(ctx, TypeAlertThresholds, "0.9.0", []string{"an error"})
		emitApplied(ctx, Decision{
			PolicyType: TypeAlertThresholds, PolicyVersion: "1.1.0",
			Outcome: OutcomeAlertOK, Reason: "within band",
			Detail: map[string]any{"score": 91},
		})
		if got := audit.DetailViolations(); got != before {
			t.Errorf("emitting the three policy events raised the violation count %d -> %d; "+
				"an emitter sends a key its schema does not declare", before, got)
		}
	})
}
