package policy

import (
	"context"
	"encoding/json"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// emitLoaded is called by the loader on every successful load.
// Spec system-policy C-06.
func emitLoaded(ctx context.Context, t Type, newVersion, prevVersion string, warnings []string) {
	detail, _ := json.Marshal(map[string]any{
		"policy_type":      string(t),
		"new_version":      newVersion,
		"previous_version": prevVersion,
		"warnings":         warnings,
	})
	audit.Emit(ctx, audit.PolicyLoaded, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}

// emitInvalid is called on any failed load. The prior in-memory state
// is preserved by the loader; this audit row tells operators why a
// load attempt did not take effect.
// Spec system-policy C-07.
func emitInvalid(ctx context.Context, t Type, attemptedVersion string, errs []string) {
	detail, _ := json.Marshal(map[string]any{
		"policy_type":       string(t),
		"attempted_version": attemptedVersion,
		"errors":            errs,
	})
	audit.Emit(ctx, audit.PolicyInvalid, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}

// emitApplied is called by Evaluate on every decision.
// Spec system-policy C-08.
func emitApplied(ctx context.Context, d Decision) {
	detail, _ := json.Marshal(map[string]any{
		"policy_type":    string(d.PolicyType),
		"policy_version": d.PolicyVersion,
		"outcome":        string(d.Outcome),
		"reason":         d.Reason,
		"detail":         d.Detail,
	})
	audit.Emit(ctx, audit.PolicyApplied, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})
}
