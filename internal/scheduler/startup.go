package scheduler

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// PolicyLoadError classifies a policy-loading failure that would prevent
// the scheduler from starting. Values map 1:1 to the detail.reason enum
// on the scheduler.startup.failed audit event.
type PolicyLoadError string

const (
	// PolicyLoadOK means policy load succeeded (no startup refusal).
	PolicyLoadOK PolicyLoadError = ""

	// PolicyLoadMissing — no schedules policy file found at the
	// configured path.
	PolicyLoadMissing PolicyLoadError = "policy_missing"

	// PolicyLoadSignatureInvalid — file present but Ed25519 signature
	// did not verify against the active signing key.
	PolicyLoadSignatureInvalid PolicyLoadError = "signature_invalid"

	// PolicyLoadRevokedKey — Ed25519 signature is mathematically valid
	// but the signing key has been revoked. See spec AC-14.
	PolicyLoadRevokedKey PolicyLoadError = "revoked_key"

	// PolicyLoadParseError — file present and signed, but YAML parse
	// failed or the schema is invalid.
	PolicyLoadParseError PolicyLoadError = "parse_error"
)

// ErrStartupRefused is the sentinel error returned by Startup when the
// scheduler refuses to boot. cmd/openwatch/main.go checks for this with
// errors.Is and exits non-zero.
var ErrStartupRefused = errors.New("scheduler: startup refused")

// EmitFunc is the audit-emission shape the scheduler depends on. Matches
// audit.Emit's signature so cmd/openwatch wires the real audit emitter
// in by passing audit.Emit directly; tests pass a fake that records calls.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Startup performs pre-flight checks before the scheduler accepts the
// first cron tick.
//
// Spec ACs satisfied here:
//
//   - AC-10: when the schedules policy is missing or fails Ed25519
//     verification at boot, scheduler refuses to start and emits
//     scheduler.startup.failed audit event.
//
// Arguments:
//
//   - ctx: caller's context (typically cmd/openwatch's bootCtx)
//   - emit: audit emitter (audit.Emit in production)
//   - policyPath: filesystem path of the schedules policy, for audit detail
//   - reason: classification of the load failure; PolicyLoadOK means
//     success and Startup returns nil
//
// Return:
//
//   - nil if reason == PolicyLoadOK
//   - ErrStartupRefused (with the failure reason surfaced via the audit
//     event's detail.reason) otherwise
func Startup(ctx context.Context, emit EmitFunc, policyPath string, reason PolicyLoadError) error {
	if reason == PolicyLoadOK {
		return nil
	}

	// json.Marshal of map[string]string never returns an error for these
	// scalar values, but check defensively so the compiler doesn't blame
	// us if the type widens later.
	detail, _ := json.Marshal(map[string]string{
		"reason":      string(reason),
		"policy_path": policyPath,
	})

	emit(ctx, audit.SchedulerStartupFailed, audit.Event{
		ActorType: "system",
		Detail:    detail,
	})

	return ErrStartupRefused
}
