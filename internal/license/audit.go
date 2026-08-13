package license

import (
	"context"
	"log/slog"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitLoadResult emits the appropriate license.* audit event after a Load
// attempt. Critical events (install, signature failure, clock rollback)
// use EmitSync so they're durable before the load function returns.
func EmitLoadResult(ctx context.Context, source string, result VerifyResult, lic *License, err error) {
	// A rollback is a warning, not a denial (decision record 06), so the load
	// reports Valid and the switch below would never reach the rollback arm.
	// Emit it here, before and in addition to license.installed, or the one
	// signal an operator has that their clock moved would vanish exactly when
	// the fail-open policy makes it the only signal left.
	if lic != nil && lic.ClockRollbackDetected {
		emitClockRollback(ctx, source, err)
	}

	switch result {
	case VerifyValid:
		emitInstalled(ctx, source, lic)
	case VerifyClockRollback:
		// Still reachable via VerifyOnly, which applies no policy.
		emitClockRollback(ctx, source, err)
	case VerifyFingerprintMismatch:
		emitTampered(ctx, source, "fingerprint_mismatch")
	case VerifySignatureInvalid:
		emitInvalid(ctx, source, "signature_invalid", err)
	case VerifyExpired:
		emitExpired(ctx, source)
	default:
		emitInvalid(ctx, source, string(result), err)
	}
}

func emitInstalled(ctx context.Context, source string, lic *License) {
	detail := map[string]any{"source": source}
	if lic != nil {
		detail["tier"] = string(lic.Tier)
		detail["customer_id"] = lic.CustomerID
		detail["features_count"] = len(lic.Features)
		detail["using_prev_key"] = lic.UsingPrevKey
		detail["in_grace_period"] = lic.InGracePeriod
		// The kid the token presented, when it did not name the key that
		// verified. Only set when there is something to report, so a normal
		// load carries no extra field and the presence of the key is the
		// signal. The consumer is Hanalyx, not the operator: a mislabel means
		// the issuer stamped the wrong thumbprint, and says nothing about
		// whether this deployment's license is good.
		if lic.MismatchedKeyID != "" {
			detail["mismatched_key_id"] = lic.MismatchedKeyID
		}
	}
	if err := audit.EmitSync(ctx, audit.LicenseInstalled, audit.Event{
		ActorType: "system",
		Detail:    audit.MakeDetail(detail),
	}); err != nil {
		slog.WarnContext(ctx, "license: emit license.installed failed", slog.String("error", err.Error()))
	}
}

func emitClockRollback(ctx context.Context, source string, err error) {
	detail := map[string]any{"source": source}
	if err != nil {
		detail["error"] = err.Error()
	}
	if e := audit.EmitSync(ctx, audit.LicenseClockRollbackDetected, audit.Event{
		ActorType: "system",
		Detail:    audit.MakeDetail(detail),
	}); e != nil {
		slog.ErrorContext(ctx, "license: emit clock-rollback failed", slog.String("error", e.Error()))
	}
}

func emitTampered(ctx context.Context, source, reason string) {
	if err := audit.EmitSync(ctx, audit.LicenseTampered, audit.Event{
		ActorType: "system",
		Detail:    audit.MakeDetail(map[string]any{"source": source, "reason": reason}),
	}); err != nil {
		slog.ErrorContext(ctx, "license: emit tampered failed", slog.String("error", err.Error()))
	}
}

func emitInvalid(ctx context.Context, source, reason string, err error) {
	detail := map[string]any{"source": source, "reason": reason}
	if err != nil {
		detail["error"] = err.Error()
	}
	if e := audit.EmitSync(ctx, audit.LicenseInvalid, audit.Event{
		ActorType: "system",
		Detail:    audit.MakeDetail(detail),
	}); e != nil {
		slog.WarnContext(ctx, "license: emit license.invalid failed", slog.String("error", e.Error()))
	}
}

func emitExpired(ctx context.Context, source string) {
	if err := audit.EmitSync(ctx, audit.LicenseExpired, audit.Event{
		ActorType: "system",
		Detail:    audit.MakeDetail(map[string]any{"source": source}),
	}); err != nil {
		slog.WarnContext(ctx, "license: emit license.expired failed", slog.String("error", err.Error()))
	}
}
