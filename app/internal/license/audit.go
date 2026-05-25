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
	switch result {
	case VerifyValid:
		emitInstalled(ctx, source, lic)
	case VerifyClockRollback:
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
