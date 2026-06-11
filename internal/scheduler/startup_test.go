// @spec system-scheduler
//
// AC traceability (this file):
//   AC-10  TestStartup_PolicyOK_ReturnsNilAndDoesNotEmit
//          TestStartup_PolicyMissing_RefusesAndEmits
//          TestStartup_SignatureInvalid_RefusesAndEmits
//          TestStartup_ParseError_RefusesAndEmits
//          TestStartup_RevokedKey_RefusesAndEmits

package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// emitCall is a captured audit emission used by the fake emitter.
type emitCall struct {
	Code  audit.Code
	Event audit.Event
}

// fakeEmitter returns an EmitFunc that appends every call to *calls.
// Closure pattern keeps the test bodies short.
func fakeEmitter(calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}
}

// @ac AC-10
// AC-10 (success path): when policy load succeeded (PolicyLoadOK),
// Startup returns nil and emits NO audit event.
func TestStartup_PolicyOK_ReturnsNilAndDoesNotEmit(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		var calls []emitCall

		err := Startup(context.Background(), fakeEmitter(&calls), "/opt/openwatch/policies/schedules.yaml", PolicyLoadOK)

		if err != nil {
			t.Errorf("Startup(PolicyLoadOK) = %v, want nil", err)
		}
		if len(calls) != 0 {
			t.Errorf("emitted %d audit events on OK path, want 0: %+v", len(calls), calls)
		}
	})
}

// @ac AC-10
// AC-10 (missing policy): refuses to start AND emits scheduler.startup.failed
// with detail.reason = "policy_missing" + detail.policy_path populated.
func TestStartup_PolicyMissing_RefusesAndEmits(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		var calls []emitCall
		path := "/opt/openwatch/policies/schedules.yaml"

		err := Startup(context.Background(), fakeEmitter(&calls), path, PolicyLoadMissing)

		if !errors.Is(err, ErrStartupRefused) {
			t.Errorf("err = %v, want ErrStartupRefused", err)
		}
		if len(calls) != 1 {
			t.Fatalf("emitted %d events, want exactly 1: %+v", len(calls), calls)
		}
		assertStartupFailedEmit(t, calls[0], "policy_missing", path)
	})
}

// @ac AC-10
// AC-10 (signature invalid): the Ed25519 verification path produces this
// specific reason; the dispatcher receives it and refuses + audits.
func TestStartup_SignatureInvalid_RefusesAndEmits(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		var calls []emitCall
		path := "/opt/openwatch/policies/schedules.yaml"

		err := Startup(context.Background(), fakeEmitter(&calls), path, PolicyLoadSignatureInvalid)

		if !errors.Is(err, ErrStartupRefused) {
			t.Errorf("err = %v, want ErrStartupRefused", err)
		}
		if len(calls) != 1 {
			t.Fatalf("emitted %d events, want 1", len(calls))
		}
		assertStartupFailedEmit(t, calls[0], "signature_invalid", path)
	})
}

// @ac AC-10
// AC-10 (parse error): YAML is signed correctly but the schema is broken.
func TestStartup_ParseError_RefusesAndEmits(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		var calls []emitCall
		path := "/opt/openwatch/policies/schedules.yaml"

		err := Startup(context.Background(), fakeEmitter(&calls), path, PolicyLoadParseError)

		if !errors.Is(err, ErrStartupRefused) {
			t.Errorf("err = %v, want ErrStartupRefused", err)
		}
		assertStartupFailedEmit(t, calls[0], "parse_error", path)
	})
}

// @ac AC-10
// AC-10 (revoked key): signature mathematically valid but signing key
// has been revoked. The boot path treats this as a policy-load failure
// and refuses-and-audits via scheduler.startup.failed. The full AC-14
// path (runtime reload + scheduler.policy.revoked_key.rejected event +
// revocation list mechanism itself) lands in a subsequent commit.
func TestStartup_RevokedKey_RefusesAndEmits(t *testing.T) {
	t.Run("system-scheduler/AC-10", func(t *testing.T) {
		var calls []emitCall
		path := "/opt/openwatch/policies/schedules.yaml"

		err := Startup(context.Background(), fakeEmitter(&calls), path, PolicyLoadRevokedKey)

		if !errors.Is(err, ErrStartupRefused) {
			t.Errorf("err = %v, want ErrStartupRefused", err)
		}
		assertStartupFailedEmit(t, calls[0], "revoked_key", path)
	})
}

// assertStartupFailedEmit checks that a captured audit emission has the
// expected code, actor_type, reason, and policy_path. Detail is JSON-encoded
// inside audit.Event so we decode it here for inspection.
func assertStartupFailedEmit(t *testing.T, c emitCall, wantReason, wantPath string) {
	t.Helper()
	if c.Code != audit.SchedulerStartupFailed {
		t.Errorf("Code = %q, want %q", c.Code, audit.SchedulerStartupFailed)
	}
	if c.Event.ActorType != "system" {
		t.Errorf("ActorType = %q, want %q", c.Event.ActorType, "system")
	}

	var detail map[string]string
	if err := json.Unmarshal(c.Event.Detail, &detail); err != nil {
		t.Fatalf("decode Detail: %v (raw=%s)", err, string(c.Event.Detail))
	}
	if got := detail["reason"]; got != wantReason {
		t.Errorf("Detail.reason = %q, want %q", got, wantReason)
	}
	if got := detail["policy_path"]; got != wantPath {
		t.Errorf("Detail.policy_path = %q, want %q", got, wantPath)
	}
}
