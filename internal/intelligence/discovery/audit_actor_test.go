// @spec system-host-discovery
//
//	AC-23  TestEmitAuditSuccess_ActorAttribution

package discovery

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-23
func TestEmitAuditSuccess_ActorAttribution(t *testing.T) {
	t.Run("system-host-discovery/AC-23", func(t *testing.T) {
		var captured audit.Event
		svc := &Service{emit: func(_ context.Context, _ audit.Code, ev audit.Event) { captured = ev }}
		host := uuid.Must(uuid.NewV7())

		// Automated scheduled run: no identity on the background ctx -> system.
		svc.emitAuditSuccess(context.Background(), host, SystemFacts{})
		if captured.ActorType != "system" {
			t.Errorf("scheduled actor_type = %q, want system", captured.ActorType)
		}
		if captured.ActorID != "" {
			t.Errorf("scheduled actor_id = %q, want empty", captured.ActorID)
		}

		// Operator-triggered (Reconnect / Run now / add host): a bound
		// identity on ctx -> user + its id.
		uid := uuid.Must(uuid.NewV7()).String()
		ctx := auth.SetIdentity(context.Background(), auth.Identity{ID: uid, RoleID: auth.RoleAdmin})
		svc.emitAuditSuccess(ctx, host, SystemFacts{})
		if captured.ActorType != "user" {
			t.Errorf("operator-triggered actor_type = %q, want user", captured.ActorType)
		}
		if captured.ActorID != uid {
			t.Errorf("actor_id = %q, want %q", captured.ActorID, uid)
		}
	})
}
