// @spec system-audit-emission
//
//	AC-24  TestEmitAuditSuccess_TokenIsAPIKeyNotOwner
//
// bugs/OW-100: a token-triggered discovery was recorded as actor_type user.
// Discovery only emits after a successful SSH collection, which the HTTP
// test harness cannot provide, so the emit path is driven here with the
// identity the binder would bind.
package discovery

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-24
func TestEmitAuditSuccess_TokenIsAPIKeyNotOwner(t *testing.T) {
	t.Run("system-audit-emission/AC-24", func(t *testing.T) {
		var captured audit.Event
		svc := &Service{emit: func(_ context.Context, _ audit.Code, ev audit.Event) { captured = ev }}
		host := uuid.Must(uuid.NewV7())
		tokenID, owner := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())

		ctx := auth.SetIdentity(context.Background(), auth.Identity{
			ID: tokenID.String(), UserID: owner, RoleID: auth.RoleAdmin, IsAPIToken: true,
		})
		svc.emitAuditSuccess(ctx, host, SystemFacts{})
		if captured.ActorType != audit.ActorAPIKey || captured.ActorID != tokenID.String() {
			t.Errorf("token-triggered actor = %s/%s, want api_key/%s", captured.ActorType, captured.ActorID, tokenID)
		}
		if captured.ActorID == owner.String() {
			t.Error("the token's owner was recorded as the actor")
		}

		// A session stays a user, and a scheduled run stays the system.
		uid := uuid.Must(uuid.NewV7()).String()
		svc.emitAuditSuccess(auth.SetIdentity(context.Background(), auth.Identity{ID: uid, UserID: uuid.MustParse(uid), RoleID: auth.RoleAdmin}), host, SystemFacts{})
		if captured.ActorType != audit.ActorUser || captured.ActorID != uid {
			t.Errorf("session actor = %s/%s, want user/%s", captured.ActorType, captured.ActorID, uid)
		}
		svc.emitAuditSuccess(context.Background(), host, SystemFacts{})
		if captured.ActorType != audit.ActorSystem {
			t.Errorf("scheduled actor_type = %q, want system", captured.ActorType)
		}
	})
}
