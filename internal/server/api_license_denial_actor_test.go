// @spec system-license-features
//
// AC traceability (DSN-gated):
//
//	AC-16  TestLicenseDenial_AttributedToCaller
//
// bugs/OW-101: an authenticated license denial recorded actor_type "user"
// with no actor id. An unauthenticated caller cannot reach a handler's
// license gate (RBAC answers first), so the anonymous case is covered at
// the middleware level (AC-15).
package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/license"
)

// @ac AC-16
func TestLicenseDenial_AttributedToCaller(t *testing.T) {
	t.Run("system-license-features/AC-16", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		license.Init() // free tier: attestation is not enabled
		admin := roleUserIDs[auth.RoleAdmin]
		raw, tokenID := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		chID := uuid.New()
		if _, err := pool.Exec(context.Background(), `INSERT INTO notification_channels (id, type, name, enabled, config_ciphertext) VALUES ($1, 'email', 'lic', true, $2)`, chID, []byte("x")); err != nil {
			t.Fatalf("seed channel: %v", err)
		}
		body := map[string]any{"name": "lic", "kind": "attestation", "framework": "cis_rhel9", "frequency": "daily", "channel_id": chID.String()}
		for _, c := range []struct {
			bearer, wantType, wantID string
		}{
			{"", "user", admin.String()},
			{raw, "api_key", tokenID.String()},
		} {
			st, b, corr := tokCall(t, url, c.bearer, auth.RoleAdmin, "POST", "/api/v1/reports/schedules", body)
			if st != http.StatusPaymentRequired {
				t.Fatalf("expected 402, got %d %s", st, b)
			}
			den := tokOnlyAction(t, tokAuditRowsFor(t, pool, corr), "license.feature_check_denied")
			if len(den) != 1 {
				t.Fatalf("%s: license.feature_check_denied rows = %d, want 1", c.wantType, len(den))
			}
			if den[0].ActorType != c.wantType || den[0].ActorID != c.wantID {
				t.Errorf("license denial actor = %s/%q, want %s/%s (OW-101 recorded user with no id)",
					den[0].ActorType, den[0].ActorID, c.wantType, c.wantID)
			}
		}
	})
}
