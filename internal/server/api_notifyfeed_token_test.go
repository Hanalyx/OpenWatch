// @spec system-notifications
//
// AC traceability (DSN-gated):
//
//	AC-24  TestNotificationFeed_RefusesAPIToken
package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/notifyfeed"
)

// @ac AC-24
func TestNotificationFeed_RefusesAPIToken(t *testing.T) {
	t.Run("system-notifications/AC-24", func(t *testing.T) {
		url, pool, srv := freshAPIServerWithHandles(t)
		srv.WithNotifyFeed(notifyfeed.NewStore(pool))
		ctx := context.Background()
		owner := roleUserIDs[auth.RoleAdmin]
		raw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		if err := notifyfeed.NewStore(pool).Record(ctx, notifyfeed.Notification{UserID: owner, Kind: "t", Severity: "info", Title: "owner item", GroupKey: "ac24"}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		var nid uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM notifications WHERE user_id = $1 AND group_key = 'ac24'`, owner).Scan(&nid); err != nil {
			t.Fatalf("read seed: %v", err)
		}

		assertTokenRefused(t, url, raw, "GET", "/api/v1/notifications/feed", nil)
		assertTokenRefused(t, url, raw, "POST", "/api/v1/notifications/feed:read-all", nil)
		assertTokenRefused(t, url, raw, "POST", "/api/v1/notifications/feed/"+nid.String()+":read", nil)

		var read int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE id = $1 AND read_at IS NOT NULL`, nid).Scan(&read)
		if read != 0 {
			t.Error("a token marked its owner's notification read")
		}
	})
}
