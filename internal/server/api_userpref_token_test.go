// @spec system-user-preferences
//
// AC traceability (DSN-gated):
//
//	AC-06  TestUserPrefs_RefuseAPIToken
package server

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// @ac AC-06
func TestUserPrefs_RefuseAPIToken(t *testing.T) {
	t.Run("system-user-preferences/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		owner := roleUserIDs[auth.RoleAdmin]
		raw, _ := mintTokenAs(t, url, auth.RoleAdmin, auth.RoleAdmin)
		before := queryString(t, pool, `SELECT preferences::text FROM users WHERE id = $1`, owner)

		assertTokenRefused(t, url, raw, "GET", "/api/v1/users/me/preferences", nil)
		assertTokenRefused(t, url, raw, "PATCH", "/api/v1/users/me/preferences", map[string]any{"hosts_view_default": "table"})

		if after := queryString(t, pool, `SELECT preferences::text FROM users WHERE id = $1`, owner); after != before {
			t.Errorf("the owner's preferences changed: %s -> %s", before, after)
		}
	})
}
