// @spec system-compliance-lens
//
// host_effective_target view precedence + framework.EffectiveTarget resolver
// (Phase 3 compliance-targets, migration 0051).

package framework

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// @ac AC-07
// AC-07: host_effective_target resolves host target > oldest site-group target
// > NULL; EffectiveTarget applies the org default as the final fallback.
func TestEffectiveTarget_Precedence(t *testing.T) {
	t.Run("system-compliance-lens/AC-07", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewService(pool)

		var uid uuid.UUID
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (id, username, email, password_hash)
			 VALUES (gen_random_uuid(), 'tgt-u', 'tgt-u@x', 'h') RETURNING id`).Scan(&uid); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		mkHost := func(name string, target *string) uuid.UUID {
			var id uuid.UUID
			if err := pool.QueryRow(ctx,
				`INSERT INTO hosts (id, hostname, ip_address, created_by, target_framework)
				 VALUES (gen_random_uuid(), $1, '10.0.0.1', $2, $3) RETURNING id`,
				name, uid, target).Scan(&id); err != nil {
				t.Fatalf("seed host %s: %v", name, err)
			}
			return id
		}
		mkSiteGroup := func(name, target string) uuid.UUID {
			var gid uuid.UUID
			if err := pool.QueryRow(ctx,
				`INSERT INTO groups (id, name, kind, membership, target_framework)
				 VALUES (gen_random_uuid(), $1, 'site', 'manual', $2) RETURNING id`,
				name, target).Scan(&gid); err != nil {
				t.Fatalf("seed group %s: %v", name, err)
			}
			return gid
		}
		addMember := func(gid, hid uuid.UUID, addedAt time.Time) {
			if _, err := pool.Exec(ctx,
				`INSERT INTO group_members (group_id, host_id, added_at) VALUES ($1, $2, $3)`,
				gid, hid, addedAt); err != nil {
				t.Fatalf("seed membership: %v", err)
			}
		}
		strp := func(s string) *string { return &s }

		// host override wins over a site-group target.
		hOwn := mkHost("h-own", strp("cis"))
		gStig := mkSiteGroup("site-stig", "stig")
		addMember(gStig, hOwn, time.Unix(1000, 0))

		// no own target, one site-group target -> the group's.
		hGroup := mkHost("h-group", nil)
		addMember(gStig, hGroup, time.Unix(1000, 0))

		// no own target, no group -> org default fallback.
		hNone := mkHost("h-none", nil)

		// two site groups, different targets -> oldest membership wins.
		hTie := mkHost("h-tie", nil)
		gCis := mkSiteGroup("site-cis", "cis")
		addMember(gStig, hTie, time.Unix(1000, 0)) // older -> stig
		addMember(gCis, hTie, time.Unix(2000, 0))  // newer -> cis

		cases := []struct {
			name string
			host uuid.UUID
			org  string
			want string
		}{
			{"host override", hOwn, "srg", "cis"},
			{"site-group target", hGroup, "srg", "stig"},
			{"org-default fallback", hNone, "srg", "srg"},
			{"oldest membership wins", hTie, "srg", "stig"},
		}
		for _, tc := range cases {
			got, err := s.EffectiveTarget(ctx, tc.host, tc.org)
			if err != nil {
				t.Fatalf("%s: EffectiveTarget: %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("%s: EffectiveTarget = %q, want %q", tc.name, got, tc.want)
			}
		}
	})
}
