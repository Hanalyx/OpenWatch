// @spec system-notifications
//
// AC traceability (this file):
//
//	AC-15  TestGovernance_ExceptionRequestedFansToApprovers — pending → approvers only (RBAC-scoped fan-out)
//	AC-16  TestGovernance_ExceptionDecidedNotifiesRequester — decision → requester only
//	AC-17  TestGovernance_RemediationFailedFansToOperators — failure → remediation operators only
//
// Skipped without OPENWATCH_TEST_DSN. Assertions filter by the per-test-unique
// group_key so the role-scoped fan-out from other tests on the shared DB does
// not perturb counts.
package notifyfeed

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func seedUserWithRole(t *testing.T, pool *pgxpool.Pool, name, roleID string) uuid.UUID {
	t.Helper()
	id := seedUser(t, pool, name)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, id, roleID); err != nil {
		t.Fatalf("grant %s to %s: %v", roleID, name, err)
	}
	return id
}

// notifByGroupKey returns the user's single notification with the given
// group_key, or nil if none — isolating the assertion from other tests' fan-out
// on the shared DB (group_key embeds a per-test unique id).
func notifByGroupKey(t *testing.T, s *Store, user uuid.UUID, groupKey string) *Notification {
	t.Helper()
	all, err := s.List(context.Background(), user, false, 200)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for i := range all {
		if all[i].GroupKey == groupKey {
			return &all[i]
		}
	}
	return nil
}

// @ac AC-15
func TestGovernance_ExceptionRequestedFansToApprovers(t *testing.T) {
	t.Run("system-notifications/AC-15", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		g := NewGovernanceProjector(s)

		approver := seedUserWithRole(t, pool, "secadmin-"+uniq(), "security_admin")
		adminU := seedUserWithRole(t, pool, "admin-"+uniq(), "admin")
		viewer := seedUserWithRole(t, pool, "viewer-"+uniq(), "viewer")
		creator := seedUser(t, pool, "creator-"+uniq())
		host := seedHost(t, pool, creator, "web-"+uniq(), "Web One")

		excID, _ := uuid.NewV7()
		if err := g.ExceptionRequested(ctx, excID, host, "rule.sshd_config"); err != nil {
			t.Fatalf("ExceptionRequested: %v", err)
		}
		gk := "exception_pending:" + excID.String()

		// Approvers (security_admin, admin) receive it.
		for _, u := range []uuid.UUID{approver, adminU} {
			n := notifByGroupKey(t, s, u, gk)
			if n == nil {
				t.Fatalf("approver %s did not receive the pending-exception notification", u)
			}
			if n.Kind != "exception_pending" || n.Severity != "high" {
				t.Errorf("kind/severity = %q/%q, want exception_pending/high", n.Kind, n.Severity)
			}
			if n.Link != "/settings/policies" {
				t.Errorf("link = %q, want /settings/policies", n.Link)
			}
		}
		// A viewer (no exception:approve) does NOT.
		if n := notifByGroupKey(t, s, viewer, gk); n != nil {
			t.Errorf("viewer must not receive an approver-scoped notification")
		}
	})
}

// @ac AC-16
func TestGovernance_ExceptionDecidedNotifiesRequester(t *testing.T) {
	t.Run("system-notifications/AC-16", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		g := NewGovernanceProjector(s)

		requester := seedUser(t, pool, "req-"+uniq())
		other := seedUser(t, pool, "other-"+uniq())

		excID, _ := uuid.NewV7()
		if err := g.ExceptionDecided(ctx, excID, requester, "rule.audit_rules", true); err != nil {
			t.Fatalf("ExceptionDecided: %v", err)
		}
		gk := "exception_decided:" + excID.String()

		n := notifByGroupKey(t, s, requester, gk)
		if n == nil {
			t.Fatalf("requester did not receive the decision notification")
		}
		if n.Kind != "exception_approved" || n.Severity != "medium" {
			t.Errorf("kind/severity = %q/%q, want exception_approved/medium", n.Kind, n.Severity)
		}
		// No one else gets a requester-facing decision.
		if n := notifByGroupKey(t, s, other, gk); n != nil {
			t.Errorf("a non-requester must not receive the decision notification")
		}

		// A rejection maps to exception_rejected.
		excID2, _ := uuid.NewV7()
		if err := g.ExceptionDecided(ctx, excID2, requester, "rule.x", false); err != nil {
			t.Fatalf("ExceptionDecided reject: %v", err)
		}
		if n := notifByGroupKey(t, s, requester, "exception_decided:"+excID2.String()); n == nil || n.Kind != "exception_rejected" {
			t.Errorf("rejection should record kind exception_rejected")
		}
	})
}

// @ac AC-17
func TestGovernance_RemediationFailedFansToOperators(t *testing.T) {
	t.Run("system-notifications/AC-17", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		g := NewGovernanceProjector(s)

		opsLead := seedUserWithRole(t, pool, "ops-"+uniq(), "ops_lead")
		viewer := seedUserWithRole(t, pool, "viewer-"+uniq(), "viewer")
		creator := seedUser(t, pool, "creator-"+uniq())
		host := seedHost(t, pool, creator, "db-"+uniq(), "DB One")

		if err := g.RemediationFailed(ctx, host, "rule.firewalld", "execute", "failed"); err != nil {
			t.Fatalf("RemediationFailed: %v", err)
		}
		gk := "remediation_failed:" + host.String() + ":rule.firewalld"

		n := notifByGroupKey(t, s, opsLead, gk)
		if n == nil {
			t.Fatalf("ops_lead did not receive the remediation-failure notification")
		}
		if n.Kind != "remediation_failed" || n.Severity != "high" {
			t.Errorf("kind/severity = %q/%q, want remediation_failed/high", n.Kind, n.Severity)
		}
		if n.Link != "/hosts/"+host.String() {
			t.Errorf("link = %q, want /hosts/<host>", n.Link)
		}
		// A viewer (no remediation:execute) does NOT receive it.
		if n := notifByGroupKey(t, s, viewer, gk); n != nil {
			t.Errorf("viewer must not receive an operator-scoped notification")
		}
	})
}
