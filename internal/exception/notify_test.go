// @spec system-notifications
//
// AC traceability (this file):
//
//	AC-19  TestExpiringSoonSweep_InWindowApprovedOnly — the sweep query selects
//	       only approved exceptions expiring within the window and warns each.
//
// Skipped without OPENWATCH_TEST_DSN (shared per-package isolated DB).
package exception

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// fakeNotifier records which exceptions each governance hook fired for.
type fakeNotifier struct {
	expiringSoon []uuid.UUID
	expired      []uuid.UUID
}

func (f *fakeNotifier) ExceptionRequested(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}
func (f *fakeNotifier) ExceptionDecided(context.Context, uuid.UUID, uuid.UUID, string, bool) error {
	return nil
}
func (f *fakeNotifier) ExceptionExpiringSoon(_ context.Context, id, _ uuid.UUID, _ string) error {
	f.expiringSoon = append(f.expiringSoon, id)
	return nil
}
func (f *fakeNotifier) ExceptionExpired(_ context.Context, id, _ uuid.UUID, _ string) error {
	f.expired = append(f.expired, id)
	return nil
}

// @ac AC-19
func TestExpiringSoonSweep_InWindowApprovedOnly(t *testing.T) {
	t.Run("system-notifications/AC-19", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		fake := &fakeNotifier{}
		svc := NewService(pool, fakeEmitter(&[]emitCall{})).WithNotifier(fake)

		requester := seedUser(t, pool, "req")
		reviewer := seedUser(t, pool, "rev")
		host := seedHost(t, pool, requester)

		soon := time.Now().UTC().Add(24 * time.Hour)                // inside the 72h window
		far := time.Now().UTC().Add(ExpiringSoonWindow + time.Hour) // outside

		// In-window, approved → must be warned.
		inWin, err := svc.Request(ctx, host, "rule-soon", "reason", requester, &soon)
		if err != nil {
			t.Fatalf("request in-window: %v", err)
		}
		if _, err := svc.Approve(ctx, inWin.ID, reviewer, "ok"); err != nil {
			t.Fatalf("approve in-window: %v", err)
		}
		// Out-of-window, approved → must NOT be warned.
		farEx, _ := svc.Request(ctx, host, "rule-far", "reason", requester, &far)
		if _, err := svc.Approve(ctx, farEx.ID, reviewer, "ok"); err != nil {
			t.Fatalf("approve far: %v", err)
		}
		// In-window but only requested (not approved) → must NOT be warned.
		if _, err := svc.Request(ctx, host, "rule-pending", "reason", requester, &soon); err != nil {
			t.Fatalf("request pending: %v", err)
		}

		n, err := svc.ExpiringSoonSweep(ctx)
		if err != nil {
			t.Fatalf("ExpiringSoonSweep: %v", err)
		}
		if n != 1 {
			t.Fatalf("want 1 warned, got %d", n)
		}
		if len(fake.expiringSoon) != 1 || fake.expiringSoon[0] != inWin.ID {
			t.Errorf("only the in-window approved exception should be warned, got %v (want %v)",
				fake.expiringSoon, inWin.ID)
		}
	})
}
