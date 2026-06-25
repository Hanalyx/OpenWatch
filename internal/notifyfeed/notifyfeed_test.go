// @spec system-notifications
//
// AC traceability (this file):
//
//	AC-09  TestStore_RecordDedupAndList — upsert/collapse + List
//	AC-10  TestStore_ReadState — per-user unread/mark-read scoping
//	AC-11  TestChannel_FanOut — alert fans one row per recipient; alert->notification mapping
//
// Skipped without OPENWATCH_TEST_DSN (uses the shared per-package isolated DB).
package notifyfeed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func seedUser(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, 'x')`,
		id, name, name+"@example.com"); err != nil {
		t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// @ac AC-09
func TestStore_RecordDedupAndList(t *testing.T) {
	t.Run("system-notifications/AC-09", func(t *testing.T) {
		pool := dbtest.Pool(t)
		s := NewStore(pool)
		ctx := context.Background()
		uid := seedUser(t, pool, "ac09")

		// First record.
		if err := s.Record(ctx, Notification{UserID: uid, Kind: "drift_major", Severity: "high",
			Title: "fleet drift", GroupKey: "g1", OccurredAt: time.Now().UTC()}); err != nil {
			t.Fatalf("record 1: %v", err)
		}
		// A second, second-group record so List ordering is exercised.
		if err := s.Record(ctx, Notification{UserID: uid, Kind: "host_unreachable", Severity: "high",
			Title: "host down", GroupKey: "g2", OccurredAt: time.Now().UTC().Add(time.Second)}); err != nil {
			t.Fatalf("record 2: %v", err)
		}
		list, err := s.List(ctx, uid, false, 50)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("want 2 notifications, got %d", len(list))
		}
		if list[0].GroupKey != "g2" {
			t.Errorf("want newest-first (g2 first), got %q", list[0].GroupKey)
		}

		// Read g1, then Record the SAME group again → collapses onto one row and
		// re-surfaces unread.
		if err := s.MarkRead(ctx, uid, list[1].ID); err != nil {
			t.Fatalf("mark read: %v", err)
		}
		if err := s.Record(ctx, Notification{UserID: uid, Kind: "drift_major", Severity: "critical",
			Title: "fleet drift worsened", GroupKey: "g1", OccurredAt: time.Now().UTC().Add(2 * time.Second)}); err != nil {
			t.Fatalf("record dedup: %v", err)
		}
		again, _ := s.List(ctx, uid, false, 50)
		if len(again) != 2 {
			t.Fatalf("dedup failed — want still 2 rows, got %d", len(again))
		}
		// unreadOnly returns both again (g1 re-surfaced unread, g2 still unread).
		unread, _ := s.List(ctx, uid, true, 50)
		if len(unread) != 2 {
			t.Errorf("want 2 unread after re-surface, got %d", len(unread))
		}
		// The collapsed g1 row carries the refreshed content.
		var g1 *Notification
		for i := range again {
			if again[i].GroupKey == "g1" {
				g1 = &again[i]
			}
		}
		if g1 == nil || g1.Title != "fleet drift worsened" || g1.ReadAt != nil {
			t.Errorf("g1 not refreshed/unread: %+v", g1)
		}
	})
}

// @ac AC-10
func TestStore_ReadState(t *testing.T) {
	t.Run("system-notifications/AC-10", func(t *testing.T) {
		pool := dbtest.Pool(t)
		s := NewStore(pool)
		ctx := context.Background()
		alice := seedUser(t, pool, "ac10-alice")
		bob := seedUser(t, pool, "ac10-bob")

		if err := s.Record(ctx, Notification{UserID: alice, Kind: "host_unreachable", Severity: "high",
			Title: "down", GroupKey: "g", OccurredAt: time.Now().UTC()}); err != nil {
			t.Fatalf("record: %v", err)
		}
		if n, _ := s.UnreadCount(ctx, alice); n != 1 {
			t.Fatalf("alice unread = %d, want 1", n)
		}
		list, _ := s.List(ctx, alice, false, 10)
		id := list[0].ID

		// Bob cannot mark Alice's notification read.
		if err := s.MarkRead(ctx, bob, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("bob mark-read alice's row = %v, want ErrNotFound", err)
		}
		// Alice can.
		if err := s.MarkRead(ctx, alice, id); err != nil {
			t.Fatalf("alice mark read: %v", err)
		}
		if n, _ := s.UnreadCount(ctx, alice); n != 0 {
			t.Errorf("alice unread after read = %d, want 0", n)
		}
		// MarkAllRead is a no-op count of 0 now (nothing unread).
		if n, err := s.MarkAllRead(ctx, alice); err != nil || n != 0 {
			t.Errorf("mark all read = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// @ac AC-11
func TestChannel_FanOut(t *testing.T) {
	t.Run("system-notifications/AC-11", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		u1 := seedUser(t, pool, "ac11-a")
		u2 := seedUser(t, pool, "ac11-b")
		ch := NewChannel(pool, NewStore(pool))

		alert := alertrouter.Alert{
			Type:       alertrouter.AlertTypeDriftMajor,
			Severity:   alertrouter.SeverityHigh,
			Title:      "fleet compliance dropped",
			Body:       "major drift",
			OccurredAt: time.Now().UTC(),
		}
		if err := ch.Send(ctx, alert); err != nil {
			t.Fatalf("Send: %v", err)
		}
		// Each active recipient got a row.
		for _, uid := range []uuid.UUID{u1, u2} {
			list, _ := NewStore(pool).List(ctx, uid, false, 10)
			if len(list) != 1 {
				t.Fatalf("user %s got %d notifications, want 1", uid, len(list))
			}
			n := list[0]
			if n.Kind != "drift_major" || n.Severity != "high" || n.Title != "fleet compliance dropped" {
				t.Errorf("mapping wrong: %+v", n)
			}
			if n.HostID != nil || n.Link != "" {
				t.Errorf("fleet alert should carry no host link: %+v", n)
			}
		}

		// Mapping unit-check: a host-scoped alert deep-links to /hosts/{id}.
		hostID, _ := uuid.NewV7()
		mapped := notificationFromAlert(alertrouter.Alert{
			Type: alertrouter.AlertTypeHostUnreachable, Severity: alertrouter.SeverityCritical,
			HostID: hostID, Title: "host down", OccurredAt: time.Now().UTC(),
		})
		if mapped.HostID == nil || *mapped.HostID != hostID || mapped.Link != "/hosts/"+hostID.String() {
			t.Errorf("host-scoped mapping wrong: %+v", mapped)
		}
		if mapped.GroupKey == "" {
			t.Errorf("group_key (alert DedupKey) must be set")
		}
	})
}
