// Package notifyfeed is the durable, per-user in-app notification feed — the
// data layer behind the bell. It records change-driven notifications (fanned
// out from the alert engine; in later slices, the transaction log), tracks
// per-user read state, and serves the unread count + list the UI renders.
//
// This is distinct from internal/notification, which delivers alerts OUTWARD
// to Slack/email/webhook channels. notifyfeed is the INWARD, in-app surface.
//
// Design: docs/engineering/notifications_design.md. Spec: system-notifications.
package notifyfeed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a mark-read targets a notification that does not
// exist for the calling user (wrong id, or another user's row).
var ErrNotFound = errors.New("notifyfeed: notification not found")

// Notification is one in-app notification row for one recipient.
type Notification struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Kind       string
	Severity   string
	Title      string
	Body       string
	HostID     *uuid.UUID
	Link       string
	GroupKey   string
	OccurredAt time.Time
	ReadAt     *time.Time
	CreatedAt  time.Time
}

// Store is the PostgreSQL-backed notification feed.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a feed store over the given pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// hostName returns the host's display name (falling back to hostname, then the
// id) for a notification title. A lookup failure degrades to the id string
// rather than failing the projection. Shared by the regression + governance
// projectors.
func (s *Store) hostName(ctx context.Context, hostID uuid.UUID) string {
	var name string
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(display_name, ''), hostname) FROM hosts WHERE id = $1`,
		hostID).Scan(&name); err != nil || name == "" {
		return hostID.String()
	}
	return name
}

// Record upserts one notification for one user. A repeat of the same change
// (same user_id + group_key) collapses onto the existing row, refreshing its
// content + occurred_at and re-surfacing it as UNREAD — so a recurring problem
// re-pings the bell without creating a second entry. id/created_at on the
// passed Notification are ignored (the store assigns them).
func (s *Store) Record(ctx context.Context, n Notification) error {
	if n.UserID == uuid.Nil {
		return errors.New("notifyfeed: Record requires UserID")
	}
	if n.GroupKey == "" {
		return errors.New("notifyfeed: Record requires GroupKey")
	}
	if n.OccurredAt.IsZero() {
		n.OccurredAt = time.Now().UTC()
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("notifyfeed: uuid: %w", err)
	}
	const stmt = `
		INSERT INTO notifications
			(id, user_id, kind, severity, title, body, host_id, link, group_key, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id, group_key) DO UPDATE SET
			kind        = EXCLUDED.kind,
			severity    = EXCLUDED.severity,
			title       = EXCLUDED.title,
			body        = EXCLUDED.body,
			host_id     = EXCLUDED.host_id,
			link        = EXCLUDED.link,
			occurred_at = EXCLUDED.occurred_at,
			read_at     = NULL`
	if _, err := s.pool.Exec(ctx, stmt,
		id, n.UserID, n.Kind, n.Severity, n.Title, n.Body,
		n.HostID, n.Link, n.GroupKey, n.OccurredAt,
	); err != nil {
		return fmt.Errorf("notifyfeed: record: %w", err)
	}
	return nil
}

// RecordFanout records one notification for EVERY active (non-deleted) user in
// a single statement (one row per recipient, same upsert/collapse semantics as
// Record). This replaces a per-user Record loop, so a fleet alert is one DB
// round-trip rather than N — important on large user bases. The UserID on the
// template is ignored; recipients come from the users table.
func (s *Store) RecordFanout(ctx context.Context, n Notification) error {
	if n.GroupKey == "" {
		return errors.New("notifyfeed: RecordFanout requires GroupKey")
	}
	if n.OccurredAt.IsZero() {
		n.OccurredAt = time.Now().UTC()
	}
	const stmt = `
		INSERT INTO notifications
			(id, user_id, kind, severity, title, body, host_id, link, group_key, occurred_at)
		SELECT gen_random_uuid(), u.id, $1, $2, $3, $4, $5, $6, $7, $8
		  FROM users u
		 WHERE u.deleted_at IS NULL
		ON CONFLICT (user_id, group_key) DO UPDATE SET
			kind        = EXCLUDED.kind,
			severity    = EXCLUDED.severity,
			title       = EXCLUDED.title,
			body        = EXCLUDED.body,
			host_id     = EXCLUDED.host_id,
			link        = EXCLUDED.link,
			occurred_at = EXCLUDED.occurred_at,
			read_at     = NULL`
	if _, err := s.pool.Exec(ctx, stmt,
		n.Kind, n.Severity, n.Title, n.Body, n.HostID, n.Link, n.GroupKey, n.OccurredAt,
	); err != nil {
		return fmt.Errorf("notifyfeed: record fanout: %w", err)
	}
	return nil
}

// RecordForRoles records one notification for every active (non-deleted) user
// who holds at least one of the given built-in roles, in a single statement
// (same upsert/collapse semantics as RecordFanout). This is the RBAC-scoped
// fan-out behind governance notifications — e.g. an exception pending approval
// reaches only users whose role grants exception:approve, not the whole fleet.
// An empty roleIDs slice matches no one (a no-op). The UserID on the template
// is ignored; recipients come from users joined to user_roles. EXISTS (not
// JOIN) keeps a user holding two matching roles to one row, avoiding an ON
// CONFLICT double-hit within the statement.
func (s *Store) RecordForRoles(ctx context.Context, roleIDs []string, n Notification) error {
	if n.GroupKey == "" {
		return errors.New("notifyfeed: RecordForRoles requires GroupKey")
	}
	if len(roleIDs) == 0 {
		return nil
	}
	if n.OccurredAt.IsZero() {
		n.OccurredAt = time.Now().UTC()
	}
	const stmt = `
		INSERT INTO notifications
			(id, user_id, kind, severity, title, body, host_id, link, group_key, occurred_at)
		SELECT gen_random_uuid(), u.id, $1, $2, $3, $4, $5, $6, $7, $8
		  FROM users u
		 WHERE u.deleted_at IS NULL
		   AND EXISTS (
			SELECT 1 FROM user_roles ur
			 WHERE ur.user_id = u.id AND ur.role_id = ANY($9::text[]))
		ON CONFLICT (user_id, group_key) DO UPDATE SET
			kind        = EXCLUDED.kind,
			severity    = EXCLUDED.severity,
			title       = EXCLUDED.title,
			body        = EXCLUDED.body,
			host_id     = EXCLUDED.host_id,
			link        = EXCLUDED.link,
			occurred_at = EXCLUDED.occurred_at,
			read_at     = NULL`
	if _, err := s.pool.Exec(ctx, stmt,
		n.Kind, n.Severity, n.Title, n.Body, n.HostID, n.Link, n.GroupKey, n.OccurredAt, roleIDs,
	); err != nil {
		return fmt.Errorf("notifyfeed: record for roles: %w", err)
	}
	return nil
}

// List returns a user's notifications newest-first (by occurred_at). When
// unreadOnly is true, only unread rows are returned. limit caps the result
// (defaulted/clamped to a sane page size).
func (s *Store) List(ctx context.Context, userID uuid.UUID, unreadOnly bool, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `
		SELECT id, user_id, kind, severity, title, body, host_id, link,
		       group_key, occurred_at, read_at, created_at
		  FROM notifications
		 WHERE user_id = $1`
	if unreadOnly {
		q += ` AND read_at IS NULL`
	}
	q += ` ORDER BY occurred_at DESC LIMIT $2`
	rows, err := s.pool.Query(ctx, q, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("notifyfeed: list: %w", err)
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Kind, &n.Severity, &n.Title, &n.Body,
			&n.HostID, &n.Link, &n.GroupKey, &n.OccurredAt, &n.ReadAt, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("notifyfeed: scan: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UnreadCount returns how many unread notifications a user has.
func (s *Store) UnreadCount(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL`,
		userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("notifyfeed: unread count: %w", err)
	}
	return n, nil
}

// MarkRead marks one notification read, scoped to the owning user (so a user
// can never read or mutate another user's row). Idempotent on an already-read
// row; returns ErrNotFound when no such row belongs to the user.
func (s *Store) MarkRead(ctx context.Context, userID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE notifications SET read_at = COALESCE(read_at, now()) WHERE id = $1 AND user_id = $2`,
		id, userID)
	if err != nil {
		return fmt.Errorf("notifyfeed: mark read: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAllRead marks every unread notification for the user read; returns the
// number affected.
func (s *Store) MarkAllRead(ctx context.Context, userID uuid.UUID) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE notifications SET read_at = now() WHERE user_id = $1 AND read_at IS NULL`,
		userID)
	if err != nil {
		return 0, fmt.Errorf("notifyfeed: mark all read: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
