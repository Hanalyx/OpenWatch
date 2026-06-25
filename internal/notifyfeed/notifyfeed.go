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
	"github.com/jackc/pgx/v5"
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

// activeUserIDs returns every non-deleted user — the Slice-1 recipient set for
// a fleet-visible change. Per-host RBAC scoping is a later refinement.
func activeUserIDs(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	rows, err := pool.Query(ctx, `SELECT id FROM users WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("notifyfeed: recipients: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("notifyfeed: recipient scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return ids, nil
}
