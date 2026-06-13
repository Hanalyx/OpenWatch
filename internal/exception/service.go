package exception

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitFunc is the audit-emission shape (matches audit.Emit). Tests
// pass a fake.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Service is the exception governance service.
type Service struct {
	pool *pgxpool.Pool
	emit EmitFunc
}

// NewService wires the service. emit is audit.Emit in production.
func NewService(pool *pgxpool.Pool, emit EmitFunc) *Service {
	return &Service{pool: pool, emit: emit}
}

const selectCols = `id, host_id, rule_id, reason, status, requested_by,
	reviewed_by, COALESCE(review_note, ''), expires_at, requested_at, reviewed_at`

func scanException(row pgx.Row) (Exception, error) {
	var e Exception
	var status string
	if err := row.Scan(&e.ID, &e.HostID, &e.RuleID, &e.Reason, &status,
		&e.RequestedBy, &e.ReviewedBy, &e.ReviewNote, &e.ExpiresAt,
		&e.RequestedAt, &e.ReviewedAt); err != nil {
		return Exception{}, err
	}
	e.Status = Status(status)
	return e, nil
}

// Request submits a new exception (status 'requested'). Returns
// ErrDuplicateOpen when a requested/approved exception already exists
// for the same host+rule. Emits compliance.exception.requested.
func (s *Service) Request(ctx context.Context, hostID uuid.UUID, ruleID, reason string,
	requestedBy uuid.UUID, expiresAt *time.Time) (Exception, error) {
	ruleID = strings.TrimSpace(ruleID)
	reason = strings.TrimSpace(reason)
	if ruleID == "" || reason == "" {
		return Exception{}, ErrInvalidInput
	}

	id := uuid.Must(uuid.NewV7())
	row := s.pool.QueryRow(ctx, `
		INSERT INTO compliance_exceptions
			(id, host_id, rule_id, reason, status, requested_by, expires_at)
		VALUES ($1, $2, $3, $4, 'requested', $5, $6)
		RETURNING `+selectCols,
		id, hostID, ruleID, reason, requestedBy, expiresAt)
	e, err := scanException(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Exception{}, ErrDuplicateOpen
		}
		return Exception{}, fmt.Errorf("exception: request: %w", err)
	}

	s.emitEvent(ctx, audit.ComplianceExceptionRequested, e, requestedBy, "requested")
	return e, nil
}

// Approve transitions a 'requested' exception to 'approved'. The
// reviewer must differ from the requester (separation of duties).
// Emits compliance.exception.approved.
func (s *Service) Approve(ctx context.Context, id, reviewedBy uuid.UUID, note string) (Exception, error) {
	return s.review(ctx, id, reviewedBy, note, StatusRequested, StatusApproved,
		audit.ComplianceExceptionApproved, true)
}

// Reject transitions a 'requested' exception to 'rejected'. Like
// Approve, the reviewer must differ from the requester. Emits
// compliance.exception.rejected.
func (s *Service) Reject(ctx context.Context, id, reviewedBy uuid.UUID, note string) (Exception, error) {
	return s.review(ctx, id, reviewedBy, note, StatusRequested, StatusRejected,
		audit.ComplianceExceptionRejected, true)
}

// Revoke transitions an 'approved' exception to 'revoked' before its
// expiry. The revoker may be anyone with the permission (revoking is
// not a self-review concern). Emits compliance.exception.revoked.
func (s *Service) Revoke(ctx context.Context, id, reviewedBy uuid.UUID, note string) (Exception, error) {
	return s.review(ctx, id, reviewedBy, note, StatusApproved, StatusRevoked,
		audit.ComplianceExceptionRevoked, false)
}

// review performs a guarded state transition fromState -> toState. The
// CHECK is in SQL (WHERE status = fromState) so a concurrent reviewer
// cannot double-transition; a zero-row update means the row was
// missing or already moved.
func (s *Service) review(ctx context.Context, id, reviewedBy uuid.UUID, note string,
	fromState, toState Status, code audit.Code, blockSelfReview bool) (Exception, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Exception{}, fmt.Errorf("exception: review begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row and read the requester for the self-review check.
	var status string
	var requestedBy uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT status, requested_by FROM compliance_exceptions
		 WHERE id = $1 FOR UPDATE`, id).Scan(&status, &requestedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Exception{}, ErrNotFound
	}
	if err != nil {
		return Exception{}, fmt.Errorf("exception: review lock: %w", err)
	}
	if Status(status) != fromState {
		return Exception{}, ErrWrongState
	}
	if blockSelfReview && requestedBy == reviewedBy {
		return Exception{}, ErrSelfReview
	}

	row := tx.QueryRow(ctx, `
		UPDATE compliance_exceptions
		   SET status = $2, reviewed_by = $3, review_note = NULLIF($4, ''),
		       reviewed_at = now(), updated_at = now()
		 WHERE id = $1
		RETURNING `+selectCols,
		id, string(toState), reviewedBy, note)
	e, err := scanException(row)
	if err != nil {
		return Exception{}, fmt.Errorf("exception: review update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Exception{}, fmt.Errorf("exception: review commit: %w", err)
	}

	s.emitEvent(ctx, code, e, reviewedBy, string(toState))
	return e, nil
}

// ListForHost returns a host's exceptions. When includeHistory is
// false, only open rows (requested + approved) are returned; true
// returns every row, newest first.
func (s *Service) ListForHost(ctx context.Context, hostID uuid.UUID, includeHistory bool) ([]Exception, error) {
	q := `SELECT ` + selectCols + ` FROM compliance_exceptions WHERE host_id = $1`
	if !includeHistory {
		q += ` AND status IN ('requested','approved')`
	}
	q += ` ORDER BY requested_at DESC`
	return s.queryList(ctx, q, hostID)
}

// ListFleet returns fleet-wide exceptions, optionally filtered by
// status. Empty status returns all. Newest first.
func (s *Service) ListFleet(ctx context.Context, status Status, limit int) ([]Exception, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if status == "" {
		return s.queryList(ctx, `SELECT `+selectCols+`
			FROM compliance_exceptions ORDER BY requested_at DESC LIMIT $1`, limit)
	}
	return s.queryList(ctx, `SELECT `+selectCols+`
		FROM compliance_exceptions WHERE status = $1
		ORDER BY requested_at DESC LIMIT $2`, string(status), limit)
}

func (s *Service) queryList(ctx context.Context, q string, args ...any) ([]Exception, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("exception: list: %w", err)
	}
	defer rows.Close()
	out := []Exception{}
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, fmt.Errorf("exception: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ActiveCountForHost counts the host's currently-suppressing
// exceptions (approved, not past expiry). Backs the host-detail
// Watchlist Exceptions row.
func (s *Service) ActiveCountForHost(ctx context.Context, hostID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_exceptions
		 WHERE host_id = $1 AND status = 'approved'
		   AND (expires_at IS NULL OR expires_at > now())`, hostID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("exception: active count: %w", err)
	}
	return n, nil
}

// ActiveRuleIDsForHost returns the set of rule ids the host has an
// active (suppressing) exception for. Backs the Compliance-tab
// waived-rule annotation - read alongside host_rule_state, never
// mutating it.
func (s *Service) ActiveRuleIDsForHost(ctx context.Context, hostID uuid.UUID) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rule_id FROM compliance_exceptions
		 WHERE host_id = $1 AND status = 'approved'
		   AND (expires_at IS NULL OR expires_at > now())`, hostID)
	if err != nil {
		return nil, fmt.Errorf("exception: active rule ids: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, fmt.Errorf("exception: scan rule id: %w", err)
		}
		out[ruleID] = true
	}
	return out, rows.Err()
}

// ExpireSweep flips approved exceptions whose expires_at has passed to
// 'expired' and emits compliance.exception.expired for each. Returns
// the count expired. Idempotent: a second run finds nothing.
func (s *Service) ExpireSweep(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE compliance_exceptions
		   SET status = 'expired', updated_at = now()
		 WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at <= now()
		RETURNING `+selectCols)
	if err != nil {
		return 0, fmt.Errorf("exception: expire sweep: %w", err)
	}
	defer rows.Close()
	var expired []Exception
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return 0, fmt.Errorf("exception: sweep scan: %w", err)
		}
		expired = append(expired, e)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("exception: sweep iterate: %w", err)
	}
	for _, e := range expired {
		// System-actor expiry: no reviewer.
		s.emitEvent(ctx, audit.ComplianceExceptionExpired, e, uuid.Nil, "expired")
	}
	return len(expired), nil
}

// emitEvent records one compliance.exception.* audit row. actor is the
// requester/reviewer; uuid.Nil actor marks a system event (expiry).
func (s *Service) emitEvent(ctx context.Context, code audit.Code, e Exception, actor uuid.UUID, action string) {
	if s.emit == nil {
		return
	}
	actorType := "user"
	actorID := actor.String()
	if actor == uuid.Nil {
		actorType, actorID = "system", "openwatch"
	}
	detail, _ := json.Marshal(map[string]any{
		"exception_id": e.ID.String(),
		"host_id":      e.HostID.String(),
		"rule_id":      e.RuleID,
		"action":       action,
		"status":       string(e.Status),
	})
	s.emit(ctx, code, audit.Event{
		ActorType:    actorType,
		ActorID:      actorID,
		ResourceType: "compliance_exception",
		ResourceID:   e.ID.String(),
		Detail:       detail,
	})
}

// isUniqueViolation reports whether err is a Postgres unique-violation
// (SQLSTATE 23505) - the partial-unique one-open-per-host+rule index.
// Same errors.As idiom as internal/host (robust to wrapping).
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// ExpirySweepInterval is the production cadence of the expiry sweep.
// Hourly is fine: an exception only needs to flip to expired soon
// after its expires_at, and the count/annotation queries already guard
// on expires_at so suppression stops at the deadline regardless.
const ExpirySweepInterval = time.Hour
