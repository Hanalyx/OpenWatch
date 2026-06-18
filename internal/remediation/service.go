package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// EmitFunc is the audit-emission shape (matches audit.Emit). Tests pass a fake.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// Service is the free remediation governance service. It never contacts a host.
type Service struct {
	pool *pgxpool.Pool
	emit EmitFunc
}

// NewService wires the service. emit is audit.Emit in production.
func NewService(pool *pgxpool.Pool, emit EmitFunc) *Service {
	return &Service{pool: pool, emit: emit}
}

const selectCols = `id, host_id, rule_id, status, requested_by, reviewed_by,
	COALESCE(review_note, ''), scan_run_id, COALESCE(mechanism, ''),
	reboot_required, transactional, projected_cis, projected_stig, projected_nist,
	requested_at, reviewed_at`

// listCols adds the joined hostname for the list query. Aliased "e." since the
// list query joins hosts as h.
const listCols = `e.id, e.host_id, COALESCE(h.hostname, ''), e.rule_id, e.status,
	e.requested_by, e.reviewed_by, COALESCE(e.review_note, ''), e.scan_run_id,
	COALESCE(e.mechanism, ''), e.reboot_required, e.transactional,
	e.projected_cis, e.projected_stig, e.projected_nist,
	e.requested_at, e.reviewed_at`

func scanRequest(row pgx.Row) (Request, error) {
	var rq Request
	var status string
	if err := row.Scan(&rq.ID, &rq.HostID, &rq.RuleID, &status, &rq.RequestedBy,
		&rq.ReviewedBy, &rq.ReviewNote, &rq.ScanRunID, &rq.Mechanism,
		&rq.RebootRequired, &rq.Transactional,
		&rq.Projected.CIS, &rq.Projected.STIG, &rq.Projected.NIST,
		&rq.RequestedAt, &rq.ReviewedAt); err != nil {
		return Request{}, err
	}
	rq.Status = Status(status)
	return rq, nil
}

// scanListRequest scans a list row (listCols), including hostname.
func scanListRequest(row pgx.Row) (Request, error) {
	var rq Request
	var status string
	if err := row.Scan(&rq.ID, &rq.HostID, &rq.HostName, &rq.RuleID, &status,
		&rq.RequestedBy, &rq.ReviewedBy, &rq.ReviewNote, &rq.ScanRunID, &rq.Mechanism,
		&rq.RebootRequired, &rq.Transactional,
		&rq.Projected.CIS, &rq.Projected.STIG, &rq.Projected.NIST,
		&rq.RequestedAt, &rq.ReviewedAt); err != nil {
		return Request{}, err
	}
	rq.Status = Status(status)
	return rq, nil
}

// Request submits a new remediation request (status 'pending_approval'),
// recording a best-effort projected per-framework lift. Returns
// ErrDuplicateOpen when an open request already exists for the same host+rule.
// NEVER contacts the host. Emits remediation.requested.
func (s *Service) Request(ctx context.Context, hostID uuid.UUID, ruleID string,
	scanRunID *uuid.UUID, requestedBy uuid.UUID) (Request, error) {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return Request{}, ErrInvalidInput
	}

	// Best-effort projection: a failure to compute lift must not block the
	// request (C-07). An empty projection is recorded as NULL columns.
	proj, _ := s.ProjectLift(ctx, hostID, ruleID)

	id := uuid.Must(uuid.NewV7())
	row := s.pool.QueryRow(ctx, `
		INSERT INTO remediation_requests
			(id, host_id, rule_id, scan_run_id, status, requested_by,
			 projected_cis, projected_stig, projected_nist)
		VALUES ($1, $2, $3, $4, 'pending_approval', $5, $6, $7, $8)
		RETURNING `+selectCols,
		id, hostID, ruleID, scanRunID, requestedBy, proj.CIS, proj.STIG, proj.NIST)
	rq, err := scanRequest(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Request{}, ErrDuplicateOpen
		}
		return Request{}, fmt.Errorf("remediation: request: %w", err)
	}

	s.emitEvent(ctx, audit.RemediationRequested, rq, requestedBy, "requested")
	return rq, nil
}

// Approve transitions a 'pending_approval' request to 'approved'. The reviewer
// must differ from the requester (separation of duties). Emits
// remediation.approved.
func (s *Service) Approve(ctx context.Context, id, reviewedBy uuid.UUID, note string) (Request, error) {
	return s.review(ctx, id, reviewedBy, note, StatusPendingApproval, StatusApproved)
}

// Reject transitions a 'pending_approval' request to 'rejected'. Like Approve,
// the reviewer must differ from the requester. The registered taxonomy has no
// separate rejected code, so this emits remediation.approved with
// detail.outcome=rejected.
func (s *Service) Reject(ctx context.Context, id, reviewedBy uuid.UUID, note string) (Request, error) {
	return s.review(ctx, id, reviewedBy, note, StatusPendingApproval, StatusRejected)
}

// review performs a guarded state transition fromState -> toState under a row
// lock (FOR UPDATE) so concurrent reviewers cannot double-transition. Both
// approve and reject emit remediation.approved (the only registered review
// code); the outcome is carried in detail.outcome.
func (s *Service) review(ctx context.Context, id, reviewedBy uuid.UUID, note string,
	fromState, toState Status) (Request, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: review begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row and read the requester for the self-review check.
	var status string
	var requestedBy uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT status, requested_by FROM remediation_requests
		 WHERE id = $1 FOR UPDATE`, id).Scan(&status, &requestedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("remediation: review lock: %w", err)
	}
	if Status(status) != fromState {
		return Request{}, ErrWrongState
	}
	if requestedBy == reviewedBy {
		return Request{}, ErrSelfReview
	}

	row := tx.QueryRow(ctx, `
		UPDATE remediation_requests
		   SET status = $2, reviewed_by = $3, review_note = NULLIF($4, ''),
		       reviewed_at = now(), updated_at = now()
		 WHERE id = $1
		RETURNING `+selectCols,
		id, string(toState), reviewedBy, note)
	rq, err := scanRequest(row)
	if err != nil {
		return Request{}, fmt.Errorf("remediation: review update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("remediation: review commit: %w", err)
	}

	s.emitEvent(ctx, audit.RemediationApproved, rq, reviewedBy, string(toState))
	return rq, nil
}

// Get returns a single remediation request by id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Request, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+selectCols+`
		FROM remediation_requests WHERE id = $1`, id)
	rq, err := scanRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	if err != nil {
		return Request{}, fmt.Errorf("remediation: get: %w", err)
	}
	return rq, nil
}

// ListFilter scopes ListRequests. A zero-value filter lists the whole fleet.
type ListFilter struct {
	Status Status
	HostID *uuid.UUID
	RuleID string
	Limit  int
}

// ListRequests returns remediation requests, newest first, optionally filtered
// by status, host, or rule. Soft-deleted hosts are excluded.
func (s *Service) ListRequests(ctx context.Context, f ListFilter) ([]Request, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT ` + listCols + ` FROM remediation_requests e
		JOIN hosts h ON h.id = e.host_id AND h.deleted_at IS NULL WHERE 1 = 1`
	args := []any{}
	if f.Status != "" {
		args = append(args, string(f.Status))
		q += fmt.Sprintf(" AND e.status = $%d", len(args))
	}
	if f.HostID != nil {
		args = append(args, *f.HostID)
		q += fmt.Sprintf(" AND e.host_id = $%d", len(args))
	}
	if r := strings.TrimSpace(f.RuleID); r != "" {
		args = append(args, r)
		q += fmt.Sprintf(" AND e.rule_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY e.requested_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("remediation: list: %w", err)
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		rq, err := scanListRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("remediation: scan: %w", err)
		}
		out = append(out, rq)
	}
	return out, rows.Err()
}

// ListSteps returns the per-step Kensa transaction journal for a request, in
// apply order. Empty in the free build (only the licensed execute path writes
// steps).
func (s *Service) ListSteps(ctx context.Context, requestID uuid.UUID) ([]Step, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, rule_id, COALESCE(mechanism, ''), phase_result, dry_run, applied_at
		  FROM remediation_transactions
		 WHERE request_id = $1
		 ORDER BY ordinal ASC, created_at ASC`, requestID)
	if err != nil {
		return nil, fmt.Errorf("remediation: list steps: %w", err)
	}
	defer rows.Close()
	out := []Step{}
	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.ID, &st.RuleID, &st.Mechanism, &st.PhaseResult,
			&st.DryRun, &st.AppliedAt); err != nil {
			return nil, fmt.Errorf("remediation: scan step: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ProjectLift estimates the per-framework compliance-score lift (percentage
// points) if ruleID flips to pass on hostID. Read-only and best-effort: it
// reads host_rule_state only. A non-failing or unknown rule, or absent
// framework data, yields an empty projection (no error). One passing rule is
// ~1/N of its framework's rules on the host, so delta ~= 100/N.
func (s *Service) ProjectLift(ctx context.Context, hostID uuid.UUID, ruleID string) (ProjectedLift, error) {
	var status string
	var refsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT current_status, framework_refs FROM host_rule_state
		 WHERE host_id = $1 AND rule_id = $2`, hostID, ruleID).Scan(&status, &refsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProjectedLift{}, nil // no state for this rule on this host
	}
	if err != nil {
		return ProjectedLift{}, fmt.Errorf("remediation: project lift: %w", err)
	}
	if status != "fail" {
		return ProjectedLift{}, nil // only a failing rule has lift to gain
	}

	refs := map[string][]string{}
	_ = json.Unmarshal(refsRaw, &refs)
	classes := map[string]bool{}
	for fwID := range refs {
		if c := frameworkClass(fwID); c != "" {
			classes[c] = true
		}
	}
	if len(classes) == 0 {
		return ProjectedLift{}, nil
	}

	// Denominators: how many of the host's rules participate in each framework.
	var nCIS, nSTIG, nNIST int
	err = s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_object_keys(framework_refs) k WHERE k LIKE 'cis%')),
		  count(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_object_keys(framework_refs) k WHERE k LIKE 'stig%')),
		  count(*) FILTER (WHERE EXISTS (SELECT 1 FROM jsonb_object_keys(framework_refs) k WHERE k LIKE 'nist%'))
		FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&nCIS, &nSTIG, &nNIST)
	if err != nil {
		return ProjectedLift{}, fmt.Errorf("remediation: project lift denom: %w", err)
	}

	var out ProjectedLift
	if classes["cis"] && nCIS > 0 {
		out.CIS = f64ptr(round2(100.0 / float64(nCIS)))
	}
	if classes["stig"] && nSTIG > 0 {
		out.STIG = f64ptr(round2(100.0 / float64(nSTIG)))
	}
	if classes["nist"] && nNIST > 0 {
		out.NIST = f64ptr(round2(100.0 / float64(nNIST)))
	}
	return out, nil
}

// frameworkClass maps a kensa framework_id (e.g. "cis_rhel9_v2",
// "stig_rhel9_v2r7", "nist_800_53_r5") to the cis/stig/nist projection bucket.
func frameworkClass(fwID string) string {
	switch {
	case strings.HasPrefix(fwID, "cis"):
		return "cis"
	case strings.HasPrefix(fwID, "stig"):
		return "stig"
	case strings.HasPrefix(fwID, "nist"):
		return "nist"
	}
	return ""
}

func round2(f float64) float64  { return math.Round(f*100) / 100 }
func f64ptr(f float64) *float64 { return &f }

// emitEvent records one remediation.* audit row. actor is the
// requester/reviewer.
func (s *Service) emitEvent(ctx context.Context, code audit.Code, rq Request, actor uuid.UUID, outcome string) {
	if s.emit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"request_id": rq.ID.String(),
		"host_id":    rq.HostID.String(),
		"rule_id":    rq.RuleID,
		"outcome":    outcome,
		"status":     string(rq.Status),
	})
	s.emit(ctx, code, audit.Event{
		ActorType:    "user",
		ActorID:      actor.String(),
		ResourceType: "remediation_request",
		ResourceID:   rq.ID.String(),
		Detail:       detail,
	})
}

// isUniqueViolation reports whether err is a Postgres unique-violation
// (SQLSTATE 23505) - the partial-unique one-open-per-host+rule index.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
