package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/server/api"
)

// loadHostLiveness reads the host_liveness row for the given host, or
// returns (nil, nil) when no row exists. Spec api-hosts C-05 / AC-13 /
// AC-14.
func loadHostLiveness(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (*api.HostLiveness, error) {
	const q = `
		SELECT reachability_status, last_probe_at, last_response_ms,
		       consecutive_failures, last_state_change_at, last_error_type
		  FROM host_liveness
		 WHERE host_id = $1`
	var (
		status            string
		lastProbeAt       *time.Time
		lastResponseMS    *int
		consecutiveFails  int
		lastStateChangeAt *time.Time
		lastErrorType     *string
	)
	err := pool.QueryRow(ctx, q, hostID).Scan(
		&status, &lastProbeAt, &lastResponseMS,
		&consecutiveFails, &lastStateChangeAt, &lastErrorType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // AC-14: no liveness row → null in response
		}
		return nil, fmt.Errorf("loadHostLiveness: %w", err)
	}
	out := &api.HostLiveness{
		ReachabilityStatus:  api.HostLivenessReachabilityStatus(status),
		ConsecutiveFailures: &consecutiveFails,
		LastProbeAt:         lastProbeAt,
		LastResponseMs:      lastResponseMS,
		LastStateChangeAt:   lastStateChangeAt,
		LastErrorType:       lastErrorType,
	}
	return out, nil
}

// loadHostComplianceSummary reads the per-status counts from
// host_rule_state for the given host. A host with no rule_state rows
// returns all zeros — never an error. Spec api-hosts C-06 / AC-16.
//
// framework, when non-empty, filters rows to those whose framework_refs
// JSONB contains the given key (api-hosts v1.2.0 AC-17 / AC-18). A host
// whose rule_state has no rows mapped to the requested framework
// returns all-zero counts (AC-18).
func loadHostComplianceSummary(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, framework string) (api.HostComplianceSummary, error) {
	const q = `
		SELECT
			COUNT(*) FILTER (WHERE current_status = 'pass')::BIGINT    AS passing,
			COUNT(*) FILTER (WHERE current_status = 'fail')::BIGINT    AS failing,
			COUNT(*) FILTER (WHERE current_status = 'skipped')::BIGINT AS skipped,
			COUNT(*) FILTER (WHERE current_status = 'error')::BIGINT   AS errors,
			COUNT(*)::BIGINT                                           AS total
		  FROM host_rule_state
		 WHERE host_id = $1
		   AND ($2::text IS NULL OR framework_refs ? $2)`
	var s api.HostComplianceSummary
	var frameworkParam any
	if framework != "" {
		frameworkParam = framework
	}
	if err := pool.QueryRow(ctx, q, hostID, frameworkParam).Scan(
		&s.Passing, &s.Failing, &s.Skipped, &s.Error, &s.Total,
	); err != nil {
		return api.HostComplianceSummary{}, fmt.Errorf("loadHostComplianceSummary: %w", err)
	}
	return s, nil
}
