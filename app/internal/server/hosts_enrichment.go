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
// AC-14. v1.4.0 adds monitoring_state + per-layer counters.
func loadHostLiveness(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) (*api.HostLiveness, error) {
	const q = `
		SELECT reachability_status, monitoring_state,
		       last_probe_at, last_response_ms,
		       consecutive_failures,
		       ping_consecutive_failures, ping_consecutive_successes,
		       ssh_consecutive_failures, ssh_consecutive_successes,
		       privilege_consecutive_failures, privilege_consecutive_successes,
		       last_state_change_at, last_error_type
		  FROM host_liveness
		 WHERE host_id = $1`
	var (
		status            string
		monState          string
		lastProbeAt       *time.Time
		lastResponseMS    *int
		consecutiveFails  int
		pingFail, pingOK  int
		sshFail, sshOK    int
		privFail, privOK  int
		lastStateChangeAt *time.Time
		lastErrorType     *string
	)
	err := pool.QueryRow(ctx, q, hostID).Scan(
		&status, &monState,
		&lastProbeAt, &lastResponseMS,
		&consecutiveFails,
		&pingFail, &pingOK,
		&sshFail, &sshOK,
		&privFail, &privOK,
		&lastStateChangeAt, &lastErrorType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // AC-14: no liveness row → null in response
		}
		return nil, fmt.Errorf("loadHostLiveness: %w", err)
	}
	ms := api.HostLivenessMonitoringState(monState)
	out := &api.HostLiveness{
		ReachabilityStatus:            api.HostLivenessReachabilityStatus(status),
		MonitoringState:               &ms,
		ConsecutiveFailures:           &consecutiveFails,
		PingConsecutiveFailures:       &pingFail,
		PingConsecutiveSuccesses:      &pingOK,
		SshConsecutiveFailures:        &sshFail,
		SshConsecutiveSuccesses:       &sshOK,
		PrivilegeConsecutiveFailures:  &privFail,
		PrivilegeConsecutiveSuccesses: &privOK,
		LastProbeAt:                   lastProbeAt,
		LastResponseMs:                lastResponseMS,
		LastStateChangeAt:             lastStateChangeAt,
		LastErrorType:                 lastErrorType,
	}
	return out, nil
}

// loadHostLivenessByIDs returns liveness sub-objects keyed by host ID.
// Single batched query — one round-trip regardless of fleet size.
// Hosts with no liveness row simply don't appear in the map (the list
// handler renders that as null on the response item).
func loadHostLivenessByIDs(ctx context.Context, pool *pgxpool.Pool, ids []uuid.UUID) (map[uuid.UUID]*api.HostLiveness, error) {
	out := map[uuid.UUID]*api.HostLiveness{}
	if len(ids) == 0 {
		return out, nil
	}
	const q = `
		SELECT host_id, reachability_status, monitoring_state,
		       last_probe_at, last_response_ms, consecutive_failures,
		       ping_consecutive_failures, ping_consecutive_successes,
		       ssh_consecutive_failures, ssh_consecutive_successes,
		       privilege_consecutive_failures, privilege_consecutive_successes,
		       last_state_change_at, last_error_type
		  FROM host_liveness
		 WHERE host_id = ANY($1)`
	rows, err := pool.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("loadHostLivenessByIDs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			hostID            uuid.UUID
			status            string
			monState          string
			lastProbeAt       *time.Time
			lastResponseMS    *int
			consecutiveFails  int
			pingFail, pingOK  int
			sshFail, sshOK    int
			privFail, privOK  int
			lastStateChangeAt *time.Time
			lastErrorType     *string
		)
		if err := rows.Scan(
			&hostID, &status, &monState,
			&lastProbeAt, &lastResponseMS, &consecutiveFails,
			&pingFail, &pingOK,
			&sshFail, &sshOK,
			&privFail, &privOK,
			&lastStateChangeAt, &lastErrorType,
		); err != nil {
			return nil, fmt.Errorf("loadHostLivenessByIDs scan: %w", err)
		}
		ms := api.HostLivenessMonitoringState(monState)
		out[hostID] = &api.HostLiveness{
			ReachabilityStatus:            api.HostLivenessReachabilityStatus(status),
			MonitoringState:               &ms,
			ConsecutiveFailures:           &consecutiveFails,
			PingConsecutiveFailures:       &pingFail,
			PingConsecutiveSuccesses:      &pingOK,
			SshConsecutiveFailures:        &sshFail,
			SshConsecutiveSuccesses:       &sshOK,
			PrivilegeConsecutiveFailures:  &privFail,
			PrivilegeConsecutiveSuccesses: &privOK,
			LastProbeAt:                   lastProbeAt,
			LastResponseMs:                lastResponseMS,
			LastStateChangeAt:             lastStateChangeAt,
			LastErrorType:                 lastErrorType,
		}
	}
	return out, rows.Err()
}

// loadHostLastScanByIDs returns MAX(host_rule_state.last_checked_at)
// keyed by host id. Hosts with no rule_state rows don't appear in the
// map — the list handler renders that as null ("Never scanned").
//
// Spec api-hosts v1.5.0 — surfaces "last scan" without requiring a
// separate scans table. host_rule_state's last_checked_at is the
// source of truth because every compliance check writes there.
func loadHostLastScanByIDs(ctx context.Context, pool *pgxpool.Pool, ids []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := map[uuid.UUID]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}
	const q = `
		SELECT host_id, MAX(last_checked_at)
		  FROM host_rule_state
		 WHERE host_id = ANY($1)
		 GROUP BY host_id`
	rows, err := pool.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("loadHostLastScanByIDs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hid uuid.UUID
		var last time.Time
		if err := rows.Scan(&hid, &last); err != nil {
			return nil, fmt.Errorf("loadHostLastScanByIDs scan: %w", err)
		}
		out[hid] = last
	}
	return out, rows.Err()
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
