package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/framework"
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

// loadHostLatestScanIDByIDs returns the id of the newest COMPLETED
// scan_runs row per host, keyed by host id. Hosts with no completed
// scan_run don't appear in the map — the list handler renders that as
// latest_scan_id: null, so the host card hides its "view report" link.
//
// A queued/running-only host is intentionally excluded: the link targets
// GET /scans/{id}, the scan-detail (report) page, which only has results
// once the run completes. ONE query for the whole page (DISTINCT ON over
// the scan_runs_host_recent index) — no per-host N+1. Spec api-hosts
// v1.6.0 C-13.
func loadHostLatestScanIDByIDs(ctx context.Context, pool *pgxpool.Pool, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := map[uuid.UUID]uuid.UUID{}
	if len(ids) == 0 {
		return out, nil
	}
	const q = `
		SELECT DISTINCT ON (host_id) host_id, id
		  FROM scan_runs
		 WHERE host_id = ANY($1) AND status = 'completed'
		 ORDER BY host_id, queued_at DESC`
	rows, err := pool.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("loadHostLatestScanIDByIDs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hid, sid uuid.UUID
		if err := rows.Scan(&hid, &sid); err != nil {
			return nil, fmt.Errorf("loadHostLatestScanIDByIDs scan: %w", err)
		}
		out[hid] = sid
	}
	return out, rows.Err()
}

// loadHostListComplianceByIDs returns per-host compliance roll-ups
// keyed by host id — ONE grouped query against host_rule_state for the
// whole page, no per-host N+1. Hosts with zero rule_state rows don't
// appear in the map; the list handler renders that as
// compliance_summary: null ("never scanned"). critical_failing counts
// rows with current_status='fail' AND critical severity
// (case-insensitive). Spec api-hosts v1.5.0 C-12 / AC-23.
func loadHostListComplianceByIDs(ctx context.Context, pool *pgxpool.Pool, ids []uuid.UUID, lens string) (map[uuid.UUID]*api.HostListComplianceSummary, error) {
	out := map[uuid.UUID]*api.HostListComplianceSummary{}
	if len(ids) == 0 {
		return out, nil
	}
	// $2 is the default-lens family / specific key (or NULL for all rules);
	// framework.MatchSQL resolves a family per host in-query so each card
	// reflects the same lens as the fleet KPI.
	q := `
		SELECT host_id,
		       COUNT(*) FILTER (WHERE current_status = 'pass')::BIGINT    AS passing,
		       COUNT(*) FILTER (WHERE current_status = 'fail')::BIGINT    AS failing,
		       COUNT(*) FILTER (WHERE current_status = 'skipped')::BIGINT AS skipped,
		       COUNT(*) FILTER (WHERE current_status = 'error')::BIGINT   AS errors,
		       COUNT(*)::BIGINT                                           AS total,
		       COUNT(*) FILTER (WHERE current_status = 'fail'
		                          AND lower(COALESCE(severity, '')) = 'critical')::BIGINT AS critical_failing
		  FROM host_rule_state
		 WHERE host_id = ANY($1)
		   AND ` + framework.MatchSQL("$2") + `
		 GROUP BY host_id`
	var frameworkParam any
	if lens != "" {
		frameworkParam = lens
	}
	rows, err := pool.Query(ctx, q, ids, frameworkParam)
	if err != nil {
		return nil, fmt.Errorf("loadHostListComplianceByIDs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hid uuid.UUID
		var s api.HostListComplianceSummary
		if err := rows.Scan(&hid, &s.Passing, &s.Failing, &s.Skipped,
			&s.Error, &s.Total, &s.CriticalFailing); err != nil {
			return nil, fmt.Errorf("loadHostListComplianceByIDs scan: %w", err)
		}
		out[hid] = &s
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
func loadHostComplianceSummary(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, lens string) (api.HostComplianceSummary, error) {
	// $2 is a family id or a specific corpus key (or NULL for all rules);
	// framework.MatchSQL resolves a family (e.g. "stig") to the host's own
	// OS key (stig_rhel9 for a RHEL 9 host) in-query, so the list can carry
	// a single family filter uniformly across a mixed-OS fleet.
	q := `
		SELECT
			COUNT(*) FILTER (WHERE current_status = 'pass')::BIGINT    AS passing,
			COUNT(*) FILTER (WHERE current_status = 'fail')::BIGINT    AS failing,
			COUNT(*) FILTER (WHERE current_status = 'skipped')::BIGINT AS skipped,
			COUNT(*) FILTER (WHERE current_status = 'error')::BIGINT   AS errors,
			COUNT(*)::BIGINT                                           AS total
		  FROM host_rule_state
		 WHERE host_id = $1
		   AND ` + framework.MatchSQL("$2")
	var s api.HostComplianceSummary
	var frameworkParam any
	if lens != "" {
		frameworkParam = lens
	}
	if err := pool.QueryRow(ctx, q, hostID, frameworkParam).Scan(
		&s.Passing, &s.Failing, &s.Skipped, &s.Error, &s.Total,
	); err != nil {
		return api.HostComplianceSummary{}, fmt.Errorf("loadHostComplianceSummary: %w", err)
	}
	return s, nil
}
