/**
 * Scheduler API Adapter
 *
 * Provides typed API methods for the adaptive compliance scheduler.
 * Used by the ScheduledScans page for configuration, status, and
 * per-host schedule management.
 *
 * @module services/adapters/schedulerAdapter
 */

import { api } from '../api';

// =============================================================================
// Types
// =============================================================================

/** Scheduler configuration returned from GET /api/compliance/scheduler/config */
export interface SchedulerConfig {
  enabled: boolean;
  interval_compliant: number;
  interval_mostly_compliant: number;
  interval_partial: number;
  interval_low: number;
  interval_critical: number;
  interval_unknown: number;
  interval_maintenance: number;
  max_interval_minutes: number;
  priority_compliant: number;
  priority_mostly_compliant: number;
  priority_partial: number;
  priority_low: number;
  priority_critical: number;
  priority_unknown: number;
  priority_maintenance: number;
  max_concurrent_scans: number;
  scan_timeout_seconds: number;
}

/** Scheduler status returned from GET /api/compliance/scheduler/status */
export interface SchedulerStatus {
  enabled: boolean;
  total_hosts: number;
  hosts_due: number;
  hosts_in_maintenance: number;
  by_compliance_state: Record<string, number>;
  next_scheduled_scans: ScheduledScanEntry[];
}

/** An upcoming scheduled scan entry */
export interface ScheduledScanEntry {
  host_id: string;
  hostname: string;
  compliance_state: string;
  next_scheduled_scan: string;
  scan_priority: number;
}

/** Per-host schedule returned from GET /api/compliance/scheduler/hosts/:id */
export interface HostScheduleEntry {
  host_id: string;
  hostname: string;
  compliance_score: number | null;
  compliance_state: string;
  has_critical_findings: boolean;
  pass_count: number | null;
  fail_count: number | null;
  current_interval_minutes: number;
  next_scheduled_scan: string | null;
  last_scan_completed: string | null;
  maintenance_mode: boolean;
  maintenance_until: string | null;
  scan_priority: number;
  consecutive_scan_failures: number;
}

/** Partial config update for PUT /api/compliance/scheduler/config */
export interface SchedulerConfigUpdate {
  enabled?: boolean;
  interval_compliant?: number;
  interval_mostly_compliant?: number;
  interval_partial?: number;
  interval_low?: number;
  interval_critical?: number;
  interval_unknown?: number;
  max_concurrent_scans?: number;
  scan_timeout_seconds?: number;
}

// =============================================================================
// Service
// =============================================================================

export const schedulerService = {
  /** Fetch current scheduler configuration */
  getConfig: (): Promise<SchedulerConfig> =>
    api.get<SchedulerConfig>('/api/compliance/scheduler/config'),

  /** Update scheduler configuration (partial update) */
  updateConfig: (config: SchedulerConfigUpdate): Promise<SchedulerConfig> =>
    api.put<SchedulerConfig>('/api/compliance/scheduler/config', config),

  /** Fetch scheduler status and statistics */
  getStatus: (): Promise<SchedulerStatus> =>
    api.get<SchedulerStatus>('/api/compliance/scheduler/status'),

  /** Fetch schedule for a specific host */
  getHostSchedule: (hostId: string): Promise<HostScheduleEntry> =>
    api.get<HostScheduleEntry>(`/api/compliance/scheduler/hosts/${hostId}`),
};
