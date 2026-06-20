// Host list view-model types. The /hosts page maps the real API response
// (ApiHost) into this shape for rendering. There is NO demo/fixture data —
// the page always reflects the live backend.

// monitoring_state distinguishes WHICH layer is failing (sudo broken vs ssh
// down vs network outage). 'status' stays as the coarse online/down view.
export type MonitoringBand =
  | 'online'
  | 'degraded'
  | 'critical'
  | 'down'
  | 'maintenance'
  | 'unknown';

export interface DevHost {
  id: string;
  hostname: string; // "—" if no hostname registered (display falls back to IP)
  ip_address: string;
  /**
   * Display label produced by osDisplayLabel() from the real
   * hosts.os_family column (populated by Discovery). "Unknown" for
   * pre-Discovery hosts. Spec: frontend-host-list-os.
   */
  os: string;
  status: 'down' | 'online';
  /** 5-band classification, from host_liveness.monitoring_state */
  monitoring: MonitoringBand;
  /** operator paused per-host probes */
  maintenance?: boolean;
  compliance: number | null; // 0..100, null when no scan data
  passed: number | null;
  failed: number | null;
  total: number;
  /**
   * Failing rules with critical severity, from the list endpoint's
   * compliance_summary.critical_failing. 0 when never scanned.
   * Spec frontend-hosts-list AC-18.
   */
  criticalFailing?: number;
  // null when no host_liveness row exists ("never probed"). The list cell
  // renders "—" in that case rather than the misleading "0m ago".
  lastCheckMinutes: number | null;
  lastScan: string; // "Xh ago" or "Xm ago"
  /**
   * id of the newest completed scan_run, from the list endpoint's
   * latest_scan_id. null when the host has no completed scan — the card's
   * "view report" affordance is hidden in that case. Spec
   * frontend-hosts-list AC-24, links to /scans/{latestScanId}.
   */
  latestScanId: string | null;
}

export type DeltaTier = 'crit' | 'warn' | 'ok' | 'neutral';

export interface DevKpis {
  hostsOnline: { value: number; total: number; delta: string; deltaTier: DeltaTier };
  avgCompliance: { value: number; target: number; delta: string; deltaTier: DeltaTier };
  criticalIssues: { value: number; scope: string; delta: string; deltaTier: DeltaTier };
  scanQueue: { value: number; scope: string; delta: string; deltaTier: DeltaTier };
}
