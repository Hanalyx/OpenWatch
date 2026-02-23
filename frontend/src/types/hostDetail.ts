/**
 * Host Detail Type Definitions
 *
 * Type definitions for the Host Detail page redesign.
 * Provides interfaces for auto-scan centric data display
 * including compliance state, scheduler status, and server intelligence.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module types/hostDetail
 */

// =============================================================================
// Compliance State Types
// =============================================================================

/**
 * Individual compliance finding from scan results
 */
export interface ComplianceFinding {
  ruleId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'pass' | 'fail' | 'skipped' | 'error';
  detail: string | null;
  frameworkSection: string | null;
}

/**
 * Severity summary with pass/fail breakdown
 */
export interface SeveritySummary {
  critical: { passed: number; failed: number };
  high: { passed: number; failed: number };
  medium: { passed: number; failed: number };
  low: { passed: number; failed: number };
}

/**
 * Compliance state for a host from latest Kensa scan
 */
export interface ComplianceState {
  hostId: string;
  hostname: string;
  scanId: string | null;
  scanDate: string | null;
  totalRules: number;
  passed: number;
  failed: number;
  unknown: number;
  complianceScore: number;
  findings: ComplianceFinding[];
  severitySummary: SeveritySummary;
}

// =============================================================================
// Scheduler Types
// =============================================================================

/**
 * Host schedule details from compliance scheduler
 */
export interface HostSchedule {
  hostId: string;
  hostname: string;
  complianceScore: number | null;
  complianceState: 'compliant' | 'mostly_compliant' | 'partial' | 'low' | 'critical' | 'unknown';
  hasCriticalFindings: boolean;
  passCount: number | null;
  failCount: number | null;
  currentIntervalMinutes: number;
  nextScheduledScan: string | null;
  lastScanCompleted: string | null;
  maintenanceMode: boolean;
  maintenanceUntil: string | null;
  scanPriority: number;
  consecutiveScanFailures: number;
}

/**
 * Scheduler status for dashboard widget
 */
export interface SchedulerStatus {
  enabled: boolean;
  totalHosts: number;
  hostsDue: number;
  hostsInMaintenance: number;
  byComplianceState: Record<string, number>;
  nextScheduledScans: ScheduledScan[];
}

/**
 * Upcoming scheduled scan
 */
export interface ScheduledScan {
  hostId: string;
  hostname: string;
  complianceState: string;
  nextScheduledScan: string;
  scanPriority: number;
}

// =============================================================================
// System Information Types
// =============================================================================

/**
 * Host system information
 */
export interface SystemInfo {
  osName: string | null;
  osVersion: string | null;
  osVersionFull: string | null;
  osPrettyName: string | null;
  osId: string | null;
  osIdLike: string | null;
  kernelVersion: string | null;
  kernelRelease: string | null;
  kernelName: string | null;
  architecture: string | null;
  cpuModel: string | null;
  cpuCores: number | null;
  cpuThreads: number | null;
  memoryTotalMb: number | null;
  memoryAvailableMb: number | null;
  swapTotalMb: number | null;
  diskTotalGb: number | null;
  diskUsedGb: number | null;
  diskFreeGb: number | null;
  selinuxStatus: string | null;
  selinuxMode: string | null;
  firewallStatus: string | null;
  firewallService: string | null;
  hostname: string | null;
  fqdn: string | null;
  primaryIp: string | null;
  uptimeSeconds: number | null;
  bootTime: string | null;
  collectedAt: string | null;
  updatedAt: string | null;
}

/**
 * Server intelligence summary
 */
export interface ServerIntelligenceSummary {
  hostId: string;
  systemInfoCollected: boolean;
  packagesCount: number;
  servicesCount: number;
  runningServicesCount: number;
  listeningPortsCount: number;
  usersCount: number;
  sudoUsersCount: number;
  networkInterfacesCount: number;
  firewallRulesCount: number;
  routesCount: number;
  lastCollectedAt: string | null;
}

// =============================================================================
// Packages Types
// =============================================================================

/**
 * Installed package on a host
 */
export interface Package {
  name: string;
  version: string | null;
  release: string | null;
  arch: string | null;
  sourceRepo: string | null;
  installedAt: string | null;
  collectedAt: string | null;
}

/**
 * Paginated packages response
 */
export interface PackagesResponse {
  items: Package[];
  total: number;
  limit: number;
  offset: number;
}

// =============================================================================
// Services Types
// =============================================================================

/**
 * System service on a host
 */
export interface Service {
  name: string;
  displayName: string | null;
  status: 'running' | 'stopped' | 'failed' | 'unknown' | null;
  enabled: boolean | null;
  serviceType: string | null;
  runAsUser: string | null;
  listeningPorts: ListeningPort[] | null;
  collectedAt: string | null;
}

/**
 * Listening port for a service
 */
export interface ListeningPort {
  port: number;
  protocol: string;
  address: string;
}

/**
 * Paginated services response
 */
export interface ServicesResponse {
  items: Service[];
  total: number;
  limit: number;
  offset: number;
}

// =============================================================================
// Users Types
// =============================================================================

/**
 * User account on a host
 */
export interface User {
  username: string;
  uid: number | null;
  gid: number | null;
  groups: string[] | null;
  homeDir: string | null;
  shell: string | null;
  gecos: string | null;
  isSystemAccount: boolean | null;
  isLocked: boolean | null;
  hasPassword: boolean | null;
  passwordLastChanged: string | null;
  passwordExpires: string | null;
  passwordMaxDays: number | null;
  passwordWarnDays: number | null;
  lastLogin: string | null;
  lastLoginIp: string | null;
  sshKeysCount: number | null;
  sshKeyTypes: string[] | null;
  sudoRules: string[] | null;
  hasSudoAll: boolean | null;
  hasSudoNopasswd: boolean | null;
  collectedAt: string | null;
}

/**
 * Paginated users response
 */
export interface UsersResponse {
  items: User[];
  total: number;
  limit: number;
  offset: number;
}

// =============================================================================
// Network Types
// =============================================================================

/**
 * Network interface on a host
 */
export interface NetworkInterface {
  interfaceName: string;
  macAddress: string | null;
  ipAddresses: IpAddress[] | null;
  isUp: boolean | null;
  mtu: number | null;
  speedMbps: number | null;
  interfaceType: string | null;
  collectedAt: string | null;
}

/**
 * IP address configuration
 */
export interface IpAddress {
  address: string;
  prefixLength: number;
  family: 'ipv4' | 'ipv6';
}

/**
 * Paginated network interfaces response
 */
export interface NetworkResponse {
  items: NetworkInterface[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Firewall rule on a host
 */
export interface FirewallRule {
  firewallType: string | null;
  chain: string | null;
  ruleNumber: number | null;
  protocol: string | null;
  source: string | null;
  destination: string | null;
  port: string | null;
  action: string | null;
  interfaceIn: string | null;
  interfaceOut: string | null;
  state: string | null;
  comment: string | null;
  rawRule: string | null;
  collectedAt: string | null;
}

/**
 * Paginated firewall rules response
 */
export interface FirewallResponse {
  items: FirewallRule[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Network route on a host
 */
export interface Route {
  destination: string;
  gateway: string | null;
  interface: string | null;
  metric: number | null;
  scope: string | null;
  routeType: string | null;
  protocol: string | null;
  isDefault: boolean | null;
  collectedAt: string | null;
}

/**
 * Paginated routes response
 */
export interface RoutesResponse {
  items: Route[];
  total: number;
  limit: number;
  offset: number;
}

// =============================================================================
// Exceptions Types
// =============================================================================

/**
 * Compliance exception
 */
export interface ComplianceException {
  id: string;
  ruleId: string;
  hostId: string | null;
  hostGroupId: string | null;
  justification: string;
  riskAcceptance: string | null;
  compensatingControls: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked';
  requestedBy: number;
  approvedBy: number | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Exceptions summary for a host
 */
export interface ExceptionsSummary {
  hostId: string;
  activeCount: number;
  pendingCount: number;
  expiredCount: number;
}

// =============================================================================
// Alerts Types
// =============================================================================

/**
 * Compliance alert
 */
export interface ComplianceAlert {
  id: string;
  hostId: string;
  alertType: 'compliance_drop' | 'critical_finding' | 'scan_failure' | 'drift_detected';
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  isAcknowledged: boolean;
  createdAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy: number | null;
}

/**
 * Alerts summary for a host
 */
export interface AlertsSummary {
  hostId: string;
  activeCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  recentAlerts: ComplianceAlert[];
}

// =============================================================================
// Scan History Types
// =============================================================================

/**
 * Historical scan record
 */
export interface ScanHistoryItem {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  startedAt: string;
  completedAt: string | null;
  contentName: string | null;
  profileId: string | null;
  results: ScanResults | null;
}

/**
 * Scan results summary
 */
export interface ScanResults {
  totalRules: number;
  passedRules: number;
  failedRules: number;
  errorRules: number;
  score: string;
  severityHigh: number;
  severityMedium: number;
  severityLow: number;
  severityCritical?: number;
}

/**
 * Paginated scan history response
 */
export interface ScanHistoryResponse {
  scans: ScanHistoryItem[];
  total: number;
}

// =============================================================================
// Combined Host Detail Data
// =============================================================================

/**
 * Complete host detail data for the redesigned page
 */
export interface HostDetailData {
  // Basic host info
  host: {
    id: string;
    hostname: string;
    displayName: string;
    ipAddress: string;
    operatingSystem: string;
    osVersion: string;
    kernelVersion: string | null;
    status: string;
    port: number;
    username: string;
    authMethod: string;
    createdAt: string;
    updatedAt: string;
    lastCheck: string | null;
  };

  // Compliance data
  complianceState: ComplianceState | null;

  // Scheduler data
  schedule: HostSchedule | null;

  // Server intelligence
  systemInfo: SystemInfo | null;
  intelligenceSummary: ServerIntelligenceSummary | null;

  // Exceptions and alerts
  exceptionsSummary: ExceptionsSummary | null;
  alertsSummary: AlertsSummary | null;

  // Scan history
  scanHistory: ScanHistoryItem[];
}
