/**
 * Host Detail API Adapter
 *
 * Transforms snake_case backend API responses to camelCase frontend types
 * for the Host Detail page redesign. Centralizes all host detail data fetching
 * with proper type conversion.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module services/adapters/hostDetailAdapter
 */

import { api } from '../api';
import type {
  ComplianceState,
  ComplianceFinding,
  SeveritySummary,
  HostSchedule,
  SchedulerStatus,
  ScheduledScan,
  SystemInfo,
  ServerIntelligenceSummary,
  PackagesResponse,
  Package,
  ServicesResponse,
  Service,
  UsersResponse,
  User,
  NetworkResponse,
  NetworkInterface,
  FirewallResponse,
  FirewallRule,
  RoutesResponse,
  Route,
  ScanHistoryResponse,
  ScanHistoryItem,
  ScanResults,
} from '../../types/hostDetail';

// =============================================================================
// API Response Types (snake_case from backend)
// =============================================================================

interface ApiComplianceFinding {
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  detail: string | null;
  framework_section: string | null;
}

interface ApiSeveritySummary {
  critical: { passed: number; failed: number };
  high: { passed: number; failed: number };
  medium: { passed: number; failed: number };
  low: { passed: number; failed: number };
}

interface ApiComplianceState {
  host_id: string;
  hostname: string;
  scan_id: string | null;
  scan_date: string | null;
  total_rules: number;
  passed: number;
  failed: number;
  unknown: number;
  compliance_score: number;
  findings: ApiComplianceFinding[];
  severity_summary: ApiSeveritySummary;
}

interface ApiHostSchedule {
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

interface ApiScheduledScan {
  host_id: string;
  hostname: string;
  compliance_state: string;
  next_scheduled_scan: string;
  scan_priority: number;
}

interface ApiSchedulerStatus {
  enabled: boolean;
  total_hosts: number;
  hosts_due: number;
  hosts_in_maintenance: number;
  by_compliance_state: Record<string, number>;
  next_scheduled_scans: ApiScheduledScan[];
}

interface ApiSystemInfo {
  os_name: string | null;
  os_version: string | null;
  os_version_full: string | null;
  os_pretty_name: string | null;
  os_id: string | null;
  os_id_like: string | null;
  kernel_version: string | null;
  kernel_release: string | null;
  kernel_name: string | null;
  architecture: string | null;
  cpu_model: string | null;
  cpu_cores: number | null;
  cpu_threads: number | null;
  memory_total_mb: number | null;
  memory_available_mb: number | null;
  swap_total_mb: number | null;
  disk_total_gb: number | null;
  disk_used_gb: number | null;
  disk_free_gb: number | null;
  selinux_status: string | null;
  selinux_mode: string | null;
  firewall_status: string | null;
  firewall_service: string | null;
  hostname: string | null;
  fqdn: string | null;
  primary_ip: string | null;
  uptime_seconds: number | null;
  boot_time: string | null;
  collected_at: string | null;
  updated_at: string | null;
}

interface ApiServerIntelligenceSummary {
  host_id: string;
  system_info_collected: boolean;
  packages_count: number;
  services_count: number;
  running_services_count: number;
  listening_ports_count: number;
  users_count: number;
  sudo_users_count: number;
  network_interfaces_count: number;
  firewall_rules_count: number;
  routes_count: number;
  last_collected_at: string | null;
}

interface ApiPackage {
  name: string;
  version: string | null;
  release: string | null;
  arch: string | null;
  source_repo: string | null;
  installed_at: string | null;
  collected_at: string | null;
}

interface ApiService {
  name: string;
  display_name: string | null;
  status: string | null;
  enabled: boolean | null;
  service_type: string | null;
  run_as_user: string | null;
  listening_ports: Array<{ port: number; protocol: string; address: string }> | null;
  collected_at: string | null;
}

interface ApiUser {
  username: string;
  uid: number | null;
  gid: number | null;
  groups: string[] | null;
  home_dir: string | null;
  shell: string | null;
  gecos: string | null;
  is_system_account: boolean | null;
  is_locked: boolean | null;
  has_password: boolean | null;
  password_last_changed: string | null;
  password_expires: string | null;
  password_max_days: number | null;
  password_warn_days: number | null;
  last_login: string | null;
  last_login_ip: string | null;
  ssh_keys_count: number | null;
  ssh_key_types: string[] | null;
  sudo_rules: string[] | null;
  has_sudo_all: boolean | null;
  has_sudo_nopasswd: boolean | null;
  collected_at: string | null;
}

interface ApiNetworkInterface {
  interface_name: string;
  mac_address: string | null;
  ip_addresses: Array<{ address: string; prefix_length: number; family: string }> | null;
  is_up: boolean | null;
  mtu: number | null;
  speed_mbps: number | null;
  interface_type: string | null;
  collected_at: string | null;
}

interface ApiFirewallRule {
  firewall_type: string | null;
  chain: string | null;
  rule_number: number | null;
  protocol: string | null;
  source: string | null;
  destination: string | null;
  port: string | null;
  action: string | null;
  interface_in: string | null;
  interface_out: string | null;
  state: string | null;
  comment: string | null;
  raw_rule: string | null;
  collected_at: string | null;
}

interface ApiRoute {
  destination: string;
  gateway: string | null;
  interface: string | null;
  metric: number | null;
  scope: string | null;
  route_type: string | null;
  protocol: string | null;
  is_default: boolean | null;
  collected_at: string | null;
}

interface ApiScanResults {
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  error_rules: number;
  score: string;
  severity_high: number;
  severity_medium: number;
  severity_low: number;
  severity_critical?: number;
}

interface ApiScanHistoryItem {
  id: string;
  name: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at: string | null;
  content_name: string | null;
  profile_id: string | null;
  results: ApiScanResults | null;
}

// =============================================================================
// Transformation Functions
// =============================================================================

function adaptComplianceFinding(finding: ApiComplianceFinding): ComplianceFinding {
  return {
    ruleId: finding.rule_id,
    title: finding.title,
    severity: finding.severity as ComplianceFinding['severity'],
    status: finding.status as ComplianceFinding['status'],
    detail: finding.detail,
    frameworkSection: finding.framework_section,
  };
}

function adaptSeveritySummary(summary: ApiSeveritySummary): SeveritySummary {
  return {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
  };
}

function adaptComplianceState(state: ApiComplianceState): ComplianceState {
  return {
    hostId: state.host_id,
    hostname: state.hostname,
    scanId: state.scan_id,
    scanDate: state.scan_date,
    totalRules: state.total_rules,
    passed: state.passed,
    failed: state.failed,
    unknown: state.unknown,
    complianceScore: state.compliance_score,
    findings: state.findings.map(adaptComplianceFinding),
    severitySummary: adaptSeveritySummary(state.severity_summary),
  };
}

function adaptHostSchedule(schedule: ApiHostSchedule): HostSchedule {
  return {
    hostId: schedule.host_id,
    hostname: schedule.hostname,
    complianceScore: schedule.compliance_score,
    complianceState: schedule.compliance_state as HostSchedule['complianceState'],
    hasCriticalFindings: schedule.has_critical_findings,
    passCount: schedule.pass_count,
    failCount: schedule.fail_count,
    currentIntervalMinutes: schedule.current_interval_minutes,
    nextScheduledScan: schedule.next_scheduled_scan,
    lastScanCompleted: schedule.last_scan_completed,
    maintenanceMode: schedule.maintenance_mode,
    maintenanceUntil: schedule.maintenance_until,
    scanPriority: schedule.scan_priority,
    consecutiveScanFailures: schedule.consecutive_scan_failures,
  };
}

function adaptScheduledScan(scan: ApiScheduledScan): ScheduledScan {
  return {
    hostId: scan.host_id,
    hostname: scan.hostname,
    complianceState: scan.compliance_state,
    nextScheduledScan: scan.next_scheduled_scan,
    scanPriority: scan.scan_priority,
  };
}

function adaptSchedulerStatus(status: ApiSchedulerStatus): SchedulerStatus {
  return {
    enabled: status.enabled,
    totalHosts: status.total_hosts,
    hostsDue: status.hosts_due,
    hostsInMaintenance: status.hosts_in_maintenance,
    byComplianceState: status.by_compliance_state,
    nextScheduledScans: status.next_scheduled_scans.map(adaptScheduledScan),
  };
}

function adaptSystemInfo(info: ApiSystemInfo): SystemInfo {
  return {
    osName: info.os_name,
    osVersion: info.os_version,
    osVersionFull: info.os_version_full,
    osPrettyName: info.os_pretty_name,
    osId: info.os_id,
    osIdLike: info.os_id_like,
    kernelVersion: info.kernel_version,
    kernelRelease: info.kernel_release,
    kernelName: info.kernel_name,
    architecture: info.architecture,
    cpuModel: info.cpu_model,
    cpuCores: info.cpu_cores,
    cpuThreads: info.cpu_threads,
    memoryTotalMb: info.memory_total_mb,
    memoryAvailableMb: info.memory_available_mb,
    swapTotalMb: info.swap_total_mb,
    diskTotalGb: info.disk_total_gb,
    diskUsedGb: info.disk_used_gb,
    diskFreeGb: info.disk_free_gb,
    selinuxStatus: info.selinux_status,
    selinuxMode: info.selinux_mode,
    firewallStatus: info.firewall_status,
    firewallService: info.firewall_service,
    hostname: info.hostname,
    fqdn: info.fqdn,
    primaryIp: info.primary_ip,
    uptimeSeconds: info.uptime_seconds,
    bootTime: info.boot_time,
    collectedAt: info.collected_at,
    updatedAt: info.updated_at,
  };
}

function adaptServerIntelligenceSummary(
  summary: ApiServerIntelligenceSummary
): ServerIntelligenceSummary {
  return {
    hostId: summary.host_id,
    systemInfoCollected: summary.system_info_collected,
    packagesCount: summary.packages_count,
    servicesCount: summary.services_count,
    runningServicesCount: summary.running_services_count,
    listeningPortsCount: summary.listening_ports_count,
    usersCount: summary.users_count,
    sudoUsersCount: summary.sudo_users_count,
    networkInterfacesCount: summary.network_interfaces_count,
    firewallRulesCount: summary.firewall_rules_count,
    routesCount: summary.routes_count,
    lastCollectedAt: summary.last_collected_at,
  };
}

function adaptPackage(pkg: ApiPackage): Package {
  return {
    name: pkg.name,
    version: pkg.version,
    release: pkg.release,
    arch: pkg.arch,
    sourceRepo: pkg.source_repo,
    installedAt: pkg.installed_at,
    collectedAt: pkg.collected_at,
  };
}

function adaptService(svc: ApiService): Service {
  return {
    name: svc.name,
    displayName: svc.display_name,
    status: svc.status as Service['status'],
    enabled: svc.enabled,
    serviceType: svc.service_type,
    runAsUser: svc.run_as_user,
    listeningPorts: svc.listening_ports,
    collectedAt: svc.collected_at,
  };
}

function adaptUser(user: ApiUser): User {
  return {
    username: user.username,
    uid: user.uid,
    gid: user.gid,
    groups: user.groups,
    homeDir: user.home_dir,
    shell: user.shell,
    gecos: user.gecos,
    isSystemAccount: user.is_system_account,
    isLocked: user.is_locked,
    hasPassword: user.has_password,
    passwordLastChanged: user.password_last_changed,
    passwordExpires: user.password_expires,
    passwordMaxDays: user.password_max_days,
    passwordWarnDays: user.password_warn_days,
    lastLogin: user.last_login,
    lastLoginIp: user.last_login_ip,
    sshKeysCount: user.ssh_keys_count,
    sshKeyTypes: user.ssh_key_types,
    sudoRules: user.sudo_rules,
    hasSudoAll: user.has_sudo_all,
    hasSudoNopasswd: user.has_sudo_nopasswd,
    collectedAt: user.collected_at,
  };
}

function adaptNetworkInterface(iface: ApiNetworkInterface): NetworkInterface {
  return {
    interfaceName: iface.interface_name,
    macAddress: iface.mac_address,
    ipAddresses:
      iface.ip_addresses?.map((ip) => ({
        address: ip.address,
        prefixLength: ip.prefix_length,
        family: ip.family as 'ipv4' | 'ipv6',
      })) || null,
    isUp: iface.is_up,
    mtu: iface.mtu,
    speedMbps: iface.speed_mbps,
    interfaceType: iface.interface_type,
    collectedAt: iface.collected_at,
  };
}

function adaptFirewallRule(rule: ApiFirewallRule): FirewallRule {
  return {
    firewallType: rule.firewall_type,
    chain: rule.chain,
    ruleNumber: rule.rule_number,
    protocol: rule.protocol,
    source: rule.source,
    destination: rule.destination,
    port: rule.port,
    action: rule.action,
    interfaceIn: rule.interface_in,
    interfaceOut: rule.interface_out,
    state: rule.state,
    comment: rule.comment,
    rawRule: rule.raw_rule,
    collectedAt: rule.collected_at,
  };
}

function adaptRoute(route: ApiRoute): Route {
  return {
    destination: route.destination,
    gateway: route.gateway,
    interface: route.interface,
    metric: route.metric,
    scope: route.scope,
    routeType: route.route_type,
    protocol: route.protocol,
    isDefault: route.is_default,
    collectedAt: route.collected_at,
  };
}

function adaptScanResults(results: ApiScanResults): ScanResults {
  return {
    totalRules: results.total_rules,
    passedRules: results.passed_rules,
    failedRules: results.failed_rules,
    errorRules: results.error_rules,
    score: results.score,
    severityHigh: results.severity_high,
    severityMedium: results.severity_medium,
    severityLow: results.severity_low,
    severityCritical: results.severity_critical,
  };
}

function adaptScanHistoryItem(item: ApiScanHistoryItem): ScanHistoryItem {
  return {
    id: item.id,
    name: item.name,
    status: item.status as ScanHistoryItem['status'],
    progress: item.progress,
    startedAt: item.started_at,
    completedAt: item.completed_at,
    contentName: item.content_name,
    profileId: item.profile_id,
    results: item.results ? adaptScanResults(item.results) : null,
  };
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Fetch compliance state for a host
 */
export async function fetchComplianceState(hostId: string): Promise<ComplianceState> {
  const data = await api.get<ApiComplianceState>(`/api/scans/aegis/compliance-state/${hostId}`);
  return adaptComplianceState(data);
}

/**
 * Fetch host schedule from compliance scheduler
 */
export async function fetchHostSchedule(hostId: string): Promise<HostSchedule> {
  const data = await api.get<ApiHostSchedule>(`/api/compliance/scheduler/hosts/${hostId}`);
  return adaptHostSchedule(data);
}

/**
 * Fetch scheduler status for dashboard
 */
export async function fetchSchedulerStatus(): Promise<SchedulerStatus> {
  const data = await api.get<ApiSchedulerStatus>('/api/compliance/scheduler/status');
  return adaptSchedulerStatus(data);
}

/**
 * Fetch system info for a host
 */
export async function fetchSystemInfo(hostId: string): Promise<SystemInfo | null> {
  try {
    const data = await api.get<ApiSystemInfo>(`/api/hosts/${hostId}/system-info`);
    return adaptSystemInfo(data);
  } catch {
    // Return null if no system info collected yet
    return null;
  }
}

/**
 * Fetch server intelligence summary for a host
 */
export async function fetchIntelligenceSummary(
  hostId: string
): Promise<ServerIntelligenceSummary | null> {
  try {
    const data = await api.get<ApiServerIntelligenceSummary>(
      `/api/hosts/${hostId}/intelligence/summary`
    );
    return adaptServerIntelligenceSummary(data);
  } catch {
    return null;
  }
}

/**
 * Fetch packages for a host
 */
export async function fetchPackages(
  hostId: string,
  options?: { search?: string; limit?: number; offset?: number }
): Promise<PackagesResponse> {
  const params = new URLSearchParams();
  if (options?.search) params.append('search', options.search);
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/packages${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{ items: ApiPackage[]; total: number; limit: number; offset: number }>(
    url
  );
  return {
    items: data.items.map(adaptPackage),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch services for a host
 */
export async function fetchServices(
  hostId: string,
  options?: { search?: string; status?: string; limit?: number; offset?: number }
): Promise<ServicesResponse> {
  const params = new URLSearchParams();
  if (options?.search) params.append('search', options.search);
  if (options?.status) params.append('status', options.status);
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/services${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{ items: ApiService[]; total: number; limit: number; offset: number }>(
    url
  );
  return {
    items: data.items.map(adaptService),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch users for a host
 */
export async function fetchUsers(
  hostId: string,
  options?: {
    search?: string;
    includeSystem?: boolean;
    hasSudo?: boolean;
    limit?: number;
    offset?: number;
  }
): Promise<UsersResponse> {
  const params = new URLSearchParams();
  if (options?.search) params.append('search', options.search);
  if (options?.includeSystem !== undefined)
    params.append('include_system', String(options.includeSystem));
  if (options?.hasSudo !== undefined) params.append('has_sudo', String(options.hasSudo));
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/users${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{ items: ApiUser[]; total: number; limit: number; offset: number }>(
    url
  );
  return {
    items: data.items.map(adaptUser),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch network interfaces for a host
 */
export async function fetchNetwork(
  hostId: string,
  options?: { interfaceType?: string; isUp?: boolean; limit?: number; offset?: number }
): Promise<NetworkResponse> {
  const params = new URLSearchParams();
  if (options?.interfaceType) params.append('interface_type', options.interfaceType);
  if (options?.isUp !== undefined) params.append('is_up', String(options.isUp));
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/network${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{
    items: ApiNetworkInterface[];
    total: number;
    limit: number;
    offset: number;
  }>(url);
  return {
    items: data.items.map(adaptNetworkInterface),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch firewall rules for a host
 */
export async function fetchFirewall(
  hostId: string,
  options?: {
    chain?: string;
    action?: string;
    firewallType?: string;
    limit?: number;
    offset?: number;
  }
): Promise<FirewallResponse> {
  const params = new URLSearchParams();
  if (options?.chain) params.append('chain', options.chain);
  if (options?.action) params.append('action', options.action);
  if (options?.firewallType) params.append('firewall_type', options.firewallType);
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/firewall${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{
    items: ApiFirewallRule[];
    total: number;
    limit: number;
    offset: number;
  }>(url);
  return {
    items: data.items.map(adaptFirewallRule),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch routes for a host
 */
export async function fetchRoutes(
  hostId: string,
  options?: { isDefault?: boolean; limit?: number; offset?: number }
): Promise<RoutesResponse> {
  const params = new URLSearchParams();
  if (options?.isDefault !== undefined) params.append('is_default', String(options.isDefault));
  if (options?.limit) params.append('limit', String(options.limit));
  if (options?.offset) params.append('offset', String(options.offset));

  const queryString = params.toString();
  const url = `/api/hosts/${hostId}/routes${queryString ? `?${queryString}` : ''}`;

  const data = await api.get<{ items: ApiRoute[]; total: number; limit: number; offset: number }>(
    url
  );
  return {
    items: data.items.map(adaptRoute),
    total: data.total,
    limit: data.limit,
    offset: data.offset,
  };
}

/**
 * Fetch scan history for a host
 */
export async function fetchScanHistory(hostId: string): Promise<ScanHistoryResponse> {
  const data = await api.get<{ scans: ApiScanHistoryItem[] }>(`/api/scans/?host_id=${hostId}`);
  return {
    scans: (data.scans || []).map(adaptScanHistoryItem),
    total: data.scans?.length || 0,
  };
}
