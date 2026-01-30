/**
 * Host API Response Adapter
 *
 * Transforms snake_case backend API responses to camelCase frontend types
 * and vice versa for request payloads. Centralizes the transformation logic
 * previously scattered inline across Hosts.tsx and AddHost.tsx.
 *
 * Backend uses PostgreSQL naming conventions (snake_case).
 * Frontend uses TypeScript conventions (camelCase).
 *
 * @module services/adapters/hostAdapter
 */

import type { Host, HostStatus, AuthMethod } from '../../types/host';

// ---------------------------------------------------------------------------
// Backend response types (snake_case)
// ---------------------------------------------------------------------------

/** GET /api/hosts/ response item */
export interface ApiHostResponse {
  id: string;
  hostname: string;
  display_name?: string;
  ip_address: string;
  operating_system: string;
  os_version?: string;
  status?: string;
  scan_status?: string;
  compliance_score?: number;
  last_scan?: string;
  last_check?: string;
  critical_issues?: number;
  high_issues?: number;
  medium_issues?: number;
  low_issues?: number;
  tags?: string[];
  group?: string;
  group_id?: number;
  group_name?: string;
  group_description?: string;
  group_color?: string;
  owner?: string;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  uptime?: string;
  last_backup?: string;
  ssh_key?: boolean;
  agent_status?: string;
  scan_profile?: string;
  port?: number;
  username?: string;
  auth_method?: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  latest_scan_id?: string;
  latest_scan_name?: string;
  scan_progress?: number;
  failed_rules?: number;
  passed_rules?: number;
  total_rules?: number;
}

/** POST /api/hosts/test-connection response */
export interface ApiConnectionTestResponse {
  network_reachable?: boolean;
  auth_successful?: boolean;
  detected_os?: string;
  os_version?: string;
  response_time_ms?: number;
  ssh_version?: string;
  additional_info?: string;
}

/** GET /api/system/credentials response item */
export interface ApiCredentialResponse {
  id?: string;
  name?: string;
  username?: string;
  is_default: boolean;
  auth_method?: string;
  ssh_key_fingerprint?: string | null;
  ssh_key_type?: string | null;
  ssh_key_bits?: number | null;
  ssh_key_comment?: string | null;
}

/** POST /api/hosts/validate-credentials response */
export interface ApiKeyValidationResponse {
  is_valid: boolean;
  message?: string;
  key_type?: string;
  key_bits?: number;
  security_level?: 'secure' | 'acceptable' | 'deprecated' | 'rejected';
}

// ---------------------------------------------------------------------------
// Frontend types (camelCase)
// ---------------------------------------------------------------------------

export interface ConnectionTestResult {
  success: boolean;
  networkConnectivity: boolean;
  authentication: boolean;
  detectedOS: string;
  detectedVersion: string;
  responseTime: number;
  sshVersion?: string;
  additionalInfo?: string;
  error?: string;
  errorCode?: number;
}

export interface SystemCredential {
  name: string;
  username: string;
  authMethod: string;
  sshKeyType?: string;
  sshKeyBits?: number;
  sshKeyComment?: string;
}

export interface KeyValidationResult {
  isValid: boolean;
  message?: string;
  keyType?: string;
  keyBits?: number;
  securityLevel?: 'secure' | 'acceptable' | 'deprecated' | 'rejected';
}

// ---------------------------------------------------------------------------
// Backend request types (snake_case payloads)
// ---------------------------------------------------------------------------

export interface ApiHostCreateRequest {
  hostname: string;
  ip_address: string;
  display_name?: string;
  operating_system: string;
  auth_method?: string;
  ssh_key?: string;
  password?: string;
  port?: number;
  username?: string;
}

export interface ApiHostUpdateRequest {
  hostname?: string;
  ip_address?: string;
  display_name?: string;
  operating_system?: string;
  port?: number;
  username?: string;
  auth_method?: string;
  ssh_key?: string;
  password?: string;
}

// ---------------------------------------------------------------------------
// Response transformers (snake_case -> camelCase)
// ---------------------------------------------------------------------------

/** Transform a backend host response to a frontend Host object. */
export function adaptHost(host: ApiHostResponse): Host {
  return {
    id: host.id,
    hostname: host.hostname,
    displayName: host.display_name || host.hostname,
    ipAddress: host.ip_address,
    operatingSystem: host.operating_system,
    status: (host.scan_status === 'running' || host.scan_status === 'pending'
      ? 'scanning'
      : host.status || 'offline') as HostStatus,
    complianceScore: host.compliance_score || null,
    complianceTrend: 'stable' as const,
    lastScan: host.last_scan || null,
    lastCheck: host.last_check || null,
    nextScan: host.last_scan ? 'Pending' : null,
    criticalIssues: host.critical_issues || 0,
    highIssues: host.high_issues || 0,
    mediumIssues: host.medium_issues || 0,
    lowIssues: host.low_issues || 0,
    tags: host.tags || [],
    group: host.group_name || host.group || 'Ungrouped',
    group_id: host.group_id ?? undefined,
    group_name: host.group_name ?? undefined,
    group_description: host.group_description ?? undefined,
    group_color: host.group_color ?? undefined,
    owner: host.owner || 'Unassigned',
    cpuUsage: host.cpu_usage || null,
    memoryUsage: host.memory_usage || null,
    diskUsage: host.disk_usage || null,
    uptime: host.uptime || null,
    osVersion: host.os_version || host.operating_system,
    lastBackup: host.last_backup || null,
    sshKey: host.ssh_key || false,
    agent: host.agent_status || 'not_installed',
    profile: host.scan_profile || null,
    port: host.port || 22,
    username: host.username || '',
    authMethod: (host.auth_method || 'ssh_key') as AuthMethod,
    ssh_key_fingerprint: host.ssh_key_fingerprint ?? undefined,
    ssh_key_type: host.ssh_key_type ?? undefined,
    ssh_key_bits: host.ssh_key_bits ?? undefined,
    ssh_key_comment: host.ssh_key_comment ?? undefined,
    latestScanId: host.latest_scan_id || null,
    latestScanName: host.latest_scan_name || null,
    scanStatus: host.scan_status || null,
    scanProgress: host.scan_progress || null,
    failedRules: host.failed_rules || 0,
    passedRules: host.passed_rules || 0,
    totalRules: host.total_rules || 0,
  };
}

/** Transform a list of backend host responses. */
export function adaptHosts(hosts: ApiHostResponse[]): Host[] {
  return hosts.map(adaptHost);
}

/** Transform a connection test API response. */
export function adaptConnectionTest(response: ApiConnectionTestResponse): ConnectionTestResult {
  return {
    success: true,
    networkConnectivity: response.network_reachable ?? true,
    authentication: response.auth_successful ?? true,
    detectedOS: response.detected_os || 'Unknown',
    detectedVersion: response.os_version || '',
    responseTime: response.response_time_ms || 0,
    sshVersion: response.ssh_version,
    additionalInfo: response.additional_info,
  };
}

/** Transform a system credential API response. */
export function adaptCredential(cred: ApiCredentialResponse): SystemCredential {
  return {
    name: cred.name || '',
    username: cred.username || '',
    authMethod: cred.auth_method || 'password',
    sshKeyType: cred.ssh_key_type ?? undefined,
    sshKeyBits: cred.ssh_key_bits ?? undefined,
    sshKeyComment: cred.ssh_key_comment ?? undefined,
  };
}

/** Transform an SSH key validation API response. */
export function adaptKeyValidation(response: ApiKeyValidationResponse): KeyValidationResult {
  return {
    isValid: response.is_valid,
    message: response.message,
    keyType: response.key_type,
    keyBits: response.key_bits,
    securityLevel: response.security_level,
  };
}

// ---------------------------------------------------------------------------
// Request transformers (camelCase -> snake_case)
// ---------------------------------------------------------------------------

interface HostFormData {
  hostname: string;
  ipAddress: string;
  displayName?: string;
  operatingSystem: string;
  authMethod?: string;
  sshKey?: string;
  password?: string;
  port?: number;
  username?: string;
}

/** Build a create-host request payload from form data. */
export function toCreateHostRequest(form: HostFormData): ApiHostCreateRequest {
  return {
    hostname: form.hostname || form.ipAddress,
    ip_address: form.ipAddress || form.hostname,
    display_name: form.displayName,
    operating_system: form.operatingSystem === 'auto-detect' ? 'Unknown' : form.operatingSystem,
    auth_method: form.authMethod,
    ssh_key: form.authMethod === 'ssh_key' ? form.sshKey : undefined,
    password: form.authMethod === 'password' ? form.password : undefined,
    port: form.port,
    username: form.username,
  };
}

interface HostEditFormData {
  hostname: string;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  port: number;
  username: string;
  authMethod: string;
  sshKey: string;
  password: string;
}

/** Build an update-host request payload from edit form data. */
export function toUpdateHostRequest(form: HostEditFormData): ApiHostUpdateRequest {
  return {
    hostname: form.hostname,
    ip_address: form.ipAddress,
    display_name: form.displayName,
    operating_system: form.operatingSystem,
    port: form.port,
    username: form.username,
    auth_method: form.authMethod,
    ssh_key: form.sshKey,
    password: form.password,
  };
}
