/**
 * Host Type Definitions
 *
 * Centralized type definitions for host inventory management in OpenWatch.
 * This module provides type safety for host-related data structures throughout
 * the frontend application.
 *
 * Used by:
 * - Hosts management page (pages/hosts/Hosts.tsx)
 * - Host detail page (pages/hosts/HostDetail.tsx)
 * - Host API service (services/hostService.ts)
 * - Host-related components (components/hosts/*)
 *
 * DO NOT add application logic here - this file is for types only.
 *
 * @module types/host
 */

/**
 * Host status enumeration.
 *
 * Status progression for host connectivity and availability:
 * - online: Fully accessible, ready for compliance scans
 * - degraded: Operational with performance issues
 * - critical: Major functionality impaired
 * - down: Service unavailable
 * - offline: Completely unreachable (no ping response)
 * - maintenance: Scheduled maintenance mode
 * - scanning: Currently executing SCAP scan
 * - reachable: Responds to ping but SSH authentication failed
 * - ping_only: Responds to ping but SSH port 22 closed
 * - error: Error occurred during status check
 * - unknown: Status not yet determined
 */
export type HostStatus =
  | 'online'
  | 'degraded'
  | 'critical'
  | 'down'
  | 'offline'
  | 'maintenance'
  | 'scanning'
  | 'reachable'
  | 'ping_only'
  | 'error'
  | 'unknown';

/**
 * Compliance trend indicator.
 *
 * Indicates whether compliance score is improving, declining, or stable
 * compared to previous scan.
 */
export type ComplianceTrend = 'up' | 'down' | 'stable';

/**
 * SSH authentication method.
 *
 * Authentication methods for SSH connections to hosts:
 * - password: Username/password authentication
 * - ssh_key: Public/private key authentication (preferred)
 * - none: No authentication configured
 * - default: Use default credentials
 * - system_default: Use system-wide default credentials
 */
export type AuthMethod = 'password' | 'ssh_key' | 'none' | 'default' | 'system_default';

/**
 * Host inventory record.
 *
 * Represents a single host in the OpenWatch compliance scanning system.
 * Combines infrastructure metadata, compliance status, and scan results.
 *
 * @interface Host
 *
 * @example
 * const host: Host = {
 *   id: "550e8400-e29b-41d4-a716-446655440000",
 *   hostname: "web-server-01.example.com",
 *   displayName: "Production Web Server 01",
 *   ipAddress: "192.168.1.100",
 *   operatingSystem: "RHEL",
 *   osVersion: "8.5",
 *   status: "online",
 *   complianceScore: 87.5,
 *   complianceTrend: "up",
 *   criticalIssues: 2,
 *   highIssues: 5,
 *   mediumIssues: 12,
 *   lowIssues: 8,
 *   // ... other fields
 * };
 */
export interface Host {
  // Identification
  /** UUID of the host (primary key) */
  id: string;

  /** DNS hostname or FQDN */
  hostname: string;

  /** Human-friendly display name */
  displayName: string;

  /** IPv4 address */
  ipAddress: string;

  // Operating System
  /** Operating system family (RHEL, Ubuntu, Windows, etc.) */
  operatingSystem: string;

  /** Specific OS version (e.g., "8.5", "20.04 LTS") */
  osVersion: string;

  // Status & Health
  /** Current host status and connectivity state */
  status: HostStatus;

  /** CPU utilization percentage (0-100) or null if unavailable */
  cpuUsage: number | null;

  /** Memory utilization percentage (0-100) or null if unavailable */
  memoryUsage: number | null;

  /** Disk utilization percentage (0-100) or null if unavailable */
  diskUsage: number | null;

  /** Uptime duration string (e.g., "14 days, 3:22:15") or null */
  uptime: string | null;

  // Compliance & Scanning
  /** Overall compliance score (0-100) or null if never scanned */
  complianceScore: number | null;

  /** Trend compared to previous scan */
  complianceTrend: ComplianceTrend;

  /** ISO 8601 timestamp of most recent scan or null */
  lastScan: string | null;

  /** ISO 8601 timestamp of most recent status check or null */
  lastCheck: string | null;

  /** ISO 8601 timestamp of next scheduled scan or null */
  nextScan: string | null;

  /** Number of critical severity failures */
  criticalIssues: number;

  /** Number of high severity failures */
  highIssues: number;

  /** Number of medium severity failures */
  mediumIssues: number;

  /** Number of low severity failures */
  lowIssues: number;

  // Per-severity pass/fail breakdown for accurate compliance visualization
  // NIST SP 800-137 Continuous Monitoring granular tracking
  /** Number of passed critical severity rules (CVSS >= 9.0) */
  criticalPassed?: number;

  /** Number of failed critical severity rules (CVSS >= 9.0) */
  criticalFailed?: number;

  /** Number of passed high severity rules (CVSS 7.0-8.9) */
  highPassed?: number;

  /** Number of failed high severity rules (CVSS 7.0-8.9) */
  highFailed?: number;

  /** Number of passed medium severity rules (CVSS 4.0-6.9) */
  mediumPassed?: number;

  /** Number of failed medium severity rules (CVSS 4.0-6.9) */
  mediumFailed?: number;

  /** Number of passed low severity rules (CVSS 0.1-3.9) */
  lowPassed?: number;

  /** Number of failed low severity rules (CVSS 0.1-3.9) */
  lowFailed?: number;

  // Latest Scan Details (optional)
  /** UUID of most recent scan or null */
  latestScanId?: string | null;

  /** Name/description of most recent scan or null */
  latestScanName?: string | null;

  /** Current scan status if scan in progress or null */
  scanStatus?: string | null;

  /** Scan progress percentage (0-100) if scan in progress or null */
  scanProgress?: number | null;

  /** Number of failed rules in latest scan */
  failedRules?: number;

  /** Number of passed rules in latest scan */
  passedRules?: number;

  /** Total number of rules evaluated in latest scan */
  totalRules?: number;

  // Grouping & Organization
  /** Group name this host belongs to */
  group: string;

  /** Group ID (database foreign key) */
  group_id?: number;

  /** Full group name */
  group_name?: string;

  /** Group description */
  group_description?: string;

  /** Group color for UI display (hex color code) */
  group_color?: string;

  /** User tags for categorization and filtering */
  tags: string[];

  /** Owner/responsible party for this host */
  owner: string;

  // SSH/Authentication
  /** SSH port number (default: 22) */
  port?: number;

  /** SSH username for authentication */
  username?: string;

  /** SSH authentication method */
  authMethod?: AuthMethod;

  /** Whether SSH key authentication is configured */
  sshKey: boolean;

  /** SSH public key fingerprint (e.g., "SHA256:abc123...") */
  ssh_key_fingerprint?: string;

  /** SSH key type (e.g., "RSA", "Ed25519", "ECDSA") */
  ssh_key_type?: string;

  /** SSH key bit length (e.g., 2048, 4096) */
  ssh_key_bits?: number;

  /** SSH key comment field */
  ssh_key_comment?: string;

  // SCAP Configuration
  /** SCAP compliance profile ID or null if not configured */
  profile: string | null;

  /** Agent type for scanning (e.g., "agentless", "oscap-ssh") */
  agent: string;

  // Backup & Recovery
  /** ISO 8601 timestamp of most recent backup or null */
  lastBackup: string | null;
}

/**
 * Type guard to check if a value is a valid HostStatus.
 *
 * @param value - Value to check
 * @returns True if value is a valid HostStatus
 *
 * @example
 * if (isHostStatus(status)) {
 *   console.log("Valid status:", status);
 * }
 */
export function isHostStatus(value: unknown): value is HostStatus {
  return (
    typeof value === 'string' &&
    [
      'online',
      'degraded',
      'critical',
      'down',
      'offline',
      'maintenance',
      'scanning',
      'reachable',
      'ping_only',
      'error',
      'unknown',
    ].includes(value)
  );
}

/**
 * Type guard to check if a value is a valid AuthMethod.
 *
 * @param value - Value to check
 * @returns True if value is a valid AuthMethod
 *
 * @example
 * if (isAuthMethod(method)) {
 *   console.log("Valid auth method:", method);
 * }
 */
export function isAuthMethod(value: unknown): value is AuthMethod {
  return (
    typeof value === 'string' &&
    ['password', 'ssh_key', 'none', 'default', 'system_default'].includes(value)
  );
}
