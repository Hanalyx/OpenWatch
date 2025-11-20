/**
 * Host Status Utilities
 *
 * Utility functions for host status visualization including icons, colors,
 * and status labels. These functions provide consistent status representation
 * across the OpenWatch frontend.
 *
 * Used by:
 * - Hosts page (host cards, list view)
 * - Host detail page (status display)
 * - Dashboard (host status summary)
 * - Monitoring components
 *
 * @module utils/hostStatus
 */

import React from 'react';
import {
  CheckCircle,
  HighlightOff,
  Build,
  Scanner,
  Warning,
  NetworkCheck,
  Error as ErrorIcon,
  Info,
} from '@mui/icons-material';
import type { Theme } from '@mui/material/styles';
import type { HostStatus } from '../types/host';
import { COMPLIANCE_THRESHOLDS } from '../constants/compliance';

/**
 * Get Material-UI icon component for host status.
 *
 * Returns the appropriate icon component based on host connectivity status.
 * Icons provide visual indication of host health at a glance.
 *
 * Status Icon Mapping:
 * - online: CheckCircle (green) - Fully operational
 * - offline: HighlightOff (red) - Completely unreachable
 * - maintenance: Build (yellow) - Scheduled maintenance
 * - scanning: Scanner (blue) - SCAP scan in progress
 * - reachable: Warning (orange) - Ping works, SSH failed
 * - ping_only: NetworkCheck (gray) - Ping works, port 22 closed
 * - error: ErrorIcon (red) - Status check error
 * - default: Info (gray) - Unknown status
 *
 * @param status - Host status enum value
 * @returns React element containing the appropriate MUI icon
 *
 * @example
 * import { getStatusIcon } from '@/utils/hostStatus';
 *
 * function HostCard({ host }) {
 *   const icon = getStatusIcon(host.status);
 *   return <Box>{icon} {host.hostname}</Box>;
 * }
 */
export function getStatusIcon(status: HostStatus): React.ReactElement {
  switch (status) {
    case 'online':
      return <CheckCircle color="success" />;
    case 'offline':
      return <HighlightOff color="error" />;
    case 'maintenance':
      return <Build color="warning" />;
    case 'scanning':
      return <Scanner color="info" />;
    case 'reachable':
      // Orange warning - host responds but SSH auth failed
      return <Warning sx={{ color: '#ff9800' }} />;
    case 'ping_only':
      // Gray network icon - host responds to ping but SSH port closed
      return <NetworkCheck sx={{ color: '#607d8b' }} />;
    case 'error':
      return <ErrorIcon color="error" />;
    case 'degraded':
    case 'critical':
    case 'down':
    case 'unknown':
    default:
      return <Info />;
  }
}

/**
 * Get theme color for compliance score.
 *
 * Returns the appropriate Material-UI theme palette color based on
 * compliance score thresholds defined in CLAUDE.md.
 *
 * Color Thresholds (per CLAUDE.md):
 * - 95%+: success.main (green) - Compliant
 * - 75-94%: warning.main (yellow) - Near Compliant
 * - <75%: error.main (red) - Non-Compliant
 * - null: grey[500] (gray) - Not Scanned
 *
 * @param score - Compliance score (0-100) or null if not scanned
 * @param theme - Material-UI theme object for color palette
 * @returns Theme color string
 *
 * @example
 * import { useTheme } from '@mui/material/styles';
 * import { getComplianceScoreColor } from '@/utils/hostStatus';
 *
 * function ComplianceBadge({ score }) {
 *   const theme = useTheme();
 *   const color = getComplianceScoreColor(score, theme);
 *   return <Chip label={`${score}%`} sx={{ backgroundColor: color }} />;
 * }
 */
export function getComplianceScoreColor(score: number | null, theme: Theme): string {
  // Gray for hosts that have never been scanned
  if (score === null) {
    return theme.palette.grey[500];
  }

  // Green for compliant hosts (95%+ per CLAUDE.md)
  if (score >= COMPLIANCE_THRESHOLDS.COMPLIANT) {
    return theme.palette.success.main;
  }

  // Yellow for near-compliant hosts (75-94% per CLAUDE.md)
  if (score >= COMPLIANCE_THRESHOLDS.NEAR_COMPLIANT) {
    return theme.palette.warning.main;
  }

  // Red for non-compliant hosts (<75% per CLAUDE.md)
  return theme.palette.error.main;
}

/**
 * Get human-readable status label.
 *
 * Converts HostStatus enum value to user-friendly display text.
 *
 * @param status - Host status enum value
 * @returns Human-readable status label
 *
 * @example
 * getStatusLabel('online'); // "Online"
 * getStatusLabel('ping_only'); // "Ping Only"
 * getStatusLabel('reachable'); // "SSH Auth Failed"
 */
export function getStatusLabel(status: HostStatus): string {
  const labels: Record<HostStatus, string> = {
    online: 'Online',
    offline: 'Offline',
    maintenance: 'Maintenance',
    scanning: 'Scanning',
    reachable: 'SSH Auth Failed',
    ping_only: 'Ping Only',
    error: 'Error',
    degraded: 'Degraded',
    critical: 'Critical',
    down: 'Down',
    unknown: 'Unknown',
  };

  return labels[status] || 'Unknown';
}

/**
 * Get status color for non-compliance contexts.
 *
 * Returns color for host operational status (not compliance score).
 * Used for host cards, badges, and status indicators.
 *
 * @param status - Host status enum value
 * @param theme - Material-UI theme object for color palette
 * @returns Theme color string
 *
 * @example
 * import { useTheme } from '@mui/material/styles';
 * import { getStatusColor } from '@/utils/hostStatus';
 *
 * function StatusBadge({ status }) {
 *   const theme = useTheme();
 *   const color = getStatusColor(status, theme);
 *   return <Box sx={{ backgroundColor: color }}>...</Box>;
 * }
 */
export function getStatusColor(status: HostStatus, theme: Theme): string {
  switch (status) {
    case 'online':
      return theme.palette.success.main; // Green
    case 'offline':
    case 'error':
    case 'critical':
      return theme.palette.error.main; // Red
    case 'maintenance':
    case 'reachable':
    case 'degraded':
      return theme.palette.warning.main; // Yellow/Orange
    case 'scanning':
      return theme.palette.info.main; // Blue
    case 'ping_only':
    case 'down':
    case 'unknown':
    default:
      return theme.palette.grey[500]; // Gray
  }
}

/**
 * Determine if host status is considered "healthy".
 *
 * A host is healthy if it's online or scanning (actively running a scan).
 * All other statuses indicate some level of connectivity or operational issue.
 *
 * @param status - Host status enum value
 * @returns True if host is healthy, false otherwise
 *
 * @example
 * if (isHealthyStatus(host.status)) {
 *   console.log('Host is ready for compliance scans');
 * }
 */
export function isHealthyStatus(status: HostStatus): boolean {
  return status === 'online' || status === 'scanning';
}

/**
 * Determine if host status indicates a connectivity problem.
 *
 * Connectivity problems include offline, ping-only, reachable (SSH failed),
 * and error states. These statuses prevent successful SCAP scans.
 *
 * @param status - Host status enum value
 * @returns True if host has connectivity issues, false otherwise
 *
 * @example
 * if (hasConnectivityIssue(host.status)) {
 *   showTroubleshootingDialog();
 * }
 */
export function hasConnectivityIssue(status: HostStatus): boolean {
  return ['offline', 'ping_only', 'reachable', 'error'].includes(status);
}

/**
 * Get compliance status label based on score.
 *
 * Returns human-readable compliance status matching the thresholds
 * defined in constants/compliance.ts.
 *
 * @param score - Compliance score (0-100) or null if not scanned
 * @returns Compliance status label
 *
 * @example
 * getComplianceLabel(97); // "Compliant"
 * getComplianceLabel(82); // "Near Compliant"
 * getComplianceLabel(65); // "Non-Compliant"
 * getComplianceLabel(null); // "Not Scanned"
 */
export function getComplianceLabel(score: number | null): string {
  if (score === null) {
    return 'Not Scanned';
  }

  if (score >= COMPLIANCE_THRESHOLDS.COMPLIANT) {
    return 'Compliant';
  }

  if (score >= COMPLIANCE_THRESHOLDS.NEAR_COMPLIANT) {
    return 'Near Compliant';
  }

  return 'Non-Compliant';
}
