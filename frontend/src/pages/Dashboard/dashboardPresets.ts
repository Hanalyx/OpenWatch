/**
 * Dashboard Role Presets
 *
 * Defines the default widget layout for each of the 6 OpenWatch user roles.
 * Presets control which widgets are shown, their order, and the column layout.
 *
 * Spec: specs/frontend/role-dashboards.spec.yaml (AC-3 through AC-9, AC-12, AC-14, AC-15)
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Customization tier determines what the user can change */
export type CustomizationTier = 'full' | 'limited' | 'none';

/** Time range default for compliance trend widget */
export type TrendRange = '7d' | '30d' | '90d';

export interface RolePreset {
  /** Role this preset applies to */
  role: string;
  /** Dashboard title shown in the header */
  title: string;
  /** Dashboard subtitle / description */
  subtitle: string;
  /** Number of grid columns for the main content area */
  columns: 1 | 2 | 3;
  /** Customization tier: full (drag/drop), limited (show/hide), none (fixed) */
  customization: CustomizationTier;
  /** Default time range for compliance trend widget */
  defaultTrendRange: TrendRange;
  /** Ordered list of widget IDs for the main (left) column */
  mainWidgets: string[];
  /** Ordered list of widget IDs for the sidebar (right) column */
  sidebarWidgets: string[];
  /** Full-width widgets rendered above the column grid */
  topWidgets: string[];
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

const SUPER_ADMIN_PRESET: RolePreset = {
  role: 'super_admin',
  title: 'Command Center',
  subtitle: 'Unified security, compliance, and infrastructure visibility',
  columns: 3,
  customization: 'full',
  defaultTrendRange: '30d',
  topWidgets: ['summary-bar', 'smart-alert-bar', 'quick-actions'],
  mainWidgets: ['security-events', 'fleet-health', 'priority-hosts', 'compliance-trend'],
  sidebarWidgets: ['scheduler-status', 'posture', 'drift-alerts', 'saved-queries', 'activity-feed'],
};

const SECURITY_ADMIN_PRESET: RolePreset = {
  role: 'security_admin',
  title: 'Security Operations',
  subtitle: 'Infrastructure security and compliance management',
  columns: 2,
  customization: 'full',
  defaultTrendRange: '30d',
  topWidgets: ['summary-bar', 'smart-alert-bar', 'quick-actions'],
  mainWidgets: ['priority-hosts', 'fleet-health', 'compliance-trend', 'security-events'],
  sidebarWidgets: ['drift-alerts', 'scheduler-status', 'activity-feed'],
};

const SECURITY_ANALYST_PRESET: RolePreset = {
  role: 'security_analyst',
  title: 'Security Operations',
  subtitle: 'Scan operations and compliance monitoring',
  columns: 2,
  customization: 'limited',
  defaultTrendRange: '7d',
  topWidgets: ['summary-bar', 'quick-actions'],
  mainWidgets: ['fleet-health', 'priority-hosts', 'compliance-trend'],
  sidebarWidgets: ['activity-feed'],
};

const COMPLIANCE_OFFICER_PRESET: RolePreset = {
  role: 'compliance_officer',
  title: 'Compliance Dashboard',
  subtitle: 'Compliance posture, reporting, and exception management',
  columns: 2,
  customization: 'limited',
  defaultTrendRange: '90d',
  topWidgets: ['summary-bar'],
  mainWidgets: ['compliance-trend', 'priority-hosts'],
  sidebarWidgets: ['posture', 'saved-queries', 'drift-alerts', 'activity-feed'],
};

const AUDITOR_PRESET: RolePreset = {
  role: 'auditor',
  title: 'Compliance Dashboard',
  subtitle: 'Compliance evidence and audit access',
  columns: 1,
  customization: 'none',
  defaultTrendRange: '90d',
  topWidgets: ['summary-bar'],
  mainWidgets: [
    'compliance-trend',
    'posture',
    'saved-queries',
    'fleet-health',
    'drift-alerts',
    'activity-feed',
  ],
  sidebarWidgets: [],
};

const GUEST_PRESET: RolePreset = {
  role: 'guest',
  title: 'Dashboard',
  subtitle: 'Compliance overview',
  columns: 1,
  customization: 'none',
  defaultTrendRange: '30d',
  topWidgets: ['summary-bar'],
  mainWidgets: ['fleet-health', 'compliance-trend'],
  sidebarWidgets: [],
};

// ---------------------------------------------------------------------------
// Preset index
// ---------------------------------------------------------------------------

export const DASHBOARD_PRESETS: Record<string, RolePreset> = {
  super_admin: SUPER_ADMIN_PRESET,
  security_admin: SECURITY_ADMIN_PRESET,
  security_analyst: SECURITY_ANALYST_PRESET,
  compliance_officer: COMPLIANCE_OFFICER_PRESET,
  auditor: AUDITOR_PRESET,
  guest: GUEST_PRESET,
};

/**
 * Get the dashboard preset for a role, falling back to guest if unknown.
 */
export function getPresetForRole(role: string): RolePreset {
  return DASHBOARD_PRESETS[role] ?? DASHBOARD_PRESETS['guest'];
}
