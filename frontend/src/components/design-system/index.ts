// Core Components
export { default as StatCard } from './StatCard';
export { default as StatusChip } from './StatusChip';
export { default as ComplianceRing } from './ComplianceRing';
export { default as SSHKeyDisplay } from './SSHKeyDisplay';

// Layout Components
export { default as DashboardLayout } from './layouts/DashboardLayout';
export { default as PageTemplate } from './layouts/PageTemplate';

// Pattern Components
export { default as FilterToolbar } from './patterns/FilterToolbar';
export { default as DataGrid } from './patterns/DataGrid';
export { default as EmptyState } from './patterns/EmptyState';

// Re-export types for external use
export type { StatusType } from './StatusChip';
export type { ViewMode, GroupBy } from './patterns/FilterToolbar';
export type { DataGridItem, DataGridGroup } from './patterns/DataGrid';
export type { EmptyStateType } from './patterns/EmptyState';
export type { SSHKeyInfo, SSHKeyDisplayProps } from './SSHKeyDisplay';

// Design tokens and theme configuration
export const designTokens = {
  colors: {
    primary: '#1976d2',
    success: '#4caf50',
    warning: '#ff9800',
    error: '#f44336',
    info: '#2196f3',
    severity: {
      critical: '#f44336',
      high: '#ff5722',
      medium: '#ff9800',
      low: '#ffc107',
    },
    status: {
      online: '#4caf50',
      offline: '#f44336',
      maintenance: '#ff9800',
      scanning: '#2196f3',
      unknown: '#9e9e9e',
    },
  },
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
    xxl: 48,
    xxxl: 64,
  },
  borderRadius: {
    sm: 4,
    md: 8,
    lg: 12,
    xl: 16,
    full: '50%',
  },
  shadows: {
    card: '0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24)',
    elevated: '0 3px 6px rgba(0,0,0,0.16), 0 3px 6px rgba(0,0,0,0.23)',
    floating: '0 10px 20px rgba(0,0,0,0.19), 0 6px 6px rgba(0,0,0,0.23)',
  },
  transitions: {
    fast: '150ms ease-out',
    normal: '300ms ease-out',
    slow: '450ms ease-out',
  },
} as const;

// Common layout breakpoints
export const layoutBreakpoints = {
  mobile: 600,
  tablet: 960,
  desktop: 1280,
  wide: 1920,
} as const;
