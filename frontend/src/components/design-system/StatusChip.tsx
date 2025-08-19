import React from 'react';
import {
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  CheckCircle,
  Error,
  Warning,
  Info,
  Schedule,
  Build,
  HelpOutline,
  Security,
  BugReport,
  Notifications,
  NetworkCheck,
} from '@mui/icons-material';

export type StatusType = 
  | 'online' | 'offline' | 'maintenance' | 'scanning' | 'pending' | 'reachable' | 'ping_only'
  | 'success' | 'error' | 'warning' | 'info'
  | 'critical' | 'high' | 'medium' | 'low'
  | 'compliant' | 'non-compliant' | 'unknown';

interface StatusChipProps {
  status: StatusType;
  label?: string;
  size?: 'small' | 'medium';
  variant?: 'filled' | 'outlined';
  showIcon?: boolean;
  onClick?: () => void;
}

const StatusChip: React.FC<StatusChipProps> = ({
  status,
  label,
  size = 'small',
  variant = 'filled',
  showIcon = true,
  onClick,
}) => {
  const theme = useTheme();

  const getStatusConfig = (status: StatusType) => {
    // Gmail-inspired compliance colors for SecureOps
    const configs: Record<StatusType, {
      color: string;
      backgroundColor: string;
      icon: React.ReactNode;
      defaultLabel: string;
    }> = {
      // System Status (Google-inspired compliance colors)
      online: {
        color: theme.palette.success.main, // Google Green - Everything OK
        backgroundColor: alpha(theme.palette.success.main, 0.12),
        icon: <CheckCircle />,
        defaultLabel: 'Online',
      },
      offline: {
        color: theme.palette.error.main, // Google Red - Critical alert
        backgroundColor: alpha(theme.palette.error.main, 0.12),
        icon: <Error />,
        defaultLabel: 'Offline',
      },
      maintenance: {
        color: theme.palette.warning.main, // Google Yellow - Needs attention
        backgroundColor: alpha(theme.palette.warning.main, 0.12),
        icon: <Build />,
        defaultLabel: 'Maintenance',
      },
      scanning: {
        color: theme.palette.info.main, // Google Blue - Informational
        backgroundColor: alpha(theme.palette.info.main, 0.12),
        icon: <Security />,
        defaultLabel: 'Scanning',
      },
      pending: {
        color: theme.palette.warning.main, // Google Yellow - Attention needed
        backgroundColor: alpha(theme.palette.warning.main, 0.12),
        icon: <Schedule />,
        defaultLabel: 'Pending',
      },
      reachable: {
        color: theme.palette.warning.main, // Google Yellow for partial connectivity
        backgroundColor: alpha(theme.palette.warning.main, 0.12),
        icon: <Warning />,
        defaultLabel: 'Reachable',
      },
      ping_only: {
        color: theme.palette.secondary.main, // Professional gray for limited status
        backgroundColor: alpha(theme.palette.secondary.main, 0.12),
        icon: <NetworkCheck />,
        defaultLabel: 'Ping Only',
      },

      // General Status (using new compliance palette)
      success: {
        color: theme.palette.success.main, // Google Green - Success state
        backgroundColor: alpha(theme.palette.success.main, 0.12),
        icon: <CheckCircle />,
        defaultLabel: 'Success',
      },
      error: {
        color: theme.palette.error.main, // Google Red - Error state
        backgroundColor: alpha(theme.palette.error.main, 0.12),
        icon: <Error />,
        defaultLabel: 'Error',
      },
      warning: {
        color: theme.palette.warning.main, // Google Yellow - Warning state
        backgroundColor: alpha(theme.palette.warning.main, 0.12),
        icon: <Warning />,
        defaultLabel: 'Warning',
      },
      info: {
        color: theme.palette.info.main, // Google Blue - Info state
        backgroundColor: alpha(theme.palette.info.main, 0.12),
        icon: <Info />,
        defaultLabel: 'Info',
      },

      // Severity Levels (compliance-focused colors)
      critical: {
        color: theme.palette.error.main, // Google Red - Critical alerts
        backgroundColor: alpha(theme.palette.error.main, 0.12),
        icon: <Error />,
        defaultLabel: 'Critical',
      },
      high: {
        color: theme.palette.error.light, // Light red for high severity
        backgroundColor: alpha(theme.palette.error.light, 0.12),
        icon: <Warning />,
        defaultLabel: 'High',
      },
      medium: {
        color: theme.palette.warning.main, // Google Yellow for medium
        backgroundColor: alpha(theme.palette.warning.main, 0.12),
        icon: <Info />,
        defaultLabel: 'Medium',
      },
      low: {
        color: theme.palette.warning.light, // Light yellow for low severity
        backgroundColor: alpha(theme.palette.warning.light, 0.12),
        icon: <Notifications />,
        defaultLabel: 'Low',
      },

      // Compliance Status (clear compliance indicators)
      compliant: {
        color: theme.palette.success.main, // Google Green - Compliant/Secure
        backgroundColor: alpha(theme.palette.success.main, 0.12),
        icon: <CheckCircle />,
        defaultLabel: 'Compliant',
      },
      'non-compliant': {
        color: theme.palette.error.main, // Google Red - Non-compliant/Security risk
        backgroundColor: alpha(theme.palette.error.main, 0.12),
        icon: <BugReport />,
        defaultLabel: 'Non-Compliant',
      },
      unknown: {
        color: theme.palette.secondary.main, // Professional gray for unknown
        backgroundColor: alpha(theme.palette.secondary.main, 0.12),
        icon: <HelpOutline />,
        defaultLabel: 'Unknown',
      },
    };

    return configs[status] || configs.unknown;
  };

  const config = getStatusConfig(status);
  const displayLabel = label || config.defaultLabel;

  const chipStyles = {
    color: config.color,
    backgroundColor: variant === 'filled' ? config.backgroundColor : 'transparent',
    border: variant === 'outlined' ? `1px solid ${config.color}` : 'none',
    borderRadius: '16px', // Gmail-style rounded chips
    fontSize: '0.75rem',
    fontWeight: 500,
    height: size === 'small' ? '24px' : '32px',
    '& .MuiChip-icon': {
      color: config.color,
      fontSize: size === 'small' ? '16px' : '18px',
    },
    '& .MuiChip-label': {
      paddingLeft: size === 'small' ? '8px' : '12px',
      paddingRight: size === 'small' ? '8px' : '12px',
      fontSize: '0.75rem',
      fontWeight: 500,
    },
    '&:hover': onClick ? {
      backgroundColor: alpha(config.color, variant === 'filled' ? 0.2 : 0.08),
      transform: 'translateY(-1px)',
      boxShadow: theme.palette.mode === 'light' 
        ? '0 2px 4px 0 rgba(60, 64, 67, .3), 0 1px 2px 0 rgba(60, 64, 67, .15)'
        : '0 2px 4px 0 rgba(0, 0, 0, .3), 0 1px 2px 0 rgba(0, 0, 0, .15)',
    } : undefined,
    transition: 'all 0.2s cubic-bezier(0.4, 0.0, 0.2, 1)', // Gmail-style smooth transitions
  };

  return (
    <Chip
      icon={showIcon ? (config.icon as React.ReactElement) : undefined}
      label={displayLabel}
      size={size}
      variant={variant}
      onClick={onClick}
      sx={chipStyles}
    />
  );
};

export default StatusChip;