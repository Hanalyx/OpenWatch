/**
 * Security Events Widget
 *
 * Displays security audit information:
 * - Failed logins count (prominent, red if > 0)
 * - Login attempts count
 * - Last 5 security events (condensed)
 * - Expand button to /oview
 *
 * Part of Command Center Dashboard.
 *
 * @module pages/Dashboard/widgets/SecurityEventsWidget
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Skeleton,
  Alert,
  Tooltip,
  Divider,
  useTheme,
  alpha,
} from '@mui/material';
import {
  OpenInFull as OpenInFullIcon,
  Warning as WarningIcon,
  Login as LoginIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  Person as PersonIcon,
  Computer as ComputerIcon,
  Settings as SettingsIcon,
  Scanner as ScannerIcon,
} from '@mui/icons-material';
import {
  useSecurityStats,
  useRecentSecurityEvents,
  type AuditEvent,
} from '../../../hooks/useSecurityStats';

/**
 * Get icon for audit event action
 */
function getActionIcon(action: string): React.ReactNode {
  if (action.includes('LOGIN')) return <LoginIcon fontSize="small" />;
  if (action.includes('SCAN')) return <ScannerIcon fontSize="small" />;
  if (action.includes('USER')) return <PersonIcon fontSize="small" />;
  if (action.includes('HOST')) return <ComputerIcon fontSize="small" />;
  if (action.includes('ADMIN')) return <SettingsIcon fontSize="small" />;
  return <SecurityIcon fontSize="small" />;
}

/**
 * Get severity color for audit event
 */
function getSeverityColor(severity: string): 'error' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'critical':
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
    default:
      return 'info';
  }
}

/**
 * Format timestamp to relative or short time
 */
function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

const SecurityEventsWidget: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const { data: stats, isLoading: statsLoading, error: statsError } = useSecurityStats();
  const {
    data: eventsData,
    isLoading: eventsLoading,
    error: eventsError,
  } = useRecentSecurityEvents(5);

  const handleExpand = () => {
    navigate('/oview');
  };

  // Loading state
  if (statsLoading || eventsLoading) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Skeleton variant="text" width="50%" />
            <Skeleton variant="circular" width={32} height={32} />
          </Box>
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <Skeleton variant="rounded" width={80} height={40} />
            <Skeleton variant="rounded" width={80} height={40} />
          </Box>
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} variant="text" sx={{ my: 1 }} />
          ))}
        </CardContent>
      </Card>
    );
  }

  // Error state
  if (statsError || eventsError) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              <Typography variant="h6">Security Events</Typography>
            </Box>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Alert severity="warning" variant="outlined">
            Unable to load security events
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const events = eventsData?.events || [];
  const failedLogins = stats?.failed_logins || 0;
  const loginAttempts = stats?.login_attempts || 0;

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">Security Events</Typography>
          </Box>
          <Tooltip title="View Full Security Log">
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>

        {/* Stats Row */}
        <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              px: 2,
              py: 1,
              borderRadius: 1,
              bgcolor: failedLogins > 0 ? alpha(theme.palette.error.main, 0.1) : 'action.hover',
            }}
          >
            <WarningIcon fontSize="small" color={failedLogins > 0 ? 'error' : 'disabled'} />
            <Box>
              <Typography
                variant="h6"
                color={failedLogins > 0 ? 'error.main' : 'text.primary'}
                sx={{ lineHeight: 1.2, fontWeight: 'bold' }}
              >
                {failedLogins}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Failed Logins
              </Typography>
            </Box>
          </Box>

          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              px: 2,
              py: 1,
              borderRadius: 1,
              bgcolor: 'action.hover',
            }}
          >
            <LoginIcon fontSize="small" color="info" />
            <Box>
              <Typography variant="h6" sx={{ lineHeight: 1.2, fontWeight: 'bold' }}>
                {loginAttempts}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Login Attempts
              </Typography>
            </Box>
          </Box>
        </Box>

        <Divider sx={{ my: 1.5 }} />

        {/* Recent Events List */}
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
          Recent Events
        </Typography>
        {events.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
            No recent security events
          </Typography>
        ) : (
          <List dense disablePadding>
            {events.map((event: AuditEvent) => (
              <ListItem
                key={event.id}
                disablePadding
                sx={{
                  py: 0.5,
                  '&:hover': { bgcolor: 'action.hover' },
                  borderRadius: 1,
                }}
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  {event.severity === 'error' || event.severity === 'critical' ? (
                    <ErrorIcon fontSize="small" color="error" />
                  ) : event.severity === 'warning' ? (
                    <WarningIcon fontSize="small" color="warning" />
                  ) : (
                    <InfoIcon fontSize="small" color="info" />
                  )}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getActionIcon(event.action)}
                      <Typography variant="body2" noWrap sx={{ maxWidth: 150 }}>
                        {event.action}
                      </Typography>
                      <Chip
                        label={event.severity}
                        size="small"
                        color={getSeverityColor(event.severity)}
                        sx={{
                          height: 18,
                          '& .MuiChip-label': { px: 1, py: 0, fontSize: '0.65rem' },
                        }}
                      />
                    </Box>
                  }
                  secondary={
                    <Typography variant="caption" color="text.secondary">
                      {event.username || 'System'} - {formatTime(event.timestamp)}
                    </Typography>
                  }
                />
              </ListItem>
            ))}
          </List>
        )}
      </CardContent>
    </Card>
  );
};

export default SecurityEventsWidget;
