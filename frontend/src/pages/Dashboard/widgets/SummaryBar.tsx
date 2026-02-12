/**
 * Summary Bar Widget
 *
 * Displays aggregated key metrics from all data sources in one glance:
 * - Compliance % (from OWCA)
 * - Online Hosts (from host monitoring)
 * - Failed Logins (from security audit)
 * - Total Events (from security audit)
 * - Active Alerts (from alerts)
 * - Avg Response (from host monitoring)
 *
 * Part of Command Center Dashboard.
 *
 * @module pages/Dashboard/widgets/SummaryBar
 */

import React from 'react';
import { Box, Paper, Typography, Skeleton, useTheme, alpha, Tooltip } from '@mui/material';
import {
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Warning as WarningIcon,
  Event as EventIcon,
  NotificationsActive as AlertsIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';

interface SummaryMetric {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
  tooltip?: string;
}

interface SummaryBarProps {
  compliancePercent: number | null;
  onlineHosts: number;
  totalHosts: number;
  failedLogins: number;
  totalEvents: number;
  activeAlerts: number;
  avgResponseMs: number | null;
  isLoading?: boolean;
}

const SummaryBar: React.FC<SummaryBarProps> = ({
  compliancePercent,
  onlineHosts,
  totalHosts,
  failedLogins,
  totalEvents,
  activeAlerts,
  avgResponseMs,
  isLoading = false,
}) => {
  const theme = useTheme();

  // Format compliance display
  const complianceDisplay = compliancePercent !== null ? `${Math.round(compliancePercent)}%` : '-';

  // Format response time
  const responseDisplay =
    avgResponseMs !== null
      ? avgResponseMs > 1000
        ? `${(avgResponseMs / 1000).toFixed(1)}s`
        : `${avgResponseMs}ms`
      : '-';

  const metrics: SummaryMetric[] = [
    {
      label: 'Compliant',
      value: complianceDisplay,
      icon: <SecurityIcon />,
      color: theme.palette.primary.main,
      tooltip: 'Average compliance score across all hosts',
    },
    {
      label: 'Online',
      value: `${onlineHosts}/${totalHosts}`,
      icon: <ComputerIcon />,
      color: theme.palette.success.main,
      tooltip: 'Number of hosts currently online',
    },
    {
      label: 'Failed Logins',
      value: failedLogins,
      icon: <WarningIcon />,
      color: failedLogins > 0 ? theme.palette.error.main : theme.palette.text.secondary,
      tooltip: 'Failed login attempts in audit log',
    },
    {
      label: 'Events',
      value: totalEvents.toLocaleString(),
      icon: <EventIcon />,
      color: theme.palette.info.main,
      tooltip: 'Total security events in audit log',
    },
    {
      label: 'Alerts',
      value: activeAlerts,
      icon: <AlertsIcon />,
      color: activeAlerts > 0 ? theme.palette.warning.main : theme.palette.text.secondary,
      tooltip: 'Active compliance alerts',
    },
    {
      label: 'Avg Response',
      value: responseDisplay,
      icon: <SpeedIcon />,
      color: theme.palette.secondary.main,
      tooltip: 'Average host response time',
    },
  ];

  if (isLoading) {
    return (
      <Paper sx={{ p: 2, mb: 3 }}>
        <Box
          sx={{
            display: 'flex',
            gap: 2,
            flexWrap: 'wrap',
            justifyContent: 'space-between',
          }}
        >
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <Box key={i} sx={{ minWidth: 100, textAlign: 'center' }}>
              <Skeleton variant="text" width={60} sx={{ mx: 'auto' }} />
              <Skeleton variant="text" width={80} sx={{ mx: 'auto' }} />
            </Box>
          ))}
        </Box>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 2, mb: 3 }}>
      <Box
        sx={{
          display: 'flex',
          gap: { xs: 2, md: 3 },
          flexWrap: 'wrap',
          justifyContent: 'space-between',
        }}
      >
        {metrics.map((metric) => (
          <Tooltip key={metric.label} title={metric.tooltip || ''} arrow>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1.5,
                minWidth: { xs: '45%', sm: 'auto' },
                flex: { xs: '1 1 45%', sm: '0 1 auto' },
                p: 1,
                borderRadius: 1,
                transition: 'background-color 0.2s',
                cursor: 'default',
                '&:hover': {
                  bgcolor: alpha(metric.color, 0.08),
                },
              }}
            >
              <Box
                sx={{
                  p: 1,
                  borderRadius: 1,
                  bgcolor: alpha(metric.color, 0.1),
                  color: metric.color,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {metric.icon}
              </Box>
              <Box>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 'bold',
                    color: metric.color,
                    lineHeight: 1.2,
                  }}
                >
                  {metric.value}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {metric.label}
                </Typography>
              </Box>
            </Box>
          </Tooltip>
        ))}
      </Box>
    </Paper>
  );
};

export default SummaryBar;
