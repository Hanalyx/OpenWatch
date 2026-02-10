/**
 * Scheduler Status Widget
 *
 * Displays the status of the adaptive compliance scheduler including:
 * - Enabled/paused status
 * - Host counts by compliance state
 * - Upcoming scheduled scans
 *
 * Part of OpenWatch OS Transformation - Dashboard Updates.
 *
 * @module pages/Dashboard/widgets/SchedulerStatusWidget
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  List,
  ListItem,
  ListItemText,
  Skeleton,
  Alert,
  Divider,
} from '@mui/material';
import {
  Schedule as ScheduleIcon,
  PlayArrow as PlayArrowIcon,
  Pause as PauseIcon,
} from '@mui/icons-material';
import { useSchedulerStatus } from '../../../hooks/useHostDetail';

/**
 * Format relative time for next scan
 */
function formatTimeUntil(nextScan: string): string {
  const next = new Date(nextScan);
  const now = new Date();
  const diffMs = next.getTime() - now.getTime();

  if (diffMs < 0) return 'Due now';

  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `in ${diffMins}m`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `in ${diffHours}h`;

  const diffDays = Math.floor(diffHours / 24);
  return `in ${diffDays}d`;
}

/**
 * Get color for compliance state
 */
function getStateColor(state: string): 'success' | 'warning' | 'error' | 'info' | 'default' {
  switch (state) {
    case 'compliant':
      return 'success';
    case 'mostly_compliant':
      return 'success';
    case 'partial':
      return 'warning';
    case 'low':
      return 'warning';
    case 'critical':
      return 'error';
    case 'unknown':
      return 'default';
    default:
      return 'default';
  }
}

const SchedulerStatusWidget: React.FC = () => {
  const navigate = useNavigate();
  const { data: status, isLoading, error } = useSchedulerStatus();

  if (isLoading) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <ScheduleIcon color="primary" />
            <Skeleton variant="text" width="60%" />
          </Box>
          <Skeleton variant="text" width="40%" />
          <Skeleton variant="text" width="80%" />
          <Skeleton variant="text" width="70%" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <ScheduleIcon color="primary" />
            <Typography variant="h6">Compliance Scheduler</Typography>
          </Box>
          <Alert severity="warning" variant="outlined">
            Unable to load scheduler status
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!status) {
    return null;
  }

  const upcomingScans = status.nextScheduledScans?.slice(0, 3) || [];

  return (
    <Card>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ScheduleIcon color="primary" />
            <Typography variant="h6">Compliance Scheduler</Typography>
          </Box>
          <Chip
            size="small"
            icon={status.enabled ? <PlayArrowIcon /> : <PauseIcon />}
            label={status.enabled ? 'Running' : 'Paused'}
            color={status.enabled ? 'success' : 'warning'}
          />
        </Box>

        {/* Host Counts */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 1 }}>
            <Typography variant="body2">
              <Typography component="span" fontWeight="medium">
                {status.totalHosts}
              </Typography>
              {' hosts total'}
            </Typography>
            <Typography variant="body2">
              <Typography component="span" color="primary.main" fontWeight="medium">
                {status.hostsDue}
              </Typography>
              {' due for scan'}
            </Typography>
            {status.hostsInMaintenance > 0 && (
              <Typography variant="body2">
                <Typography component="span" color="warning.main" fontWeight="medium">
                  {status.hostsInMaintenance}
                </Typography>
                {' in maintenance'}
              </Typography>
            )}
          </Box>

          {/* Compliance State Distribution */}
          {status.byComplianceState && Object.keys(status.byComplianceState).length > 0 && (
            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
              {Object.entries(status.byComplianceState).map(([state, count]) => (
                <Chip
                  key={state}
                  size="small"
                  label={`${state.replace('_', ' ')}: ${count}`}
                  color={getStateColor(state)}
                  variant="outlined"
                />
              ))}
            </Box>
          )}
        </Box>

        {/* Upcoming Scans */}
        {upcomingScans.length > 0 && (
          <>
            <Divider sx={{ my: 1.5 }} />
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Next Scheduled Scans
            </Typography>
            <List dense disablePadding>
              {upcomingScans.map((scan) => (
                <ListItem
                  key={scan.hostId}
                  disablePadding
                  sx={{
                    py: 0.5,
                    cursor: 'pointer',
                    '&:hover': { bgcolor: 'action.hover' },
                    borderRadius: 1,
                  }}
                  onClick={() => navigate(`/hosts/${scan.hostId}`)}
                >
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2">{scan.hostname}</Typography>
                        <Chip
                          size="small"
                          label={scan.complianceState.replace('_', ' ')}
                          color={getStateColor(scan.complianceState)}
                          sx={{
                            height: 18,
                            '& .MuiChip-label': { px: 1, py: 0, fontSize: '0.7rem' },
                          }}
                        />
                      </Box>
                    }
                    secondary={formatTimeUntil(scan.nextScheduledScan)}
                    secondaryTypographyProps={{ variant: 'caption' }}
                  />
                </ListItem>
              ))}
            </List>
          </>
        )}

        {upcomingScans.length === 0 && status.enabled && (
          <Typography variant="body2" color="text.secondary">
            No scans scheduled at this time
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default SchedulerStatusWidget;
