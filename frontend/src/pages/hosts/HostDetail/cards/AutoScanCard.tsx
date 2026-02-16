/**
 * Auto-Scan Status Card
 *
 * Displays auto-scan enabled/paused status, last scan time,
 * and next scheduled scan from the compliance scheduler.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/AutoScanCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';
import type { HostSchedule } from '../../../../types/hostDetail';

interface AutoScanCardProps {
  schedule: HostSchedule | null | undefined;
  isLoading?: boolean;
}

/**
 * Format relative time for next scan
 */
function formatNextScan(nextScan: string | null): string {
  if (!nextScan) return 'Not scheduled';

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
 * Format last scan time
 */
function formatLastScan(lastScan: string | null): string {
  if (!lastScan) return 'Never';

  const date = new Date(lastScan);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}

const AutoScanCard: React.FC<AutoScanCardProps> = ({ schedule, isLoading }) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="40%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="60%" height={32} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="80%" height={20} />
          <Skeleton variant="text" width="70%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const hasData = schedule !== null && schedule !== undefined;
  const isEnabled = hasData && !schedule.maintenanceMode;

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Auto-Scan
        </Typography>

        {hasData ? (
          <>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: isEnabled ? 'success.main' : 'warning.main',
                }}
              />
              <Typography variant="h6" fontWeight="medium">
                {isEnabled ? 'Enabled' : 'Maintenance Mode'}
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              <Typography variant="body2">
                <Typography component="span" color="text.secondary">
                  Last scan:{' '}
                </Typography>
                {formatLastScan(schedule.lastScanCompleted)}
              </Typography>

              <Typography variant="body2">
                <Typography component="span" color="text.secondary">
                  Next scan:{' '}
                </Typography>
                {isEnabled ? formatNextScan(schedule.nextScheduledScan) : 'Paused'}
              </Typography>

              <Typography variant="body2">
                <Typography component="span" color="text.secondary">
                  Interval:{' '}
                </Typography>
                {schedule.currentIntervalMinutes}m
              </Typography>
            </Box>

            {schedule.maintenanceUntil && (
              <Typography variant="caption" color="warning.main" display="block" sx={{ mt: 1 }}>
                Maintenance until: {new Date(schedule.maintenanceUntil).toLocaleString()}
              </Typography>
            )}

            {schedule.consecutiveScanFailures > 0 && (
              <Typography variant="caption" color="error.main" display="block" sx={{ mt: 1 }}>
                {schedule.consecutiveScanFailures} consecutive failures
              </Typography>
            )}
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            Auto-scan not configured for this host.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default AutoScanCard;
