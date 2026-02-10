/**
 * System Health Card
 *
 * Displays OS version, kernel, uptime, and basic resource info
 * from server intelligence collection.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/SystemHealthCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';
import type { SystemInfo } from '../../../../types/hostDetail';

interface SystemHealthCardProps {
  systemInfo: SystemInfo | null | undefined;
  isLoading?: boolean;
}

/**
 * Format uptime in human-readable format
 */
function formatUptime(seconds: number | null): string {
  if (!seconds) return 'Unknown';

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);

  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h`;
  }
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${minutes}m`;
}

/**
 * Format memory in GB
 */
function formatMemory(mb: number | null): string {
  if (!mb) return 'Unknown';
  return `${(mb / 1024).toFixed(1)} GB`;
}

const SystemHealthCard: React.FC<SystemHealthCardProps> = ({ systemInfo, isLoading }) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="50%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="80%" height={20} />
          <Skeleton variant="text" width="70%" height={20} />
          <Skeleton variant="text" width="60%" height={20} />
          <Skeleton variant="text" width="50%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const hasData = systemInfo !== null && systemInfo !== undefined;

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          System Health
        </Typography>

        {hasData ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
            <Typography variant="body2">
              <Typography component="span" color="text.secondary">
                OS:{' '}
              </Typography>
              {systemInfo.osPrettyName || systemInfo.osName || 'Unknown'}
            </Typography>

            <Typography variant="body2">
              <Typography component="span" color="text.secondary">
                Kernel:{' '}
              </Typography>
              {systemInfo.kernelRelease || 'Unknown'}
            </Typography>

            <Typography variant="body2">
              <Typography component="span" color="text.secondary">
                Uptime:{' '}
              </Typography>
              {formatUptime(systemInfo.uptimeSeconds)}
            </Typography>

            <Typography variant="body2">
              <Typography component="span" color="text.secondary">
                Memory:{' '}
              </Typography>
              {formatMemory(systemInfo.memoryTotalMb)}
            </Typography>

            {systemInfo.cpuCores && (
              <Typography variant="body2">
                <Typography component="span" color="text.secondary">
                  CPU:{' '}
                </Typography>
                {systemInfo.cpuCores} cores
              </Typography>
            )}
          </Box>
        ) : (
          <Typography variant="body2" color="text.secondary">
            System information not yet collected. Data will be available after the next scan.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default SystemHealthCard;
