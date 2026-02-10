/**
 * Alerts Card
 *
 * Displays active alert counts and most recent alert
 * for compliance monitoring.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/AlertsCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';

interface AlertsCardProps {
  activeCount?: number;
  criticalCount?: number;
  highCount?: number;
  recentAlertMessage?: string;
  recentAlertTime?: string;
  isLoading?: boolean;
}

/**
 * Get color for alert severity display
 */
function getAlertColor(criticalCount: number, highCount: number): string {
  if (criticalCount > 0) return 'error.main';
  if (highCount > 0) return 'warning.main';
  return 'text.primary';
}

const AlertsCard: React.FC<AlertsCardProps> = ({
  activeCount = 0,
  criticalCount = 0,
  highCount = 0,
  recentAlertMessage,
  recentAlertTime,
  isLoading,
}) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="40%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="30%" height={32} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="80%" height={20} />
          <Skeleton variant="text" width="60%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const hasAlerts = activeCount > 0;

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Alerts
        </Typography>

        <Typography
          variant="h4"
          fontWeight="bold"
          color={getAlertColor(criticalCount, highCount)}
          sx={{ mb: 1 }}
        >
          {activeCount}
        </Typography>

        {hasAlerts ? (
          <>
            <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
              {criticalCount > 0 && (
                <Typography variant="body2" color="error.main">
                  {criticalCount} critical
                </Typography>
              )}
              {highCount > 0 && (
                <Typography variant="body2" color="warning.main">
                  {highCount} high
                </Typography>
              )}
            </Box>

            {recentAlertMessage && (
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                  overflow: 'hidden',
                }}
              >
                {recentAlertMessage}
              </Typography>
            )}

            {recentAlertTime && (
              <Typography variant="caption" color="text.secondary" display="block">
                {new Date(recentAlertTime).toLocaleString()}
              </Typography>
            )}
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No active alerts for this host
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default AlertsCard;
