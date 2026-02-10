/**
 * Exceptions Card
 *
 * Displays active and pending compliance exception counts
 * for governance tracking.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/ExceptionsCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';

interface ExceptionsCardProps {
  activeCount?: number;
  pendingCount?: number;
  expiringSoonCount?: number;
  isLoading?: boolean;
}

const ExceptionsCard: React.FC<ExceptionsCardProps> = ({
  activeCount = 0,
  pendingCount = 0,
  expiringSoonCount = 0,
  isLoading,
}) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="50%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="40%" height={32} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="70%" height={20} />
          <Skeleton variant="text" width="60%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const hasExceptions = activeCount > 0 || pendingCount > 0;

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Exceptions
        </Typography>

        {hasExceptions ? (
          <>
            <Typography variant="h4" fontWeight="bold" sx={{ mb: 1 }}>
              {activeCount}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
              Active exceptions
            </Typography>

            {pendingCount > 0 && (
              <Typography variant="body2" color="warning.main">
                {pendingCount} pending approval
              </Typography>
            )}

            {expiringSoonCount > 0 && (
              <Typography variant="body2" color="info.main">
                {expiringSoonCount} expiring within 30 days
              </Typography>
            )}
          </>
        ) : (
          <Box>
            <Typography variant="h4" fontWeight="bold" color="text.secondary" sx={{ mb: 1 }}>
              0
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No active exceptions for this host
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default ExceptionsCard;
