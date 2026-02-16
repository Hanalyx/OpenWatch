/**
 * Connectivity Card
 *
 * Displays host online/offline status, SSH connection info,
 * and authentication method.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/cards/ConnectivityCard
 */

import React from 'react';
import { Box, Card, CardContent, Typography, Skeleton } from '@mui/material';

interface ConnectivityCardProps {
  status: string;
  hostname: string;
  ipAddress: string;
  port: number;
  username: string;
  authMethod: string;
  lastCheck?: string | null;
  isLoading?: boolean;
}

/**
 * Get display info for authentication method
 */
function getAuthMethodDisplay(authMethod: string): { label: string; description: string } {
  switch (authMethod?.toLowerCase()) {
    case 'ssh_key':
    case 'key':
      return { label: 'SSH Key', description: 'Public key authentication' };
    case 'password':
      return { label: 'Password', description: 'Password authentication' };
    case 'credential':
      return { label: 'Stored Credential', description: 'Using stored credential' };
    default:
      return { label: authMethod || 'Unknown', description: 'Authentication method' };
  }
}

const ConnectivityCard: React.FC<ConnectivityCardProps> = ({
  status,
  hostname,
  ipAddress,
  port,
  username,
  authMethod,
  lastCheck,
  isLoading,
}) => {
  if (isLoading) {
    return (
      <Card sx={{ height: '100%', minHeight: 180 }}>
        <CardContent>
          <Skeleton variant="text" width="50%" height={24} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="70%" height={20} />
          <Skeleton variant="text" width="80%" height={20} />
          <Skeleton variant="text" width="60%" height={20} />
          <Skeleton variant="text" width="50%" height={20} />
        </CardContent>
      </Card>
    );
  }

  const isOnline = status?.toLowerCase() === 'online';
  const authDisplay = getAuthMethodDisplay(authMethod);

  return (
    <Card sx={{ height: '100%', minHeight: 180 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Connectivity
        </Typography>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
          <Box
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              bgcolor: isOnline ? 'success.main' : 'error.main',
            }}
          />
          <Typography variant="h6" fontWeight="medium">
            {isOnline ? 'Online' : 'Offline'}
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          <Typography variant="body2">
            <Typography component="span" color="text.secondary">
              SSH:{' '}
            </Typography>
            {username}@{hostname}:{port}
          </Typography>

          <Typography variant="body2">
            <Typography component="span" color="text.secondary">
              IP:{' '}
            </Typography>
            {ipAddress}
          </Typography>

          <Typography variant="body2">
            <Typography component="span" color="text.secondary">
              Auth:{' '}
            </Typography>
            {authDisplay.label}
          </Typography>

          {lastCheck && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
              Last checked: {new Date(lastCheck).toLocaleString()}
            </Typography>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default ConnectivityCard;
