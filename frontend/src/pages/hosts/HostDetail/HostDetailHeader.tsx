/**
 * Host Detail Header
 *
 * Displays the header with back navigation, host title,
 * and basic info (IP, OS, kernel).
 *
 * Scan buttons have been removed - scans run automatically.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/HostDetailHeader
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Typography, IconButton } from '@mui/material';
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';
import { StatusChip } from '../../../components/design-system';
import type { SystemInfo } from '../../../types/hostDetail';

interface HostDetailHeaderProps {
  hostname: string;
  displayName?: string;
  ipAddress: string;
  operatingSystem: string;
  status: string;
  systemInfo?: SystemInfo | null;
}

const HostDetailHeader: React.FC<HostDetailHeaderProps> = ({
  hostname,
  displayName,
  ipAddress,
  operatingSystem,
  status,
  systemInfo,
}) => {
  const navigate = useNavigate();

  // Build subtitle with OS and kernel info
  const osPart = systemInfo?.osPrettyName || operatingSystem || 'Unknown OS';
  const kernelPart = systemInfo?.kernelRelease ? `Kernel ${systemInfo.kernelRelease}` : '';
  const subtitle = [ipAddress, osPart, kernelPart].filter(Boolean).join(' • ');

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
      <IconButton onClick={() => navigate('/hosts')} sx={{ mr: 2 }}>
        <ArrowBackIcon />
      </IconButton>
      <Box sx={{ flexGrow: 1 }}>
        <Typography variant="h5" component="h1" fontWeight="medium">
          {displayName || hostname}
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          {subtitle}
        </Typography>
      </Box>
      {/* Manual scan buttons removed - compliance scans run automatically */}
      <StatusChip
        status={status === 'online' ? 'online' : status === 'offline' ? 'offline' : 'unknown'}
        label={status || 'Unknown'}
      />
    </Box>
  );
};

export default HostDetailHeader;
