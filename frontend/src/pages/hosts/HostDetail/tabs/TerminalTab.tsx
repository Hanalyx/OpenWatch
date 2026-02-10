/**
 * Terminal Tab
 *
 * Wrapper component for the SSH terminal.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/TerminalTab
 */

import React from 'react';
import { Box } from '@mui/material';
import HostTerminal from '../../../../components/terminal/HostTerminal';

interface TerminalTabProps {
  hostId: string;
  hostname: string;
  ipAddress: string;
}

const TerminalTab: React.FC<TerminalTabProps> = ({ hostId, hostname, ipAddress }) => {
  return (
    <Box sx={{ height: '600px' }}>
      <HostTerminal hostId={hostId} hostname={hostname} ipAddress={ipAddress} />
    </Box>
  );
};

export default TerminalTab;
