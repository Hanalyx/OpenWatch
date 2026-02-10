/**
 * Audit Log Tab
 *
 * Displays security events and audit log entries for the host.
 * This is a placeholder component that will be expanded when
 * audit log collection is implemented.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/AuditLogTab
 */

import React from 'react';
import { Box, Alert, Typography } from '@mui/material';

interface AuditLogTabProps {
  hostId: string;
}

const AuditLogTab: React.FC<AuditLogTabProps> = ({ hostId: _hostId }) => {
  // Placeholder - audit log collection to be implemented
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Audit Events
      </Typography>
      <Alert severity="info">
        Security audit log collection is not yet enabled for this host. Audit events (login
        attempts, privilege escalations, file access) will be displayed here once audit log
        collection is configured.
      </Alert>
    </Box>
  );
};

export default AuditLogTab;
