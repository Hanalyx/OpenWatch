/**
 * Host Detail Header
 *
 * Displays the header with back navigation, host title,
 * basic info (IP, OS, kernel), and maintenance mode toggle.
 *
 * Scan buttons have been removed - scans run automatically.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/HostDetailHeader
 */

import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  IconButton,
  Switch,
  FormControlLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
  Tooltip,
} from '@mui/material';
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';
import { StatusChip } from '../../../components/design-system';
import { useAuthStore } from '../../../store/useAuthStore';
import { api } from '../../../services/api';
import type { SystemInfo } from '../../../types/hostDetail';

interface HostDetailHeaderProps {
  hostname: string;
  displayName?: string;
  ipAddress: string;
  operatingSystem: string;
  status: string;
  systemInfo?: SystemInfo | null;
  hostId?: string;
  maintenanceMode?: boolean;
  onMaintenanceModeChange?: (enabled: boolean) => void;
}

const ADMIN_ROLES = ['super_admin', 'security_admin'];

const HostDetailHeader: React.FC<HostDetailHeaderProps> = ({
  hostname,
  displayName,
  ipAddress,
  operatingSystem,
  status,
  systemInfo,
  hostId,
  maintenanceMode = false,
  onMaintenanceModeChange,
}) => {
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [pendingMaintenanceValue, setPendingMaintenanceValue] = useState(false);
  const [maintenanceLoading, setMaintenanceLoading] = useState(false);

  const isAdmin = user?.role ? ADMIN_ROLES.includes(user.role) : false;

  // Build subtitle with OS and kernel info
  const osPart = systemInfo?.osPrettyName || operatingSystem || 'Unknown OS';
  const kernelPart = systemInfo?.kernelRelease ? `Kernel ${systemInfo.kernelRelease}` : '';
  const subtitle = [ipAddress, osPart, kernelPart].filter(Boolean).join(' • ');

  const handleMaintenanceToggle = useCallback(
    (_event: React.ChangeEvent<HTMLInputElement>, checked: boolean) => {
      if (checked) {
        // Show confirmation dialog before enabling maintenance mode
        setPendingMaintenanceValue(true);
        setConfirmDialogOpen(true);
      } else {
        // Disable directly without confirmation
        setPendingMaintenanceValue(false);
        submitMaintenanceMode(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [hostId]
  );

  const submitMaintenanceMode = useCallback(
    async (enabled: boolean) => {
      if (!hostId) return;
      setMaintenanceLoading(true);
      try {
        await api.post(`/api/hosts/${hostId}/schedule`, {
          maintenance_mode: enabled,
        });
        onMaintenanceModeChange?.(enabled);
      } catch (err) {
        console.error('Failed to update maintenance mode:', err);
      } finally {
        setMaintenanceLoading(false);
      }
    },
    [hostId, onMaintenanceModeChange]
  );

  const handleConfirmMaintenance = useCallback(() => {
    setConfirmDialogOpen(false);
    submitMaintenanceMode(pendingMaintenanceValue);
  }, [pendingMaintenanceValue, submitMaintenanceMode]);

  const handleCancelMaintenance = useCallback(() => {
    setConfirmDialogOpen(false);
  }, []);

  return (
    <>
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
        {/* Maintenance Mode toggle - admin only */}
        {hostId && (
          <Tooltip
            title={
              isAdmin
                ? 'Toggle maintenance mode for this host'
                : 'Only admins can change maintenance mode'
            }
          >
            <Box sx={{ mr: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={maintenanceMode}
                    onChange={handleMaintenanceToggle}
                    disabled={!isAdmin || maintenanceLoading}
                    size="small"
                  />
                }
                label={
                  <Typography variant="body2" color="text.secondary">
                    Maintenance Mode
                  </Typography>
                }
              />
            </Box>
          </Tooltip>
        )}
        {/* Manual scan buttons removed - compliance scans run automatically */}
        <StatusChip
          status={status === 'online' ? 'online' : status === 'offline' ? 'offline' : 'unknown'}
          label={status || 'Unknown'}
        />
      </Box>

      {/* Maintenance mode confirmation dialog */}
      <Dialog open={confirmDialogOpen} onClose={handleCancelMaintenance}>
        <DialogTitle>Enable Maintenance Mode</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Hosts in maintenance mode are not scanned and do not generate alerts. Are you sure you
            want to enable maintenance mode for {displayName || hostname}?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelMaintenance}>Cancel</Button>
          <Button onClick={handleConfirmMaintenance} variant="contained" color="warning">
            Enable
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default HostDetailHeader;
