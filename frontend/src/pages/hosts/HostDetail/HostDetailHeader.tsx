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

import React, { useState, useCallback, useEffect } from 'react';
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
  Chip,
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
const BASELINE_ROLES = ['super_admin', 'security_admin', 'security_analyst'];

interface BaselineInfo {
  baseline_score: number;
  established_at: string;
  baseline_type: string;
}

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
  const [baselineDialogOpen, setBaselineDialogOpen] = useState(false);
  const [baselineAction, setBaselineAction] = useState<'reset' | 'promote'>('reset');
  const [baselineLoading, setBaselineLoading] = useState(false);
  const [baselineInfo, setBaselineInfo] = useState<BaselineInfo | null>(null);

  const isAdmin = user?.role ? ADMIN_ROLES.includes(user.role) : false;
  const canManageBaseline = user?.role ? BASELINE_ROLES.includes(user.role) : false;

  // Fetch current baseline info
  useEffect(() => {
    if (!hostId) return;
    api
      .get(`/api/hosts/${hostId}/baseline`)
      .then((res) => {
        if (res.data) {
          setBaselineInfo(res.data);
        }
      })
      .catch(() => {
        // No baseline or error - that's fine
      });
  }, [hostId]);

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

  const openBaselineDialog = useCallback((action: 'reset' | 'promote') => {
    setBaselineAction(action);
    setBaselineDialogOpen(true);
  }, []);

  const handleConfirmBaseline = useCallback(async () => {
    if (!hostId) return;
    setBaselineDialogOpen(false);
    setBaselineLoading(true);
    try {
      const res = await api.post(`/api/hosts/${hostId}/baseline/${baselineAction}`);
      if (res.data) {
        setBaselineInfo(res.data);
      }
    } catch (err) {
      console.error(`Failed to ${baselineAction} baseline:`, err);
    } finally {
      setBaselineLoading(false);
    }
  }, [hostId, baselineAction]);

  const handleCancelBaseline = useCallback(() => {
    setBaselineDialogOpen(false);
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
        {/* Baseline info and actions - SECURITY_ANALYST+ only */}
        {hostId && canManageBaseline && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mr: 2 }}>
            {baselineInfo && (
              <Chip
                label={`Baseline: ${baselineInfo.baseline_score.toFixed(1)}%`}
                size="small"
                variant="outlined"
                sx={{ mr: 1 }}
              />
            )}
            <Button
              size="small"
              variant="outlined"
              onClick={() => openBaselineDialog('reset')}
              disabled={baselineLoading}
            >
              Reset Baseline
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => openBaselineDialog('promote')}
              disabled={baselineLoading}
            >
              Promote to Baseline
            </Button>
          </Box>
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

      {/* Baseline action confirmation dialog */}
      <Dialog open={baselineDialogOpen} onClose={handleCancelBaseline}>
        <DialogTitle>
          {baselineAction === 'reset' ? 'Reset Baseline' : 'Promote to Baseline'}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {baselineAction === 'reset'
              ? `This will establish a new baseline from the most recent scan for ${displayName || hostname}. The current baseline will be superseded.`
              : `This will promote the current compliance posture to baseline for ${displayName || hostname}. Use this after a known legitimate configuration change.`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelBaseline}>Cancel</Button>
          <Button onClick={handleConfirmBaseline} variant="contained" color="primary">
            {baselineAction === 'reset' ? 'Reset' : 'Promote'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default HostDetailHeader;
