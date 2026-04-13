/**
 * Scheduled Scans Management Page
 *
 * Displays adaptive compliance scheduler status, allows configuration
 * of scan intervals per compliance state via sliders, shows a per-host
 * schedule table, and provides a 48-hour scan projection histogram.
 *
 * Spec: specs/frontend/scheduled-scans.spec.yaml
 */

import React, { useState, useCallback, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Slider,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  CircularProgress,
  Alert,
  Snackbar,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CheckCircle,
  Cancel,
  Schedule as ScheduleIcon,
  Save as SaveIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  schedulerService,
  type SchedulerConfig,
  type SchedulerStatus,
  type SchedulerConfigUpdate,
} from '../../services/adapters/schedulerAdapter';
import { api } from '../../services/api';

// =============================================================================
// Constants
// =============================================================================

/** Slider definitions for each compliance state interval */
const INTERVAL_SLIDERS = [
  {
    key: 'interval_critical' as const,
    label: 'Critical (<20%)',
    stateKey: 'critical',
    min: 15,
    max: 480,
    defaultValue: 60,
  },
  {
    key: 'interval_low' as const,
    label: 'Low (20-49%)',
    stateKey: 'low',
    min: 30,
    max: 720,
    defaultValue: 120,
  },
  {
    key: 'interval_partial' as const,
    label: 'Partial (50-79%)',
    stateKey: 'partial',
    min: 60,
    max: 1440,
    defaultValue: 360,
  },
  {
    key: 'interval_mostly_compliant' as const,
    label: 'Mostly Compliant (80-99%)',
    stateKey: 'mostly_compliant',
    min: 60,
    max: 2880,
    defaultValue: 720,
  },
  {
    key: 'interval_compliant' as const,
    label: 'Compliant (100%)',
    stateKey: 'compliant',
    min: 60,
    max: 2880,
    defaultValue: 1440,
  },
] as const;

/** Format minutes into a human-readable duration */
function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remaining = minutes % 60;
  if (remaining === 0) return `${hours}h`;
  return `${hours}h ${remaining}m`;
}

/** Map compliance state to chip color */
function getStateColor(
  state: string
): 'error' | 'warning' | 'info' | 'success' | 'default' {
  switch (state) {
    case 'critical':
      return 'error';
    case 'low':
      return 'warning';
    case 'partial':
      return 'info';
    case 'mostly_compliant':
      return 'success';
    case 'compliant':
      return 'success';
    default:
      return 'default';
  }
}

// =============================================================================
// Host type from /api/hosts/
// =============================================================================

interface HostEntry {
  id: string;
  hostname: string;
  display_name?: string;
}

// =============================================================================
// Sub-components
// =============================================================================

/** Scheduler status indicator card */
function StatusCard({ status }: { status: SchedulerStatus }) {
  const nextScanTime =
    status.next_scheduled_scans.length > 0
      ? new Date(status.next_scheduled_scans[0].next_scheduled_scan).toLocaleString()
      : 'None scheduled';

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <ScheduleIcon />
          <Typography variant="h6">Scheduler Status</Typography>
        </Box>
        <Grid container spacing={2}>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Typography variant="body2" color="text.secondary">
              Status
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              {status.enabled ? (
                <CheckCircle fontSize="small" color="success" />
              ) : (
                <Cancel fontSize="small" color="error" />
              )}
              <Typography variant="body1" fontWeight="medium">
                {status.enabled ? 'Running' : 'Stopped'}
              </Typography>
            </Box>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Typography variant="body2" color="text.secondary">
              Hosts Total
            </Typography>
            <Typography variant="body1" fontWeight="medium">
              {status.total_hosts}
            </Typography>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Typography variant="body2" color="text.secondary">
              Hosts Due
            </Typography>
            <Typography variant="body1" fontWeight="medium">
              {status.hosts_due}
            </Typography>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Typography variant="body2" color="text.secondary">
              Next Scan
            </Typography>
            <Typography variant="body1" fontWeight="medium">
              {nextScanTime}
            </Typography>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
}

/** Interval configuration sliders */
function IntervalConfig({
  config,
  onSave,
  isSaving,
}: {
  config: SchedulerConfig;
  onSave: (update: SchedulerConfigUpdate) => void;
  isSaving: boolean;
}) {
  const [localValues, setLocalValues] = useState<Record<string, number>>(() => {
    const initial: Record<string, number> = {};
    for (const slider of INTERVAL_SLIDERS) {
      initial[slider.key] = config[slider.key];
    }
    return initial;
  });

  const hasChanges = INTERVAL_SLIDERS.some(
    (slider) => localValues[slider.key] !== config[slider.key]
  );

  const handleSliderChange = useCallback(
    (key: string) => (_event: Event, value: number | number[]) => {
      setLocalValues((prev) => ({ ...prev, [key]: value as number }));
    },
    []
  );

  const handleSave = useCallback(() => {
    const update: SchedulerConfigUpdate = {};
    for (const slider of INTERVAL_SLIDERS) {
      if (localValues[slider.key] !== config[slider.key]) {
        (update as Record<string, number>)[slider.key] = localValues[slider.key];
      }
    }
    onSave(update);
  }, [localValues, config, onSave]);

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
          <Typography variant="h6">Interval Configuration</Typography>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSave}
            disabled={!hasChanges || isSaving}
          >
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {INTERVAL_SLIDERS.map((slider) => (
            <Box key={slider.key}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2">{slider.label}</Typography>
                <Typography variant="body2" fontWeight="medium">
                  {formatMinutes(localValues[slider.key])}
                </Typography>
              </Box>
              <Slider
                value={localValues[slider.key]}
                onChange={handleSliderChange(slider.key)}
                min={slider.min}
                max={slider.max}
                step={15}
                valueLabelDisplay="auto"
                valueLabelFormat={formatMinutes}
                data-testid={`slider-${slider.stateKey}`}
              />
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
}

/** Per-host schedule table */
function HostScheduleTable({ status }: { status: SchedulerStatus }) {
  // Fetch hosts list
  const { data: hosts } = useQuery<HostEntry[]>({
    queryKey: ['hosts-list'],
    queryFn: () => api.get<HostEntry[]>('/api/hosts/'),
    staleTime: 60_000,
  });

  // Merge host data with scheduler next_scheduled_scans
  const rows = useMemo(() => {
    if (!hosts) return [];

    const scanMap = new Map(
      status.next_scheduled_scans.map((s) => [s.host_id, s])
    );

    // Also use by_compliance_state for context
    return hosts.map((host) => {
      const scheduled = scanMap.get(host.id);
      return {
        hostId: host.id,
        hostname: host.display_name || host.hostname,
        complianceState: scheduled?.compliance_state ?? 'unknown',
        complianceScore: null as number | null,
        currentIntervalMinutes: 0,
        nextScheduledScan: scheduled?.next_scheduled_scan ?? null,
        maintenanceMode: false,
      };
    });
  }, [hosts, status]);

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Per-Host Schedule
        </Typography>
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Host</TableCell>
                <TableCell>Compliance State</TableCell>
                <TableCell>Score</TableCell>
                <TableCell>Interval</TableCell>
                <TableCell>Next Scan</TableCell>
                <TableCell>Maintenance</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography variant="body2" color="text.secondary">
                      No hosts found
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((row) => (
                  <TableRow key={row.hostId}>
                    <TableCell>{row.hostname}</TableCell>
                    <TableCell>
                      <Chip
                        label={row.complianceState}
                        color={getStateColor(row.complianceState)}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      {row.complianceScore !== null ? `${row.complianceScore}%` : '--'}
                    </TableCell>
                    <TableCell>
                      {row.currentIntervalMinutes > 0
                        ? formatMinutes(row.currentIntervalMinutes)
                        : '--'}
                    </TableCell>
                    <TableCell>
                      {row.nextScheduledScan
                        ? new Date(row.nextScheduledScan).toLocaleString()
                        : '--'}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={row.maintenanceMode ? 'Yes' : 'No'}
                        color={row.maintenanceMode ? 'warning' : 'default'}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </CardContent>
    </Card>
  );
}

/** Preview histogram showing projected scan counts for next 48 hours */
function ScanProjectionHistogram({
  status,
  config,
}: {
  status: SchedulerStatus;
  config: SchedulerConfig;
}) {
  // Build 48-hour projection based on compliance state distribution and intervals
  const buckets = useMemo(() => {
    const HOURS = 48;
    const hourBuckets = new Array(HOURS).fill(0);

    // For each compliance state, estimate how many scans will occur per hour
    const stateIntervals: Record<string, number> = {
      critical: config.interval_critical,
      low: config.interval_low,
      partial: config.interval_partial,
      mostly_compliant: config.interval_mostly_compliant,
      compliant: config.interval_compliant,
      unknown: config.interval_unknown,
    };

    for (const [state, count] of Object.entries(status.by_compliance_state)) {
      const intervalMinutes = stateIntervals[state] || config.interval_compliant;
      if (intervalMinutes <= 0 || count <= 0) continue;

      // Distribute scans across time buckets
      const intervalHours = intervalMinutes / 60;
      for (let h = 0; h < HOURS; h++) {
        // Approximate: each host scans once per interval
        if (intervalHours > 0) {
          hourBuckets[h] += count / intervalHours;
        }
      }
    }

    return hourBuckets.map((val, idx) => ({
      hour: idx,
      count: Math.round(val * 10) / 10,
    }));
  }, [status, config]);

  const maxCount = Math.max(...buckets.map((b) => b.count), 1);

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Projected Scans (Next 48 Hours)
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: 120 }}>
          {buckets.map((bucket) => {
            const heightPercent = maxCount > 0 ? (bucket.count / maxCount) * 100 : 0;
            return (
              <Box
                key={bucket.hour}
                sx={{
                  flex: 1,
                  minWidth: 4,
                  height: `${Math.max(heightPercent, 2)}%`,
                  bgcolor: 'primary.main',
                  borderRadius: '2px 2px 0 0',
                  opacity: 0.7,
                  '&:hover': { opacity: 1 },
                }}
                title={`Hour ${bucket.hour}: ~${bucket.count} scans`}
              />
            );
          })}
        </Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
          <Typography variant="caption" color="text.secondary">
            Now
          </Typography>
          <Typography variant="caption" color="text.secondary">
            +24h
          </Typography>
          <Typography variant="caption" color="text.secondary">
            +48h
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
}

// =============================================================================
// Main Page Component
// =============================================================================

const ScheduledScans: React.FC = () => {
  const queryClient = useQueryClient();
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Fetch scheduler status
  const {
    data: status,
    isLoading: statusLoading,
    error: statusError,
  } = useQuery<SchedulerStatus>({
    queryKey: ['scheduler-status'],
    queryFn: schedulerService.getStatus,
    refetchInterval: 30_000,
  });

  // Fetch scheduler config
  const {
    data: config,
    isLoading: configLoading,
    error: configError,
  } = useQuery<SchedulerConfig>({
    queryKey: ['scheduler-config'],
    queryFn: schedulerService.getConfig,
  });

  // Save config mutation
  const saveMutation = useMutation({
    mutationFn: (update: SchedulerConfigUpdate) => schedulerService.updateConfig(update),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduler-config'] });
      queryClient.invalidateQueries({ queryKey: ['scheduler-status'] });
      setSnackbar({ open: true, message: 'Configuration saved', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to save configuration', severity: 'error' });
    },
  });

  const handleSave = useCallback(
    (update: SchedulerConfigUpdate) => {
      saveMutation.mutate(update);
    },
    [saveMutation]
  );

  const isLoading = statusLoading || configLoading;
  const error = statusError || configError;

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Failed to load scheduler data: {(error as Error).message}
      </Alert>
    );
  }

  if (!status || !config) {
    return (
      <Alert severity="warning" sx={{ m: 2 }}>
        No scheduler data available
      </Alert>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Typography variant="h5">Scan Schedule</Typography>

      {/* AC-1: Scheduler status card */}
      <StatusCard status={status} />

      {/* AC-4: Projection histogram */}
      <ScanProjectionHistogram status={status} config={config} />

      {/* AC-2, AC-5: Interval configuration with sliders and save */}
      <IntervalConfig config={config} onSave={handleSave} isSaving={saveMutation.isPending} />

      {/* AC-3: Per-host schedule table */}
      <HostScheduleTable status={status} />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ScheduledScans;
