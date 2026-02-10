import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  Typography,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Alert,
  Chip,
  Divider,
  Collapse,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Security as SecurityIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';

interface SchedulerConfig {
  enabled: boolean;
  interval_compliant: number;
  interval_mostly_compliant: number;
  interval_partial: number;
  interval_low: number;
  interval_critical: number;
  interval_unknown: number;
  interval_maintenance: number;
  max_interval_minutes: number;
  priority_compliant: number;
  priority_mostly_compliant: number;
  priority_partial: number;
  priority_low: number;
  priority_critical: number;
  priority_unknown: number;
  priority_maintenance: number;
  max_concurrent_scans: number;
  scan_timeout_seconds: number;
}

interface SchedulerStatus {
  enabled: boolean;
  total_hosts: number;
  hosts_due: number;
  hosts_in_maintenance: number;
  by_compliance_state: { [key: string]: number };
  next_scheduled_scans: Array<{
    host_id: string;
    hostname: string;
    compliance_state: string;
    scheduled_for: string;
  }>;
}

interface ComplianceSchedulerSettingsProps {
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
}

const ComplianceSchedulerSettings: React.FC<ComplianceSchedulerSettingsProps> = ({
  onSuccess,
  onError,
}) => {
  const [config, setConfig] = useState<SchedulerConfig | null>(null);
  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [localConfig, setLocalConfig] = useState<Partial<SchedulerConfig>>({});

  useEffect(() => {
    loadConfig();
    loadStatus();
    // Refresh status every 30 seconds
    const interval = setInterval(loadStatus, 30000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadConfig = async () => {
    try {
      setLoading(true);
      const response = await api.get<SchedulerConfig>('/api/compliance/scheduler/config');
      setConfig(response);
      setLocalConfig({
        interval_compliant: response.interval_compliant,
        interval_mostly_compliant: response.interval_mostly_compliant,
        interval_partial: response.interval_partial,
        interval_low: response.interval_low,
        interval_critical: response.interval_critical,
        max_concurrent_scans: response.max_concurrent_scans,
        scan_timeout_seconds: response.scan_timeout_seconds,
      });
    } catch (err) {
      console.error('Error loading compliance scheduler config:', err);
      onError?.('Failed to load compliance scheduler configuration');
    } finally {
      setLoading(false);
    }
  };

  const loadStatus = async () => {
    try {
      const response = await api.get<SchedulerStatus>('/api/compliance/scheduler/status');
      setStatus(response);
    } catch (err) {
      console.error('Error loading compliance scheduler status:', err);
    }
  };

  const toggleScheduler = async () => {
    try {
      setLoading(true);
      const newEnabled = !config?.enabled;
      await api.post(`/api/compliance/scheduler/toggle?enabled=${newEnabled}`);
      onSuccess?.(newEnabled ? 'Compliance scheduler enabled' : 'Compliance scheduler disabled');
      await loadConfig();
      await loadStatus();
    } catch (err) {
      console.error('Error toggling compliance scheduler:', err);
      onError?.('Failed to toggle compliance scheduler');
    } finally {
      setLoading(false);
    }
  };

  const updateConfig = async () => {
    try {
      setLoading(true);
      await api.put('/api/compliance/scheduler/config', localConfig);
      onSuccess?.('Compliance scheduler configuration updated');
      await loadConfig();
    } catch (err) {
      console.error('Error updating compliance scheduler config:', err);
      onError?.('Failed to update compliance scheduler configuration');
    } finally {
      setLoading(false);
    }
  };

  const getStateColor = (state: string): string => {
    const colors: { [key: string]: string } = {
      compliant: '#4caf50',
      mostly_compliant: '#8bc34a',
      partial: '#ff9800',
      low: '#ff5722',
      critical: '#f44336',
      unknown: '#9c27b0',
      maintenance: '#2196f3',
    };
    return colors[state] || '#757575';
  };

  const getStateLabel = (state: string): string => {
    const labels: { [key: string]: string } = {
      compliant: 'Compliant (90%+)',
      mostly_compliant: 'Mostly (70-89%)',
      partial: 'Partial (50-69%)',
      low: 'Low (20-49%)',
      critical: 'Critical (<20%)',
      unknown: 'Unknown',
      maintenance: 'Maintenance',
    };
    return labels[state] || state;
  };

  const formatInterval = (minutes: number): string => {
    if (minutes >= 1440) {
      const hours = Math.round(minutes / 60);
      return `${hours}h`;
    } else if (minutes >= 60) {
      const hours = Math.round(minutes / 60);
      return `${hours}h`;
    }
    return `${minutes}m`;
  };

  if (!config) {
    return <LinearProgress />;
  }

  return (
    <Card sx={{ mb: 4, p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Typography variant="h6">
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Adaptive Compliance Scheduler
          </Typography>
          <Chip
            label={config.enabled ? 'RUNNING' : 'STOPPED'}
            color={config.enabled ? 'success' : 'default'}
            size="small"
          />
        </Box>
        <Typography variant="body2" color="text.secondary">
          Automatic compliance scanning with adaptive intervals. Critical compliance hosts are
          scanned more frequently than compliant hosts. Maximum interval: 48 hours.
        </Typography>
      </Box>

      {/* Enable/Disable Toggle */}
      <Box sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Switch checked={config.enabled} onChange={toggleScheduler} disabled={loading} />
          }
          label="Enable Automatic Compliance Scanning"
        />
        <Button
          variant="outlined"
          size="small"
          startIcon={config.enabled ? <StopIcon /> : <PlayIcon />}
          onClick={toggleScheduler}
          disabled={loading}
          sx={{ ml: 2 }}
        >
          {loading ? 'Updating...' : config.enabled ? 'Stop Scheduler' : 'Start Scheduler'}
        </Button>
      </Box>

      {/* Compliance Distribution */}
      {status && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            Compliance Distribution ({status.total_hosts} hosts)
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
            {Object.entries(status.by_compliance_state).map(([state, count]) => (
              <Chip
                key={state}
                label={`${getStateLabel(state).split(' ')[0]}: ${count}`}
                size="small"
                sx={{
                  backgroundColor: getStateColor(state),
                  color: 'white',
                  fontWeight: 'medium',
                }}
              />
            ))}
          </Box>
          {status.hosts_due > 0 && (
            <Alert severity="info" sx={{ mb: 2 }}>
              {status.hosts_due} host{status.hosts_due > 1 ? 's' : ''} due for compliance scanning
            </Alert>
          )}
          {status.hosts_in_maintenance > 0 && (
            <Typography variant="body2" color="text.secondary">
              {status.hosts_in_maintenance} host{status.hosts_in_maintenance > 1 ? 's' : ''} in
              maintenance mode
            </Typography>
          )}
        </Box>
      )}

      <Divider sx={{ my: 3 }} />

      {/* Scan Intervals */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Scan Intervals by Compliance State
          <Tooltip title="How often to scan hosts based on their compliance score. Lower compliance = more frequent scans.">
            <IconButton size="small" sx={{ ml: 0.5 }}>
              <InfoIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Typography>
        <Grid container spacing={2} sx={{ mt: 1 }}>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <TextField
              fullWidth
              label="Compliant (90%+)"
              type="number"
              size="small"
              value={localConfig.interval_compliant || ''}
              onChange={(e) =>
                setLocalConfig({
                  ...localConfig,
                  interval_compliant: parseInt(e.target.value) || 60,
                })
              }
              inputProps={{ min: 60, max: 2880 }}
              helperText={`Current: ${formatInterval(config.interval_compliant)}`}
              InputProps={{
                endAdornment: <Typography variant="caption">min</Typography>,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <TextField
              fullWidth
              label="Mostly Compliant (70-89%)"
              type="number"
              size="small"
              value={localConfig.interval_mostly_compliant || ''}
              onChange={(e) =>
                setLocalConfig({
                  ...localConfig,
                  interval_mostly_compliant: parseInt(e.target.value) || 60,
                })
              }
              inputProps={{ min: 30, max: 2880 }}
              helperText={`Current: ${formatInterval(config.interval_mostly_compliant)}`}
              InputProps={{
                endAdornment: <Typography variant="caption">min</Typography>,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <TextField
              fullWidth
              label="Partial (50-69%)"
              type="number"
              size="small"
              value={localConfig.interval_partial || ''}
              onChange={(e) =>
                setLocalConfig({ ...localConfig, interval_partial: parseInt(e.target.value) || 60 })
              }
              inputProps={{ min: 30, max: 2880 }}
              helperText={`Current: ${formatInterval(config.interval_partial)}`}
              InputProps={{
                endAdornment: <Typography variant="caption">min</Typography>,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <TextField
              fullWidth
              label="Low (20-49%)"
              type="number"
              size="small"
              value={localConfig.interval_low || ''}
              onChange={(e) =>
                setLocalConfig({ ...localConfig, interval_low: parseInt(e.target.value) || 60 })
              }
              inputProps={{ min: 30, max: 2880 }}
              helperText={`Current: ${formatInterval(config.interval_low)}`}
              InputProps={{
                endAdornment: <Typography variant="caption">min</Typography>,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <TextField
              fullWidth
              label="Critical (<20%)"
              type="number"
              size="small"
              value={localConfig.interval_critical || ''}
              onChange={(e) =>
                setLocalConfig({
                  ...localConfig,
                  interval_critical: parseInt(e.target.value) || 60,
                })
              }
              inputProps={{ min: 15, max: 2880 }}
              helperText={`Current: ${formatInterval(config.interval_critical)}`}
              InputProps={{
                endAdornment: <Typography variant="caption">min</Typography>,
              }}
            />
          </Grid>
        </Grid>
        <Box sx={{ mt: 2 }}>
          <Button variant="contained" size="small" onClick={updateConfig} disabled={loading}>
            Save Intervals
          </Button>
        </Box>
      </Box>

      <Divider sx={{ my: 3 }} />

      {/* Advanced Settings */}
      <Box>
        <Button
          size="small"
          onClick={() => setShowAdvanced(!showAdvanced)}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          Advanced Settings
        </Button>
        <Collapse in={showAdvanced}>
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  fullWidth
                  label="Max Concurrent Scans"
                  type="number"
                  size="small"
                  value={localConfig.max_concurrent_scans || ''}
                  onChange={(e) =>
                    setLocalConfig({
                      ...localConfig,
                      max_concurrent_scans: parseInt(e.target.value) || 5,
                    })
                  }
                  inputProps={{ min: 1, max: 20 }}
                  helperText="1-20 concurrent scans (prevents resource exhaustion)"
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 6 }}>
                <TextField
                  fullWidth
                  label="Scan Timeout (seconds)"
                  type="number"
                  size="small"
                  value={localConfig.scan_timeout_seconds || ''}
                  onChange={(e) =>
                    setLocalConfig({
                      ...localConfig,
                      scan_timeout_seconds: parseInt(e.target.value) || 600,
                    })
                  }
                  inputProps={{ min: 60, max: 3600 }}
                  helperText="60-3600 seconds per scan"
                />
              </Grid>
            </Grid>
            <Box sx={{ mt: 2 }}>
              <Button variant="contained" size="small" onClick={updateConfig} disabled={loading}>
                Save Advanced Settings
              </Button>
            </Box>
          </Box>
        </Collapse>
      </Box>

      {/* Next Scheduled Scans */}
      {status && status.next_scheduled_scans && status.next_scheduled_scans.length > 0 && (
        <>
          <Divider sx={{ my: 3 }} />
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Next Scheduled Scans
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {status.next_scheduled_scans.slice(0, 5).map((scan) => (
                <Box
                  key={scan.host_id}
                  sx={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    p: 1,
                    bgcolor: 'action.hover',
                    borderRadius: 1,
                  }}
                >
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      {scan.hostname}
                    </Typography>
                    <Chip
                      label={scan.compliance_state}
                      size="small"
                      sx={{
                        backgroundColor: getStateColor(scan.compliance_state),
                        color: 'white',
                        height: 20,
                        fontSize: '0.7rem',
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {new Date(scan.scheduled_for).toLocaleString()}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Box>
        </>
      )}

      {/* Info Alert */}
      <Alert severity="info" sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Adaptive Compliance Scanning:</strong> The scheduler automatically adjusts scan
          frequency based on compliance score. Hosts with critical compliance issues are scanned
          every {formatInterval(config.interval_critical)}, while compliant hosts are scanned every{' '}
          {formatInterval(config.interval_compliant)}. All hosts are scanned at least every 48 hours
          to ensure continuous visibility.
        </Typography>
      </Alert>
    </Card>
  );
};

export default ComplianceSchedulerSettings;
