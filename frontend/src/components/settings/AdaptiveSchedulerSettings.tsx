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
  Grid,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Collapse,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  Schedule as ScheduleIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  RestartAlt as ResetIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';

interface IntervalConfig {
  unknown: number;
  online: number;
  degraded: number;
  critical: number;
  down: number;
  maintenance: number;
}

interface SchedulerConfig {
  enabled: boolean;
  intervals: IntervalConfig;
  maintenance_mode: 'skip' | 'passive' | 'reduced';
  max_concurrent_checks: number;
  check_timeout_seconds: number;
  retry_on_failure: boolean;
}

interface SchedulerStats {
  enabled: boolean;
  hosts_by_state: { [key: string]: number };
  total_hosts: number;
  overdue_checks: number;
  next_check_time: string | null;
  max_concurrent_checks: number;
  maintenance_mode: string;
}

interface AdaptiveSchedulerSettingsProps {
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
}

const AdaptiveSchedulerSettings: React.FC<AdaptiveSchedulerSettingsProps> = ({
  onSuccess,
  onError,
}) => {
  const [config, setConfig] = useState<SchedulerConfig | null>(null);
  const [stats, setStats] = useState<SchedulerStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [localIntervals, setLocalIntervals] = useState<IntervalConfig | null>(null);

  useEffect(() => {
    loadConfig();
    loadStats();
    // Refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadConfig = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/system/adaptive-scheduler/config');
      setConfig(response);
      setLocalIntervals(response.intervals);
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error loading scheduler config:', err);
      onError?.('Failed to load scheduler configuration');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await api.get('/api/system/adaptive-scheduler/stats');
      setStats(response);
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error loading scheduler stats:', err);
    }
  };

  const toggleScheduler = async () => {
    try {
      setLoading(true);
      const endpoint = config?.enabled
        ? '/api/system/adaptive-scheduler/stop'
        : '/api/system/adaptive-scheduler/start';

      await api.post(endpoint);
      onSuccess?.(
        config?.enabled ? 'Scheduler stopped successfully' : 'Scheduler started successfully'
      );
      await loadConfig();
      await loadStats();
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error toggling scheduler:', err);
      onError?.('Failed to toggle scheduler');
    } finally {
      setLoading(false);
    }
  };

  const updateIntervals = async () => {
    if (!localIntervals) return;

    try {
      setLoading(true);
      await api.put('/api/system/adaptive-scheduler/config', {
        intervals: localIntervals,
      });
      onSuccess?.('Check intervals updated successfully');
      await loadConfig();
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error updating intervals:', err);
      onError?.('Failed to update check intervals');
    } finally {
      setLoading(false);
    }
  };

  const updateMaintenanceMode = async (mode: 'skip' | 'passive' | 'reduced') => {
    try {
      setLoading(true);
      await api.put('/api/system/adaptive-scheduler/config', {
        maintenance_mode: mode,
      });
      onSuccess?.('Maintenance mode updated successfully');
      await loadConfig();
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error updating maintenance mode:', err);
      onError?.('Failed to update maintenance mode');
    } finally {
      setLoading(false);
    }
  };

  const updateAdvancedSettings = async (settings: Partial<SchedulerConfig>) => {
    try {
      setLoading(true);
      await api.put('/api/system/adaptive-scheduler/config', settings);
      onSuccess?.('Advanced settings updated successfully');
      await loadConfig();
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error updating advanced settings:', err);
      onError?.('Failed to update advanced settings');
    } finally {
      setLoading(false);
    }
  };

  const resetToDefaults = async () => {
    if (!confirm('Reset all scheduler settings to defaults? This cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      await api.post('/api/system/adaptive-scheduler/reset-defaults');
      onSuccess?.('Scheduler reset to default settings');
      await loadConfig();
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error resetting scheduler:', err);
      onError?.('Failed to reset scheduler');
    } finally {
      setLoading(false);
    }
  };

  const getStateColor = (state: string): string => {
    const colors: { [key: string]: string } = {
      online: '#4caf50',
      degraded: '#ff9800',
      critical: '#f44336',
      down: '#757575',
      maintenance: '#2196f3',
      unknown: '#9c27b0',
    };
    return colors[state] || '#757575';
  };

  const getStateLabel = (state: string): string => {
    const labels: { [key: string]: string } = {
      online: 'Online',
      degraded: 'Degraded',
      critical: 'Critical',
      down: 'Down',
      maintenance: 'Maintenance',
      unknown: 'Unknown',
    };
    return labels[state] || state;
  };

  if (!config || !localIntervals) {
    return <LinearProgress />;
  }

  return (
    <Card sx={{ mb: 4, p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Typography variant="h6">
            <ScheduleIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Adaptive Host Monitoring Scheduler
          </Typography>
          <Chip
            label={config.enabled ? 'RUNNING' : 'STOPPED'}
            color={config.enabled ? 'success' : 'default'}
            size="small"
          />
        </Box>
        <Typography variant="body2" color="text.secondary">
          Intelligent monitoring with state-based check intervals. Critical hosts are checked more
          frequently than healthy hosts.
        </Typography>
      </Box>

      {/* Enable/Disable Toggle */}
      <Box sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Switch checked={config.enabled} onChange={toggleScheduler} disabled={loading} />
          }
          label="Enable Adaptive Monitoring"
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

      {/* Host Statistics */}
      {stats && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            Host Status Distribution ({stats.total_hosts} total)
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
            {Object.entries(stats.hosts_by_state).map(([state, count]) => (
              <Chip
                key={state}
                label={`${getStateLabel(state)}: ${count}`}
                size="small"
                sx={{
                  backgroundColor: getStateColor(state),
                  color: 'white',
                  fontWeight: 'medium',
                }}
              />
            ))}
          </Box>
          {stats.overdue_checks > 0 && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              {stats.overdue_checks} host{stats.overdue_checks > 1 ? 's' : ''} overdue for checking
            </Alert>
          )}
        </Box>
      )}

      <Divider sx={{ my: 3 }} />

      {/* Check Intervals */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Check Intervals (minutes)
          <Tooltip title="How often to check hosts in each state">
            <IconButton size="small" sx={{ ml: 0.5 }}>
              <InfoIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Typography>
        <Grid container spacing={2} sx={{ mt: 1 }}>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Unknown (New Hosts)"
              type="number"
              size="small"
              value={localIntervals.unknown}
              onChange={(e) =>
                setLocalIntervals({ ...localIntervals, unknown: parseInt(e.target.value) || 0 })
              }
              inputProps={{ min: 0, max: 60 }}
              helperText="0 = immediate (0-60 min)"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Online (Healthy)"
              type="number"
              size="small"
              value={localIntervals.online}
              onChange={(e) =>
                setLocalIntervals({ ...localIntervals, online: parseInt(e.target.value) || 15 })
              }
              inputProps={{ min: 5, max: 60 }}
              helperText="5-60 minutes"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Degraded (1 Failure)"
              type="number"
              size="small"
              value={localIntervals.degraded}
              onChange={(e) =>
                setLocalIntervals({ ...localIntervals, degraded: parseInt(e.target.value) || 5 })
              }
              inputProps={{ min: 1, max: 15 }}
              helperText="1-15 minutes"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Critical (2 Failures)"
              type="number"
              size="small"
              value={localIntervals.critical}
              onChange={(e) =>
                setLocalIntervals({ ...localIntervals, critical: parseInt(e.target.value) || 2 })
              }
              inputProps={{ min: 1, max: 10 }}
              helperText="1-10 minutes"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Down (3+ Failures)"
              type="number"
              size="small"
              value={localIntervals.down}
              onChange={(e) =>
                setLocalIntervals({ ...localIntervals, down: parseInt(e.target.value) || 30 })
              }
              inputProps={{ min: 10, max: 120 }}
              helperText="10-120 minutes"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              label="Maintenance"
              type="number"
              size="small"
              value={localIntervals.maintenance}
              onChange={(e) =>
                setLocalIntervals({
                  ...localIntervals,
                  maintenance: parseInt(e.target.value) || 60,
                })
              }
              inputProps={{ min: 15, max: 1440 }}
              helperText="15-1440 minutes"
            />
          </Grid>
        </Grid>
        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button variant="contained" size="small" onClick={updateIntervals} disabled={loading}>
            Save Intervals
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<ResetIcon />}
            onClick={resetToDefaults}
            disabled={loading}
          >
            Reset to Defaults
          </Button>
        </Box>
      </Box>

      <Divider sx={{ my: 3 }} />

      {/* Maintenance Mode */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Maintenance Mode Behavior
        </Typography>
        <FormControl fullWidth size="small" sx={{ mt: 1 }}>
          <InputLabel>Maintenance Mode</InputLabel>
          <Select
            value={config.maintenance_mode}
            onChange={(e) =>
              updateMaintenanceMode(e.target.value as 'skip' | 'passive' | 'reduced')
            }
            label="Maintenance Mode"
            disabled={loading}
          >
            <MenuItem value="skip">
              <Box>
                <Typography variant="body2" fontWeight="medium">
                  Skip Checks
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Do not monitor hosts in maintenance mode
                </Typography>
              </Box>
            </MenuItem>
            <MenuItem value="passive">
              <Box>
                <Typography variant="body2" fontWeight="medium">
                  Passive Only
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Only check when manually triggered
                </Typography>
              </Box>
            </MenuItem>
            <MenuItem value="reduced">
              <Box>
                <Typography variant="body2" fontWeight="medium">
                  Reduced Checks
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Check every {localIntervals.maintenance} minutes
                </Typography>
              </Box>
            </MenuItem>
          </Select>
        </FormControl>
      </Box>

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
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Max Concurrent Checks"
                  type="number"
                  size="small"
                  value={config.max_concurrent_checks}
                  onChange={(e) =>
                    updateAdvancedSettings({
                      max_concurrent_checks: parseInt(e.target.value) || 10,
                    })
                  }
                  inputProps={{ min: 1, max: 50 }}
                  helperText="1-50 (prevents network flooding)"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Check Timeout (seconds)"
                  type="number"
                  size="small"
                  value={config.check_timeout_seconds}
                  onChange={(e) =>
                    updateAdvancedSettings({
                      check_timeout_seconds: parseInt(e.target.value) || 30,
                    })
                  }
                  inputProps={{ min: 10, max: 300 }}
                  helperText="10-300 seconds"
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.retry_on_failure}
                      onChange={(e) =>
                        updateAdvancedSettings({ retry_on_failure: e.target.checked })
                      }
                      disabled={loading}
                    />
                  }
                  label="Retry failed checks"
                />
              </Grid>
            </Grid>
          </Box>
        </Collapse>
      </Box>

      {/* Info Alert */}
      <Alert severity="info" sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Adaptive Monitoring:</strong> The scheduler automatically adjusts check frequency
          based on host health. Critical hosts are checked every {localIntervals.critical} minutes,
          while healthy hosts are only checked every {localIntervals.online} minutes. This prevents
          network flooding and optimizes resource usage for environments with 100+ hosts.
        </Typography>
      </Alert>
    </Card>
  );
};

export default AdaptiveSchedulerSettings;
