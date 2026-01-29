import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  Typography,
  Switch,
  FormControlLabel,
  Button,
  Alert,
  Chip,
  Divider,
  LinearProgress,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
} from '@mui/material';
import {
  Search as SearchIcon,
  PlayArrow as PlayIcon,
  Check as CheckIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';
import { useAppDispatch } from '../../hooks/redux';
import { setOSDiscoveryFailures } from '../../store/slices/notificationSlice';

interface OSDiscoveryConfig {
  enabled: boolean;
  schedule: string;
  last_run: string | null;
  next_run: string | null;
}

interface DiscoveryFailure {
  host_id: string;
  error_message: string;
  timestamp: string;
  retry_count: number;
}

interface OSDiscoveryStats {
  total_hosts: number;
  hosts_with_platform: number;
  hosts_missing_platform: number;
  pending_failures: number;
  failures: DiscoveryFailure[];
}

interface OSDiscoverySettingsProps {
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
}

const OSDiscoverySettings: React.FC<OSDiscoverySettingsProps> = ({ onSuccess, onError }) => {
  const dispatch = useAppDispatch();
  const [config, setConfig] = useState<OSDiscoveryConfig | null>(null);
  const [stats, setStats] = useState<OSDiscoveryStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [runningDiscovery, setRunningDiscovery] = useState(false);

  useEffect(() => {
    loadConfig();
    loadStats();
    // Refresh stats every 60 seconds
    const interval = setInterval(loadStats, 60000);
    return () => clearInterval(interval);
    // ESLint disable: loadConfig and loadStats functions are not memoized
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadConfig = async () => {
    try {
      setLoading(true);
      const response = await api.get<OSDiscoveryConfig>('/api/system/os-discovery/config');
      setConfig(response);
    } catch (err) {
      console.error('Error loading OS discovery config:', err);
      onError?.('Failed to load OS discovery configuration');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await api.get<OSDiscoveryStats>('/api/system/os-discovery/stats');
      setStats(response);
      // Update Redux state for notification badge
      dispatch(setOSDiscoveryFailures(response.pending_failures || 0));
    } catch (err) {
      console.error('Error loading OS discovery stats:', err);
    }
  };

  const toggleDiscovery = async () => {
    if (!config) return;

    try {
      setLoading(true);
      await api.put('/api/system/os-discovery/config', {
        enabled: !config.enabled,
      });
      onSuccess?.(
        config.enabled ? 'Scheduled OS discovery disabled' : 'Scheduled OS discovery enabled'
      );
      await loadConfig();
    } catch (err) {
      console.error('Error toggling OS discovery:', err);
      onError?.('Failed to update OS discovery setting');
    } finally {
      setLoading(false);
    }
  };

  const runDiscoveryNow = async () => {
    try {
      setRunningDiscovery(true);
      await api.post('/api/system/os-discovery/run');
      onSuccess?.('OS discovery task started - check hosts for updated platform data');
      // Refresh stats after a delay to show updated data
      setTimeout(loadStats, 5000);
    } catch (err) {
      console.error('Error running OS discovery:', err);
      onError?.('Failed to start OS discovery');
    } finally {
      setRunningDiscovery(false);
    }
  };

  const acknowledgeFailures = async (hostIds?: string[]) => {
    try {
      setLoading(true);
      await api.post('/api/system/os-discovery/acknowledge-failures', {
        host_ids: hostIds || null,
      });
      onSuccess?.('Discovery failures acknowledged');
      await loadStats();
    } catch (err) {
      console.error('Error acknowledging failures:', err);
      onError?.('Failed to acknowledge failures');
    } finally {
      setLoading(false);
    }
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
            <SearchIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            OS Discovery
          </Typography>
          <Chip
            label={config.enabled ? 'SCHEDULED' : 'DISABLED'}
            color={config.enabled ? 'success' : 'default'}
            size="small"
          />
        </Box>
        <Typography variant="body2" color="text.secondary">
          Automatically detect OS family, version, and platform identifier for hosts. Discovery runs
          on host creation and can be scheduled daily.
        </Typography>
      </Box>

      {/* Enable/Disable Toggle */}
      <Box sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Switch checked={config.enabled} onChange={toggleDiscovery} disabled={loading} />
          }
          label="Enable Scheduled Discovery (Daily at 2 AM UTC)"
        />
        <Button
          variant="outlined"
          size="small"
          startIcon={runningDiscovery ? <RefreshIcon /> : <PlayIcon />}
          onClick={runDiscoveryNow}
          disabled={loading || runningDiscovery}
          sx={{ ml: 2 }}
        >
          {runningDiscovery ? 'Running...' : 'Run Now'}
        </Button>
      </Box>

      {/* Discovery Failures */}
      {stats && stats.pending_failures > 0 && (
        <>
          <Divider sx={{ my: 2 }} />
          <Box>
            <Box
              sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}
            >
              <Typography variant="subtitle2" color="error">
                Discovery Failures ({stats.pending_failures})
              </Typography>
              <Button size="small" onClick={() => acknowledgeFailures()} disabled={loading}>
                Acknowledge All
              </Button>
            </Box>
            <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
              {stats.failures.map((failure) => (
                <ListItem key={failure.host_id} divider>
                  <ListItemText
                    primary={`Host: ${failure.host_id.substring(0, 8)}...`}
                    secondary={
                      <>
                        <Typography component="span" variant="caption" color="error">
                          {failure.error_message}
                        </Typography>
                        <br />
                        <Typography component="span" variant="caption" color="text.secondary">
                          {new Date(failure.timestamp).toLocaleString()} - {failure.retry_count}{' '}
                          retries
                        </Typography>
                      </>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Tooltip title="Acknowledge">
                      <IconButton
                        size="small"
                        onClick={() => acknowledgeFailures([failure.host_id])}
                        disabled={loading}
                      >
                        <CheckIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          </Box>
        </>
      )}

      {/* Info Alert */}
      <Alert severity="info" sx={{ mt: 3 }} icon={<InfoIcon />}>
        <Typography variant="body2">
          <strong>How OS Discovery Works:</strong>
          <br />
          1. <strong>On Host Creation:</strong> Automatically detects platform when adding hosts
          with credentials
          <br />
          2. <strong>Scheduled (Daily):</strong> Scans all hosts missing platform data at 2 AM UTC
          <br />
          3. <strong>Just-in-Time:</strong> Detects platform during scan if not already known
          (always enabled)
        </Typography>
      </Alert>
    </Card>
  );
};

export default OSDiscoverySettings;
