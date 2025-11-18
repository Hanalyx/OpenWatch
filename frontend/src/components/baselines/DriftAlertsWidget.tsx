/**
 * Drift Alerts Widget
 *
 * Dashboard widget showing recent compliance drift events.
 * Displays hosts with significant compliance drift requiring attention.
 *
 * Features:
 * - Recent drift events (last 7 scans)
 * - Severity-based prioritization (major > minor > improvement)
 * - Quick navigation to host details
 * - Visual drift indicators
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Typography,
  List,
  ListItemText,
  ListItemButton,
  Alert,
  CircularProgress,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Refresh as RefreshIcon,
  ArrowForward as ArrowForwardIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import DriftIndicator from './DriftIndicator';

interface DriftEvent {
  id: string;
  host_id: string;
  hostname: string;
  scan_id: string;
  drift_type: 'major' | 'minor' | 'improvement' | 'stable';
  drift_magnitude: number;
  baseline_score: number;
  current_score: number;
  score_delta: number;
  detected_at: string;
}

interface DriftAlertsWidgetProps {
  limit?: number;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

const DriftAlertsWidget: React.FC<DriftAlertsWidgetProps> = ({
  limit = 5,
  autoRefresh = false,
  refreshInterval = 30000,
}) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState<boolean>(true);
  const [driftEvents, setDriftEvents] = useState<DriftEvent[]>([]);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    // Small delay to allow auto-login to complete on first mount
    const initialFetchTimeout = setTimeout(() => {
      fetchDriftEvents();
    }, 500);

    if (autoRefresh) {
      const interval = setInterval(fetchDriftEvents, refreshInterval);
      return () => {
        clearInterval(interval);
        clearTimeout(initialFetchTimeout);
      };
    }

    return () => clearTimeout(initialFetchTimeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, refreshInterval]);

  const fetchDriftEvents = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await api.get<{
        drift_events: DriftEvent[];
        total: number;
        page: number;
        per_page: number;
        total_pages: number;
      }>('/api/drift-events', {
        params: {
          limit,
          exclude_stable: true,
        },
      });

      const events = response.drift_events || [];

      const sortedEvents = events.sort((a: DriftEvent, b: DriftEvent) => {
        const severityOrder = { major: 3, minor: 2, improvement: 1, stable: 0 };
        const severityDiff = severityOrder[b.drift_type] - severityOrder[a.drift_type];

        if (severityDiff !== 0) {
          return severityDiff;
        }

        return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime();
      });

      setDriftEvents(sortedEvents);
    } catch (err: unknown) {
      console.error('Drift events fetch error:', err);
      const error = err as {
        response?: { status?: number; data?: { detail?: string } };
        message?: string;
      };

      // Handle authentication errors specially
      if (error.response?.status === 401) {
        // eslint-disable-next-line no-console
        console.log('Authentication required, will retry on next refresh');
        // Don't show error for auth issues - auto-login will handle it
        setDriftEvents([]);
      } else {
        const errorMessage =
          error.response?.data?.detail || error.message || 'Failed to fetch drift events';
        setError(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleNavigateToHost = (hostId: string) => {
    navigate(`/hosts/${hostId}`);
  };

  const getTimeAgo = (timestamp: string): string => {
    const now = new Date().getTime();
    const eventTime = new Date(timestamp).getTime();
    const diffMinutes = Math.floor((now - eventTime) / 1000 / 60);

    if (diffMinutes < 60) {
      return `${diffMinutes}m ago`;
    }

    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) {
      return `${diffHours}h ago`;
    }

    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  return (
    <Card>
      <CardHeader
        title={
          <Box display="flex" alignItems="center" gap={1}>
            <WarningIcon color="warning" />
            <Typography variant="h6">Compliance Drift Alerts</Typography>
          </Box>
        }
        action={
          <Tooltip title="Refresh">
            <span>
              <IconButton onClick={fetchDriftEvents} disabled={loading}>
                <RefreshIcon />
              </IconButton>
            </span>
          </Tooltip>
        }
      />
      <Divider />
      <CardContent sx={{ p: 0 }}>
        {error && (
          <Alert severity="error" sx={{ m: 2 }}>
            {error}
          </Alert>
        )}

        {loading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : driftEvents.length === 0 ? (
          <Box textAlign="center" py={4}>
            <TrendingUpIcon sx={{ fontSize: 48, color: 'success.main', mb: 1 }} />
            <Typography variant="body2" color="text.secondary">
              No recent compliance drift detected
            </Typography>
            <Typography variant="caption" color="text.secondary">
              All hosts are maintaining stable compliance
            </Typography>
          </Box>
        ) : (
          <List disablePadding>
            {driftEvents.map((event, index) => (
              <React.Fragment key={event.id}>
                {index > 0 && <Divider />}
                <ListItemButton onClick={() => handleNavigateToHost(event.host_id)}>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1} mb={0.5}>
                        <Typography variant="body2" fontWeight="bold">
                          {event.hostname}
                        </Typography>
                        <DriftIndicator
                          driftType={event.drift_type}
                          scoreDelta={event.score_delta}
                          baselineScore={event.baseline_score}
                          currentScore={event.current_score}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="caption" color="text.secondary">
                          {event.baseline_score.toFixed(1)}% → {event.current_score.toFixed(1)}%
                          {' • '}
                          {getTimeAgo(event.detected_at)}
                        </Typography>
                      </Box>
                    }
                  />
                  <IconButton edge="end" size="small">
                    <ArrowForwardIcon fontSize="small" />
                  </IconButton>
                </ListItemButton>
              </React.Fragment>
            ))}
          </List>
        )}
      </CardContent>
    </Card>
  );
};

export default DriftAlertsWidget;
