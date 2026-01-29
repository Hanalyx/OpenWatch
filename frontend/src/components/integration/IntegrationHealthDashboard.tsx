import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Alert,
  Button,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  Divider,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
  Speed as SpeedIcon,
  Timeline as TimelineIcon,
  Api as ApiIcon,
} from '@mui/icons-material';

interface HealthMetrics {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  timestamp: string;
  metrics: {
    total_operations_1h: number;
    error_rate_1h: number;
    recent_errors: number;
    active_metrics: number;
  };
  top_operations: Record<string, number>;
}

interface PerformanceData {
  timestamp: string;
  performance_data: Record<
    string,
    {
      last_hour: {
        requests: number;
        error_rate: number;
        avg_duration_ms: number;
        p95_duration_ms: number;
      };
      last_24h: {
        requests: number;
        error_rate: number;
        avg_duration_ms: number;
        p95_duration_ms: number;
      };
      trends?: {
        error_rate_trend: 'up' | 'down' | 'stable';
        performance_trend: 'better' | 'worse' | 'stable';
      };
    }
  >;
  summary: {
    total_operations_1h: number;
    total_operations_24h: number;
    avg_error_rate_1h: number;
    avg_error_rate_24h: number;
  };
}

const IntegrationHealthDashboard: React.FC = () => {
  const [healthMetrics, setHealthMetrics] = useState<HealthMetrics | null>(null);
  const [performanceData, setPerformanceData] = useState<PerformanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [_refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);

  const fetchHealthMetrics = async () => {
    try {
      const response = await fetch('/api/integration/metrics/health');
      if (!response.ok) {
        throw new Error('Failed to fetch health metrics');
      }
      const data = await response.json();
      setHealthMetrics(data);
    } catch (err) {
      console.error('Error fetching health metrics:', err);
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  };

  const fetchPerformanceData = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await fetch('/api/integration/metrics/performance', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!response.ok) {
        throw new Error('Failed to fetch performance data');
      }
      const data = await response.json();
      setPerformanceData(data);
    } catch (err) {
      console.error('Error fetching performance data:', err);
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  };

  const refreshData = async () => {
    setLoading(true);
    setError(null);
    try {
      await Promise.all([fetchHealthMetrics(), fetchPerformanceData()]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshData();

    // Set up auto-refresh every 30 seconds
    const interval = setInterval(refreshData, 30000);
    setRefreshInterval(interval);

    return () => {
      if (interval) clearInterval(interval);
    };
    // ESLint disable: refreshData function is not memoized to avoid complex dependency chain
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'unhealthy':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon />;
      case 'degraded':
        return <WarningIcon />;
      case 'unhealthy':
        return <ErrorIcon />;
      default:
        return <ErrorIcon />;
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up':
      case 'worse':
        return <TrendingUpIcon color="error" />;
      case 'down':
      case 'better':
        return <TrendingDownIcon color="success" />;
      default:
        return <TrendingFlatIcon color="info" />;
    }
  };

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  if (loading && !healthMetrics) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
        <Typography variant="h6" ml={2}>
          Loading integration health data...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Integration Health Dashboard
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={refreshData}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Error loading dashboard data: {error}
        </Alert>
      )}

      {/* Overall Health Status */}
      {healthMetrics && (
        <Grid container spacing={3} mb={4}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  {getStatusIcon(healthMetrics.status)}
                  <Typography variant="h6" ml={1}>
                    Overall Status
                  </Typography>
                </Box>
                <Chip
                  label={healthMetrics.status.toUpperCase()}
                  color={getStatusColor(healthMetrics.status)}
                  sx={{ mt: 1 }}
                />
                <Typography variant="caption" display="block" mt={1}>
                  Last updated: {new Date(healthMetrics.timestamp).toLocaleTimeString()}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <ApiIcon />
                  <Typography variant="h6" ml={1}>
                    Operations (1h)
                  </Typography>
                </Box>
                <Typography variant="h4">{healthMetrics.metrics.total_operations_1h}</Typography>
                <Typography variant="caption">
                  Active metrics: {healthMetrics.metrics.active_metrics}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <ErrorIcon
                    color={healthMetrics.metrics.error_rate_1h > 5 ? 'error' : 'inherit'}
                  />
                  <Typography variant="h6" ml={1}>
                    Error Rate (1h)
                  </Typography>
                </Box>
                <Typography variant="h4">
                  {healthMetrics.metrics.error_rate_1h.toFixed(2)}%
                </Typography>
                <Typography variant="caption">
                  Recent errors: {healthMetrics.metrics.recent_errors}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <TimelineIcon />
                  <Typography variant="h6" ml={1}>
                    Top Operation
                  </Typography>
                </Box>
                {Object.entries(healthMetrics.top_operations).length > 0 ? (
                  <>
                    <Typography variant="h6" noWrap>
                      {Object.keys(healthMetrics.top_operations)[0]}
                    </Typography>
                    <Typography variant="caption">
                      {Object.values(healthMetrics.top_operations)[0]} requests
                    </Typography>
                  </>
                ) : (
                  <Typography variant="body2" color="textSecondary">
                    No recent operations
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Performance Details */}
      {performanceData && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Operation Performance Overview
                </Typography>

                <TableContainer component={Paper} elevation={0}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Operation</TableCell>
                        <TableCell align="right">1h Requests</TableCell>
                        <TableCell align="right">1h Error Rate</TableCell>
                        <TableCell align="right">1h Avg Duration</TableCell>
                        <TableCell align="right">24h Requests</TableCell>
                        <TableCell align="center">Trends</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.entries(performanceData.performance_data).map(([operation, data]) => (
                        <TableRow key={operation}>
                          <TableCell component="th" scope="row">
                            <Typography variant="body2" fontWeight="medium">
                              {operation.replace(/_/g, ' ')}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">{data.last_hour.requests}</TableCell>
                          <TableCell align="right">
                            <Chip
                              label={`${data.last_hour.error_rate.toFixed(1)}%`}
                              color={
                                data.last_hour.error_rate > 5
                                  ? 'error'
                                  : data.last_hour.error_rate > 1
                                    ? 'warning'
                                    : 'success'
                              }
                              size="small"
                            />
                          </TableCell>
                          <TableCell align="right">
                            {formatDuration(data.last_hour.avg_duration_ms)}
                          </TableCell>
                          <TableCell align="right">{data.last_24h.requests}</TableCell>
                          <TableCell align="center">
                            <Box display="flex" justifyContent="center" gap={1}>
                              {data.trends && (
                                <>
                                  <Tooltip
                                    title={`Error rate trend: ${data.trends.error_rate_trend}`}
                                  >
                                    {getTrendIcon(data.trends.error_rate_trend)}
                                  </Tooltip>
                                  <Tooltip
                                    title={`Performance trend: ${data.trends.performance_trend}`}
                                  >
                                    <SpeedIcon
                                      color={
                                        data.trends.performance_trend === 'better'
                                          ? 'success'
                                          : data.trends.performance_trend === 'worse'
                                            ? 'error'
                                            : 'inherit'
                                      }
                                    />
                                  </Tooltip>
                                </>
                              )}
                            </Box>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                <Divider sx={{ my: 3 }} />

                <Typography variant="h6" gutterBottom>
                  Summary Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3}>
                    <Paper elevation={1} sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {performanceData.summary.total_operations_1h}
                      </Typography>
                      <Typography variant="caption">Total Operations (1h)</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper elevation={1} sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {performanceData.summary.total_operations_24h}
                      </Typography>
                      <Typography variant="caption">Total Operations (24h)</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper elevation={1} sx={{ p: 2, textAlign: 'center' }}>
                      <Typography
                        variant="h4"
                        color={performanceData.summary.avg_error_rate_1h > 5 ? 'error' : 'primary'}
                      >
                        {performanceData.summary.avg_error_rate_1h.toFixed(2)}%
                      </Typography>
                      <Typography variant="caption">Avg Error Rate (1h)</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper elevation={1} sx={{ p: 2, textAlign: 'center' }}>
                      <Typography
                        variant="h4"
                        color={performanceData.summary.avg_error_rate_24h > 5 ? 'error' : 'primary'}
                      >
                        {performanceData.summary.avg_error_rate_24h.toFixed(2)}%
                      </Typography>
                      <Typography variant="caption">Avg Error Rate (24h)</Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {!healthMetrics && !performanceData && !loading && (
        <Alert severity="info">
          No integration health data available. Make sure the integration metrics service is
          running.
        </Alert>
      )}
    </Box>
  );
};

export default IntegrationHealthDashboard;
