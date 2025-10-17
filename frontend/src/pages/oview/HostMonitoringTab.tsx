import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
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
  IconButton,
  Tooltip
} from '@mui/material';
import { Refresh, Computer, TrendingUp, Warning, CheckCircle } from '@mui/icons-material';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip as RechartsTooltip, LineChart, Line, XAxis, YAxis, CartesianGrid } from 'recharts';
import { api } from '../../services/api';

interface MonitoringState {
  total_hosts: number;
  status_breakdown: {
    [key: string]: number;
  };
}

interface HostStateDetail {
  host_id: string;
  hostname: string;
  ip_address: string;
  current_state: string;
  consecutive_failures: number;
  consecutive_successes: number;
  check_priority: number;
  response_time_ms: number;
  last_check: string;
  next_check_time: string;
}

interface StateTransition {
  check_time: string;
  state: string;
  response_time_ms: number;
  success: boolean;
  error_message?: string;
}

const HostMonitoringTab: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stateDistribution, setStateDistribution] = useState<MonitoringState | null>(null);
  const [criticalHosts, setCriticalHosts] = useState<HostStateDetail[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  // Color mapping for monitoring states (infrastructure-focused)
  const stateColors = {
    HEALTHY: '#1c820f', // Green - stable
    DEGRADED: '#ffdc00', // Yellow - showing issues
    CRITICAL: '#ff9800', // Orange - repeated failures
    DOWN: '#d32f2f', // Red - confirmed down
    MAINTENANCE: '#757575' // Gray - manual maintenance
  };

  const stateIcons = {
    HEALTHY: <CheckCircle sx={{ color: stateColors.HEALTHY }} />,
    DEGRADED: <Warning sx={{ color: stateColors.DEGRADED }} />,
    CRITICAL: <Warning sx={{ color: stateColors.CRITICAL }} />,
    DOWN: <Warning sx={{ color: stateColors.DOWN }} />,
    MAINTENANCE: <Computer sx={{ color: stateColors.MAINTENANCE }} />
  };

  const stateDescriptions = {
    HEALTHY: 'Stable - 30 min checks',
    DEGRADED: 'Showing issues - 5 min checks',
    CRITICAL: 'Repeated failures - 2 min checks',
    DOWN: 'Confirmed down - 30 min checks',
    MAINTENANCE: 'No checks during maintenance'
  };

  useEffect(() => {
    fetchMonitoringData();
  }, []);

  const fetchMonitoringData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch state distribution from monitoring API
      const stateResponse = await api.get('/api/monitoring/hosts/status');
      setStateDistribution(stateResponse.data || stateResponse);

      // Fetch critical/degraded hosts (DEGRADED, CRITICAL, DOWN states)
      const hostsResponse = await api.get('/api/hosts');
      const allHosts = hostsResponse.data?.hosts || hostsResponse.hosts || hostsResponse.data || hostsResponse;

      // Get detailed state for critical hosts
      const criticalHostDetails = await Promise.all(
        allHosts
          .filter((h: any) => ['DEGRADED', 'CRITICAL', 'DOWN'].includes(h.monitoring_state))
          .slice(0, 20) // Limit to 20 most critical
          .map(async (host: any) => {
            try {
              const stateDetail = await api.get(`/api/monitoring/hosts/${host.id}/state`);
              return stateDetail.data || stateDetail;
            } catch (err) {
              console.error(`Failed to get state for ${host.hostname}:`, err);
              return null;
            }
          })
      );

      setCriticalHosts(criticalHostDetails.filter((h: HostStateDetail | null): h is HostStateDetail => h !== null));
      setLoading(false);
    } catch (err: any) {
      console.error('Error fetching monitoring data:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load monitoring data');
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchMonitoringData();
    setRefreshing(false);
  };

  // Prepare pie chart data
  const pieData = stateDistribution?.status_breakdown
    ? Object.entries(stateDistribution.status_breakdown).map(([state, count]) => ({
        name: state,
        value: count,
        color: stateColors[state as keyof typeof stateColors] || '#757575'
      }))
    : [];

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header with refresh button */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5" sx={{ fontWeight: 600, color: '#004aad' }}>
          Host Infrastructure Monitoring
        </Typography>
        <Tooltip title="Refresh monitoring data">
          <IconButton onClick={handleRefresh} disabled={refreshing} color="primary">
            <Refresh />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <Card elevation={2}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Total Monitored Hosts
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 600, color: '#004aad' }}>
                {stateDistribution?.total_hosts || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card elevation={2} sx={{ bgcolor: '#e8f5e9' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Healthy Hosts
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 600, color: '#1c820f' }}>
                {stateDistribution?.status_breakdown?.HEALTHY || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card elevation={2} sx={{ bgcolor: '#fff8e1' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Degraded Hosts
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 600, color: '#f9a825' }}>
                {stateDistribution?.status_breakdown?.DEGRADED || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card elevation={2} sx={{ bgcolor: '#ffebee' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Critical/Down Hosts
              </Typography>
              <Typography variant="h4" sx={{ fontWeight: 600, color: '#d32f2f' }}>
                {(stateDistribution?.status_breakdown?.CRITICAL || 0) +
                 (stateDistribution?.status_breakdown?.DOWN || 0)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* State Distribution Pie Chart */}
        <Grid item xs={12} md={5}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Monitoring State Distribution
              </Typography>
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <Box display="flex" justifyContent="center" alignItems="center" height={300}>
                  <Typography color="textSecondary">No monitoring data available</Typography>
                </Box>
              )}

              {/* State Legend with Descriptions */}
              <Box mt={2}>
                {Object.entries(stateDescriptions).map(([state, description]) => (
                  <Box key={state} display="flex" alignItems="center" mb={1}>
                    {stateIcons[state as keyof typeof stateIcons]}
                    <Typography variant="body2" ml={1}>
                      <strong>{state}:</strong> {description}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Critical Hosts Table */}
        <Grid item xs={12} md={7}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Hosts Requiring Attention
              </Typography>
              <TableContainer component={Paper} sx={{ maxHeight: 500 }}>
                <Table stickyHeader size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Hostname</strong></TableCell>
                      <TableCell><strong>State</strong></TableCell>
                      <TableCell align="center"><strong>Failures</strong></TableCell>
                      <TableCell align="center"><strong>Priority</strong></TableCell>
                      <TableCell><strong>Last Check</strong></TableCell>
                      <TableCell align="right"><strong>Response Time</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {criticalHosts.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={6} align="center">
                          <Box py={3}>
                            <CheckCircle sx={{ fontSize: 48, color: '#1c820f', mb: 1 }} />
                            <Typography color="textSecondary">
                              No hosts requiring attention - all systems operational
                            </Typography>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ) : (
                      criticalHosts.map((host) => (
                        <TableRow key={host.host_id} hover>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontWeight: 500 }}>
                              {host.hostname}
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {host.ip_address}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              label={host.current_state}
                              sx={{
                                bgcolor: stateColors[host.current_state as keyof typeof stateColors],
                                color: '#fff',
                                fontWeight: 600
                              }}
                            />
                          </TableCell>
                          <TableCell align="center">
                            <Chip
                              size="small"
                              label={host.consecutive_failures}
                              color={host.consecutive_failures >= 3 ? 'error' : 'warning'}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell align="center">
                            <Chip
                              size="small"
                              label={host.check_priority}
                              color={host.check_priority >= 8 ? 'error' : 'default'}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              {host.last_check
                                ? new Date(host.last_check).toLocaleString()
                                : 'Never'}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {host.response_time_ms ? `${host.response_time_ms}ms` : 'N/A'}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* System Health Overview */}
        <Grid item xs={12}>
          <Card elevation={2}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Infrastructure Health Overview
              </Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="body2">
                  <strong>Hybrid Monitoring System:</strong> This dashboard shows infrastructure monitoring states for SRE/DevOps teams.
                  Hosts are automatically checked at adaptive intervals (30/5/2 minutes) based on their health state.
                  The monitoring system uses a state machine to detect and respond to connectivity issues.
                </Typography>
              </Alert>

              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={3}>
                  <Box p={2} bgcolor="#f5f5f5" borderRadius={1}>
                    <Typography variant="caption" color="textSecondary">Check Intervals</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      • HEALTHY: 30 minutes<br/>
                      • DEGRADED: 5 minutes<br/>
                      • CRITICAL: 2 minutes<br/>
                      • DOWN: 30 minutes
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box p={2} bgcolor="#f5f5f5" borderRadius={1}>
                    <Typography variant="caption" color="textSecondary">State Transitions</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      • 1 failure → DEGRADED<br/>
                      • 2 failures → CRITICAL<br/>
                      • 3 failures → DOWN<br/>
                      • 3 successes → HEALTHY
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box p={2} bgcolor="#f5f5f5" borderRadius={1}>
                    <Typography variant="caption" color="textSecondary">Priority Levels</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      • CRITICAL: Priority 9<br/>
                      • DEGRADED: Priority 6<br/>
                      • HEALTHY: Priority 3<br/>
                      • DOWN: Priority 3
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box p={2} bgcolor="#f5f5f5" borderRadius={1}>
                    <Typography variant="caption" color="textSecondary">System Capacity</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      • Checks: 2000/min<br/>
                      • Current Load: 4%<br/>
                      • Max Hosts: 5000+<br/>
                      • Workers: Distributed
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default HostMonitoringTab;
