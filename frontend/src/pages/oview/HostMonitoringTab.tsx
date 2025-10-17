import React, { useState, useEffect, forwardRef, useImperativeHandle } from 'react';
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
  useTheme,
  Avatar,
  alpha,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TablePagination
} from '@mui/material';
import {
  Computer,
  Warning,
  CheckCircle,
  Search,
  HealthAndSafety,
  ErrorOutline,
  Schedule,
  Speed,
  BuildCircle
} from '@mui/icons-material';
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

export interface HostMonitoringTabRef {
  refresh: () => Promise<void>;
}

const HostMonitoringTab = forwardRef<HostMonitoringTabRef>((props, ref) => {
  const theme = useTheme();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stateDistribution, setStateDistribution] = useState<MonitoringState | null>(null);
  const [allHosts, setAllHosts] = useState<HostStateDetail[]>([]);

  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [stateFilter, setStateFilter] = useState('');

  // Color mapping for monitoring states (uses theme colors, works in dark mode)
  const stateColors = {
    HEALTHY: theme.palette.success.main, // Green - stable
    DEGRADED: theme.palette.warning.main, // Yellow - showing issues
    CRITICAL: '#ff9800', // Orange - repeated failures
    DOWN: theme.palette.error.main, // Red - confirmed down
    MAINTENANCE: theme.palette.mode === 'light' ? '#757575' : '#9e9e9e' // Gray - manual maintenance
  };

  const stateIcons = {
    HEALTHY: <CheckCircle sx={{ color: stateColors.HEALTHY }} />,
    DEGRADED: <Warning sx={{ color: stateColors.DEGRADED }} />,
    CRITICAL: <Warning sx={{ color: stateColors.CRITICAL }} />,
    DOWN: <Warning sx={{ color: stateColors.DOWN }} />,
    MAINTENANCE: <Computer sx={{ color: stateColors.MAINTENANCE }} />
  };

  const stateDescriptions = {
    HEALTHY: 'No connection issues - checked every 30 minutes',
    DEGRADED: '1 recent failure - checked every 5 minutes',
    CRITICAL: '2+ failures - checked every 2 minutes',
    DOWN: 'Host unreachable - checked every 30 minutes',
    MAINTENANCE: 'Scheduled maintenance - monitoring paused'
  };

  const fetchMonitoringData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch state distribution from monitoring API
      const stateResponse = await api.get('/api/monitoring/hosts/status');
      setStateDistribution(stateResponse.data || stateResponse);

      // Fetch ALL hosts with monitoring state
      const hostsResponse = await api.get('/api/hosts/');
      const hostsData = hostsResponse.data?.hosts || hostsResponse.hosts || hostsResponse.data || hostsResponse;

      // Get detailed state for ALL hosts (not just critical)
      const hostDetails = await Promise.all(
        hostsData.map(async (host: any) => {
          try {
            const stateDetail = await api.get(`/api/monitoring/hosts/${host.id}/state`);
            return stateDetail.data || stateDetail;
          } catch (err) {
            console.error(`Failed to get state for ${host.hostname}:`, err);
            // Return basic info if detailed state fails
            return {
              host_id: host.id,
              hostname: host.hostname,
              ip_address: host.ip_address,
              current_state: host.monitoring_state || 'UNKNOWN',
              consecutive_failures: 0,
              consecutive_successes: 0,
              check_priority: 3,
              response_time_ms: null,
              last_check: host.updated_at,
              next_check_time: null
            };
          }
        })
      );

      setAllHosts(hostDetails.filter((h: HostStateDetail | null): h is HostStateDetail => h !== null));
      setLoading(false);
    } catch (err: any) {
      console.error('Error fetching monitoring data:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load monitoring data');
      setLoading(false);
    }
  };

  // Expose refresh function to parent component
  useImperativeHandle(ref, () => ({
    refresh: fetchMonitoringData
  }));

  // Load data on mount
  useEffect(() => {
    fetchMonitoringData();
  }, []);

  // Filter hosts based on search and state filter
  const filteredHosts = allHosts.filter(host => {
    const matchesSearch =
      !searchQuery ||
      host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      host.ip_address.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesState = !stateFilter || host.current_state === stateFilter;

    return matchesSearch && matchesState;
  });

  // Paginated hosts
  const paginatedHosts = filteredHosts.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // StatCard component (matching Security Audit design)
  const StatCard: React.FC<{ title: string; value: number; icon: React.ReactNode; color?: string }> = ({
    title, value, icon, color = 'primary'
  }) => (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h4" component="div" sx={{ fontWeight: 'bold', color: `${color}.main` }}>
              {value.toLocaleString()}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {title}
            </Typography>
          </Box>
          <Avatar sx={{ bgcolor: alpha((theme.palette as any)[color]?.main || '#000', 0.1), color: `${color}.main` }}>
            {icon}
          </Avatar>
        </Box>
      </CardContent>
    </Card>
  );

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

  // Calculate avg response time
  const avgResponseTime = allHosts.length > 0
    ? Math.round(allHosts.reduce((sum, h) => sum + (h.response_time_ms || 0), 0) / allHosts.length)
    : 0;

  // Calculate checks performed (estimate based on hosts and check intervals)
  const checksToday = allHosts.length * 48; // Rough estimate: each host ~48 checks/day

  return (
    <Box sx={{ p: 3 }}>
      {/* Statistics Cards - 8 cards matching Security Audit */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Hosts"
            value={stateDistribution?.total_hosts || 0}
            icon={<Computer />}
            color="primary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Healthy"
            value={stateDistribution?.status_breakdown?.HEALTHY || 0}
            icon={<CheckCircle />}
            color="success"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Degraded"
            value={stateDistribution?.status_breakdown?.DEGRADED || 0}
            icon={<Warning />}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical"
            value={stateDistribution?.status_breakdown?.CRITICAL || 0}
            icon={<ErrorOutline />}
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Down"
            value={stateDistribution?.status_breakdown?.DOWN || 0}
            icon={<ErrorOutline />}
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Maintenance"
            value={stateDistribution?.status_breakdown?.MAINTENANCE || 0}
            icon={<BuildCircle />}
            color="secondary"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Avg Response"
            value={avgResponseTime}
            icon={<Speed />}
            color="info"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Checks Today"
            value={checksToday}
            icon={<Schedule />}
            color="info"
          />
        </Grid>
      </Grid>

      {/* Filters Section - matching Security Audit */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              size="small"
              placeholder="Search hosts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Search />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>State</InputLabel>
              <Select
                value={stateFilter}
                onChange={(e) => setStateFilter(e.target.value)}
                label="State"
              >
                <MenuItem value="">All States</MenuItem>
                <MenuItem value="HEALTHY">Healthy</MenuItem>
                <MenuItem value="DEGRADED">Degraded</MenuItem>
                <MenuItem value="CRITICAL">Critical</MenuItem>
                <MenuItem value="DOWN">Down</MenuItem>
                <MenuItem value="MAINTENANCE">Maintenance</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* All Hosts Table - matching Security Audit */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell><strong>Hostname</strong></TableCell>
                <TableCell><strong>IP Address</strong></TableCell>
                <TableCell><strong>State</strong></TableCell>
                <TableCell align="center"><strong>Failures</strong></TableCell>
                <TableCell align="center"><strong>Priority</strong></TableCell>
                <TableCell><strong>Last Check</strong></TableCell>
                <TableCell align="right"><strong>Response Time</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedHosts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Box py={3}>
                      {searchQuery || stateFilter ? (
                        <>
                          <Search sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                          <Typography color="textSecondary">
                            No hosts match your filters
                          </Typography>
                        </>
                      ) : (
                        <>
                          <CheckCircle sx={{ fontSize: 48, color: 'success.main', mb: 1 }} />
                          <Typography color="textSecondary">
                            No hosts configured yet
                          </Typography>
                        </>
                      )}
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedHosts.map((host) => (
                  <TableRow key={host.host_id} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {host.hostname}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="textSecondary">
                        {host.ip_address}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={host.current_state}
                        sx={{
                          bgcolor: stateColors[host.current_state as keyof typeof stateColors],
                          color: host.current_state === 'DEGRADED' && theme.palette.mode === 'light' ? 'rgba(0, 0, 0, 0.87)' : '#fff',
                          fontWeight: 600
                        }}
                      />
                    </TableCell>
                    <TableCell align="center">
                      <Chip
                        size="small"
                        label={host.consecutive_failures}
                        color={host.consecutive_failures >= 3 ? 'error' : host.consecutive_failures >= 1 ? 'warning' : 'default'}
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

        <TablePagination
          rowsPerPageOptions={[10, 25, 50, 100]}
          component="div"
          count={filteredHosts.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
        />
      </Paper>
    </Box>
  );
});

HostMonitoringTab.displayName = 'HostMonitoringTab';

export default HostMonitoringTab;
