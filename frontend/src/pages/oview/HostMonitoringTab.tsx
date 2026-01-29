import React, {
  useState,
  useEffect,
  forwardRef,
  useImperativeHandle,
  useMemo,
  useRef,
  useCallback,
} from 'react';
import {
  Box,
  Card,
  CardContent,
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
  TablePagination,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  Computer,
  Warning,
  CheckCircle,
  Search,
  ErrorOutline,
  Schedule,
  Speed,
  BuildCircle,
} from '@mui/icons-material';
import { api } from '../../services/api';

/**
 * API host response structure from backend
 * Subset of fields needed for host monitoring display
 * Backend returns PostgreSQL naming (snake_case)
 */
interface ApiHostResponse {
  id: string;
  hostname: string;
  ip_address: string;
  status?: string;
  ping_consecutive_failures?: number;
  ssh_consecutive_failures?: number;
  privilege_consecutive_failures?: number;
  ping_consecutive_successes?: number;
  ssh_consecutive_successes?: number;
  privilege_consecutive_successes?: number;
  check_priority?: number;
  response_time_ms?: number | null;
  last_check?: string;
  next_check_time?: string | null;
  updated_at?: string;
}

interface MonitoringState {
  total_hosts: number;
  status_breakdown: {
    [key: string]: number;
  };
  avg_response_time_ms?: number;
  checks_today?: number;
  online_percentage?: number;
}

interface HostStateDetail {
  host_id: string;
  hostname: string;
  ip_address: string;
  current_state: string;
  consecutive_failures: number;
  consecutive_successes: number;
  check_priority: number;
  response_time_ms: number | null;
  last_check: string;
  next_check_time: string | null;
}

export interface HostMonitoringTabRef {
  refresh: () => Promise<void>;
}

interface HostMonitoringTabProps {
  onLastUpdated?: (date: Date) => void;
}

const HostMonitoringTab = forwardRef<HostMonitoringTabRef, HostMonitoringTabProps>(
  ({ onLastUpdated }, ref) => {
    const theme = useTheme();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [stateDistribution, setStateDistribution] = useState<MonitoringState | null>(null);
    const [allHosts, setAllHosts] = useState<HostStateDetail[]>([]);

    // In-flight request guard to prevent overlapping API calls
    const fetchingRef = useRef(false);

    // Mount guard to prevent double-fetch in React StrictMode
    const hasFetchedRef = useRef(false);

    // Use ref to always access latest onLastUpdated without causing re-renders
    const onLastUpdatedRef = useRef(onLastUpdated);
    useEffect(() => {
      onLastUpdatedRef.current = onLastUpdated;
    }, [onLastUpdated]);

    // Pagination
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(25);

    // Filters
    const [searchQuery, setSearchQuery] = useState('');
    const [stateFilter, setStateFilter] = useState('');

    // Color mapping for monitoring states (uses theme colors, works in dark mode)
    // Status values aligned with backend: online, down, unknown, critical, maintenance, degraded
    const stateColors = {
      online: theme.palette.success.main, // Green - fully operational
      degraded: theme.palette.warning.main, // Yellow - permission issues
      critical: '#ff9800', // Orange - partial connectivity
      down: theme.palette.error.main, // Red - completely unavailable
      maintenance: theme.palette.mode === 'light' ? '#757575' : '#9e9e9e', // Gray - planned maintenance
      unknown: theme.palette.grey[500], // Gray - not yet checked
    };

    // State icon mapping - reserved for future tooltip and legend features
    const _stateIcons = {
      online: <CheckCircle sx={{ color: stateColors.online }} />,
      degraded: <Warning sx={{ color: stateColors.degraded }} />,
      critical: <Warning sx={{ color: stateColors.critical }} />,
      down: <Warning sx={{ color: stateColors.down }} />,
      maintenance: <Computer sx={{ color: stateColors.maintenance }} />,
      unknown: <ErrorOutline sx={{ color: stateColors.unknown }} />,
    };

    // State description mapping - reserved for future tooltip and help text features
    const _stateDescriptions = {
      online: 'Can ping AND ssh - fully operational',
      degraded: 'Can ping and ssh, but no elevated privilege',
      critical: 'Can ping but cannot ssh - partial connectivity',
      down: 'No ping, no ssh - completely unavailable',
      maintenance: 'Planned/manual maintenance mode',
      unknown: 'Host added but not yet checked',
    };

    const fetchMonitoringData = useCallback(async () => {
      // CRITICAL: Prevent overlapping API calls
      if (fetchingRef.current) {
        return;
      }

      fetchingRef.current = true;

      try {
        setLoading(true);
        setError(null);

        // Fetch state distribution from monitoring API
        const stateResponse = await api.get<MonitoringState | { data: MonitoringState }>(
          '/api/monitoring/hosts/status'
        );
        const stateData = 'data' in stateResponse ? stateResponse.data : stateResponse;
        setStateDistribution(stateData);

        // Fetch ALL hosts with monitoring state
        interface HostsApiResponse {
          data?: ApiHostResponse[] | { hosts?: ApiHostResponse[] };
          hosts?: ApiHostResponse[];
        }
        const hostsResponse = await api.get<ApiHostResponse[] | HostsApiResponse>('/api/hosts/');
        let hostsData: ApiHostResponse[];
        if (Array.isArray(hostsResponse)) {
          hostsData = hostsResponse;
        } else if ('data' in hostsResponse && hostsResponse.data) {
          hostsData = Array.isArray(hostsResponse.data)
            ? hostsResponse.data
            : (hostsResponse.data as { hosts?: ApiHostResponse[] }).hosts || [];
        } else if ('hosts' in hostsResponse && hostsResponse.hosts) {
          hostsData = hostsResponse.hosts;
        } else {
          hostsData = [];
        }

        // CRITICAL FIX: Use data from /api/hosts/ directly instead of N+1 queries
        // This eliminates 7 additional API calls per refresh!
        const hostDetails: HostStateDetail[] = hostsData.map((host: ApiHostResponse) => ({
          host_id: host.id,
          hostname: host.hostname,
          ip_address: host.ip_address || '',
          current_state: host.status || 'unknown',
          consecutive_failures:
            host.ping_consecutive_failures ||
            host.ssh_consecutive_failures ||
            host.privilege_consecutive_failures ||
            0,
          consecutive_successes:
            host.ping_consecutive_successes ||
            host.ssh_consecutive_successes ||
            host.privilege_consecutive_successes ||
            0,
          check_priority: host.check_priority || 5,
          response_time_ms: host.response_time_ms ?? null,
          last_check: host.last_check || host.updated_at || new Date().toISOString(),
          next_check_time: host.next_check_time ?? null,
        }));

        setAllHosts(hostDetails);

        // Notify parent of update AFTER data is set
        if (onLastUpdatedRef.current) {
          onLastUpdatedRef.current(new Date());
        }
      } catch (err: unknown) {
        console.error('[HostMonitoringTab] Error fetching monitoring data:', err);
        // Type-safe error message extraction - check for axios-like error structure first
        const errorMessage =
          err &&
          typeof err === 'object' &&
          'response' in err &&
          err.response &&
          typeof err.response === 'object' &&
          'data' in err.response &&
          err.response.data &&
          typeof err.response.data === 'object' &&
          'detail' in err.response.data &&
          typeof err.response.data.detail === 'string'
            ? err.response.data.detail
            : err instanceof Error
              ? err.message
              : 'Failed to load monitoring data';
        setError(errorMessage);
      } finally {
        // Always clear the in-flight flag and loading state
        setLoading(false);
        fetchingRef.current = false;
      }
    }, []);

    // Keep ref to latest fetchMonitoringData for useImperativeHandle
    const fetchMonitoringDataRef = useRef(fetchMonitoringData);
    useEffect(() => {
      fetchMonitoringDataRef.current = fetchMonitoringData;
    }, [fetchMonitoringData]);

    // Expose refresh function to parent component
    // CRITICAL: Empty deps array prevents recreation on every render
    // Use ref to always call latest fetchMonitoringData
    useImperativeHandle(
      ref,
      () => ({
        refresh: () => fetchMonitoringDataRef.current(),
      }),
      []
    ); // Empty deps - only create once

    // Load data ONCE on mount only - do NOT depend on fetchMonitoringData!
    // CRITICAL: Guard against React StrictMode double-mounting
    useEffect(() => {
      if (hasFetchedRef.current) {
        return;
      }

      hasFetchedRef.current = true;
      fetchMonitoringData();
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // Empty deps = run once on mount

    // Memoized filtered hosts to prevent unnecessary recalculations
    const filteredHosts = useMemo(() => {
      return allHosts.filter((host) => {
        const matchesSearch =
          !searchQuery ||
          host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
          host.ip_address.toLowerCase().includes(searchQuery.toLowerCase());

        const matchesState = !stateFilter || host.current_state === stateFilter;

        return matchesSearch && matchesState;
      });
    }, [allHosts, searchQuery, stateFilter]);

    // Memoized paginated hosts
    const paginatedHosts = useMemo(() => {
      return filteredHosts.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
    }, [filteredHosts, page, rowsPerPage]);

    // StatCard component (matching Security Audit design)
    const StatCard: React.FC<{
      title: string;
      value: number;
      icon: React.ReactNode;
      color?: string;
      suffix?: string;
    }> = ({ title, value, icon, color = 'primary', suffix = '' }) => (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box>
              <Typography
                variant="h4"
                component="div"
                sx={{ fontWeight: 'bold', color: `${color}.main` }}
              >
                {value.toLocaleString()}
                {suffix && (
                  <Typography
                    component="span"
                    variant="h6"
                    sx={{ ml: 0.5, color: 'text.secondary' }}
                  >
                    {suffix}
                  </Typography>
                )}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {title}
              </Typography>
            </Box>
            <Avatar
              sx={{
                // Type-safe theme palette access - color is validated to be a MUI palette color key
                bgcolor: alpha(
                  (theme.palette as unknown as Record<string, { main?: string }>)[color]?.main ||
                    '#000',
                  0.1
                ),
                color: `${color}.main`,
              }}
            >
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

    // Get monitoring statistics from API response
    const avgResponseTime = stateDistribution?.avg_response_time_ms ?? 0;
    const checksToday = stateDistribution?.checks_today ?? 0;

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
              title="Online"
              value={stateDistribution?.status_breakdown?.online || 0}
              icon={<CheckCircle />}
              color="success"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard
              title="Degraded"
              value={stateDistribution?.status_breakdown?.degraded || 0}
              icon={<Warning />}
              color="warning"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard
              title="Critical"
              value={stateDistribution?.status_breakdown?.critical || 0}
              icon={<ErrorOutline />}
              color="error"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard
              title="Down"
              value={stateDistribution?.status_breakdown?.down || 0}
              icon={<ErrorOutline />}
              color="error"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard
              title="Maintenance"
              value={stateDistribution?.status_breakdown?.maintenance || 0}
              icon={<BuildCircle />}
              color="secondary"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard
              title="Avg Response"
              value={avgResponseTime}
              suffix="ms"
              icon={<Speed />}
              color="info"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <StatCard title="Checks Today" value={checksToday} icon={<Schedule />} color="info" />
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
                  <MenuItem value="online">Online</MenuItem>
                  <MenuItem value="degraded">Degraded</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="down">Down</MenuItem>
                  <MenuItem value="maintenance">Maintenance</MenuItem>
                  <MenuItem value="unknown">Unknown</MenuItem>
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
                  <TableCell>
                    <strong>Hostname</strong>
                  </TableCell>
                  <TableCell>
                    <strong>IP Address</strong>
                  </TableCell>
                  <TableCell>
                    <strong>State</strong>
                  </TableCell>
                  <TableCell align="center">
                    <strong>Failures</strong>
                  </TableCell>
                  <TableCell align="center">
                    <strong>Priority</strong>
                  </TableCell>
                  <TableCell>
                    <strong>Last Check</strong>
                  </TableCell>
                  <TableCell align="right">
                    <strong>Response Time</strong>
                  </TableCell>
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
                            <Typography color="textSecondary">No hosts configured yet</Typography>
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
                            color:
                              host.current_state === 'DEGRADED' && theme.palette.mode === 'light'
                                ? 'rgba(0, 0, 0, 0.87)'
                                : '#fff',
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          size="small"
                          label={host.consecutive_failures}
                          color={
                            host.consecutive_failures >= 3
                              ? 'error'
                              : host.consecutive_failures >= 1
                                ? 'warning'
                                : 'default'
                          }
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
                          {host.last_check ? new Date(host.last_check).toLocaleString() : 'Never'}
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
  }
);

HostMonitoringTab.displayName = 'HostMonitoringTab';

// Wrap in React.memo with custom comparison to prevent unnecessary re-renders from parent
export default React.memo(HostMonitoringTab, (prevProps, nextProps) => {
  return prevProps.onLastUpdated === nextProps.onLastUpdated;
});
