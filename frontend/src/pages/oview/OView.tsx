import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Typography,
  Box,
  Card,
  CardContent,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  InputAdornment,
  Chip,
  IconButton,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
  Avatar,
  useTheme,
  alpha,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Search,
  Security,
  Login,
  Person,
  Computer,
  Scanner,
  Settings,
  Error as ErrorIcon,
  Warning,
  Info,
  Refresh,
  Download,
  Visibility,
  Assessment,
  MonitorHeart,
  Pause,
  PlayArrow,
} from '@mui/icons-material';
import { api } from '../../services/api';
import { useDebounce } from '../../hooks/useDebounce';
import HostMonitoringTab, { type HostMonitoringTabRef } from './HostMonitoringTab';

interface AuditEvent {
  id: number;
  user_id?: number;
  username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address: string;
  user_agent?: string;
  details?: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

interface AuditStats {
  total_events: number;
  login_attempts: number;
  failed_logins: number;
  scan_operations: number;
  admin_actions: number;
  security_events: number;
  unique_users: number;
  unique_ips: number;
}

// WEEK 2 PHASE 2: TabPanel component for tab content
// CRITICAL: Define OUTSIDE OView to prevent recreation on every render
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

// CRITICAL FIX: Keep children mounted but hide with CSS to prevent unmount/remount loops
// Using conditional rendering {value === index && children} causes children to unmount
// when parent re-renders, triggering infinite mount/fetch cycles
// Use React.memo to prevent re-rendering when props haven't changed
const TabPanel = React.memo<TabPanelProps>(({ children, value, index }) => {
  const isVisible = value === index;
  return (
    <div role="tabpanel" aria-hidden={!isVisible} style={{ display: isVisible ? 'block' : 'none' }}>
      <Box sx={{ py: 3 }}>{children}</Box>
    </div>
  );
});
TabPanel.displayName = 'TabPanel';

const OView: React.FC = () => {
  const theme = useTheme();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [_statsLoading, setStatsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // WEEK 2 PHASE 2: Tab state for multi-view dashboard
  const [activeTab, setActiveTab] = useState(0);

  // Ref for Host Monitoring tab to call refresh
  const hostMonitoringRef = useRef<HostMonitoringTabRef>(null);

  // Auto-refresh state
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalEvents, setTotalEvents] = useState(0);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [dateFrom, setDateFrom] = useState<Date | null>(null);
  const [dateTo, setDateTo] = useState<Date | null>(null);
  const [userFilter, setUserFilter] = useState('');

  // Debounced search query to avoid API calls on every keystroke
  const debouncedSearchQuery = useDebounce(searchQuery, 500);

  // Memoized loadAuditEvents to prevent unnecessary re-creations
  const loadAuditEvents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams({
        page: (page + 1).toString(),
        limit: rowsPerPage.toString(),
        ...(debouncedSearchQuery && { search: debouncedSearchQuery }),
        ...(actionFilter && { action: actionFilter }),
        ...(resourceFilter && { resource_type: resourceFilter }),
        ...(severityFilter && { severity: severityFilter }),
        ...(userFilter && { user: userFilter }),
        ...(dateFrom && { date_from: dateFrom.toISOString() }),
        ...(dateTo && { date_to: dateTo.toISOString() }),
      });

      const response = await api.get(`/api/audit/events?${params}`);
      const newEvents = response.events || [];
      setEvents(newEvents);
      setTotalEvents(response.total || 0);
      setLastUpdated(new Date());
    } catch (err: any) {
      setError('Failed to load audit events');
      console.error('Error loading audit events:', err);
    } finally {
      setLoading(false);
    }
  }, [
    page,
    rowsPerPage,
    debouncedSearchQuery,
    actionFilter,
    resourceFilter,
    severityFilter,
    userFilter,
    dateFrom,
    dateTo,
  ]);

  // Memoized loadAuditStats to prevent unnecessary re-creations
  const loadAuditStats = useCallback(async () => {
    try {
      setStatsLoading(true);
      const response = await api.get('/api/audit/stats');
      setStats(response);
    } catch (err: any) {
      console.error('Error loading audit stats:', err);
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Load stats once on mount (they don't change with filters)
  useEffect(() => {
    loadAuditStats();
  }, [loadAuditStats]);

  // Load events when filters change (using debounced search)
  useEffect(() => {
    loadAuditEvents();
  }, [loadAuditEvents]);

  // Ref to always access latest loadAuditEvents function
  const loadAuditEventsRef = useRef(loadAuditEvents);
  const loadAuditStatsRef = useRef(loadAuditStats);

  // Keep refs up to date
  useEffect(() => {
    loadAuditEventsRef.current = loadAuditEvents;
    loadAuditStatsRef.current = loadAuditStats;
  }, [loadAuditEvents, loadAuditStats]);

  // Keep ref to latest activeTab to avoid stale closure in polling interval
  const activeTabRef = useRef(activeTab);
  useEffect(() => {
    activeTabRef.current = activeTab;
  }, [activeTab]);

  // Automatic polling every 30 seconds (ONLY for Security Audit tab)
  // Host Monitoring is manual-refresh only for stability
  useEffect(() => {
    if (!autoRefreshEnabled) return;

    const interval = setInterval(() => {
      const currentTab = activeTabRef.current; // Use ref to get CURRENT tab value
      if (currentTab === 0) {
        // Security Audit tab - refresh events and stats
        loadAuditEventsRef.current();
        loadAuditStatsRef.current();
      }
      // Note: Host Monitoring (tab 1) is excluded from auto-refresh
      // Users must manually click refresh button for Host Monitoring
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [autoRefreshEnabled]); // Remove activeTab from deps - we use ref instead

  const handleRefresh = async () => {
    // Context-aware refresh based on active tab
    if (activeTab === 0) {
      // Security Audit tab - only refresh events (stats don't change often)
      loadAuditEvents();
    } else if (activeTab === 1) {
      // Host Monitoring tab
      await hostMonitoringRef.current?.refresh();
    }
  };

  const toggleAutoRefresh = () => {
    setAutoRefreshEnabled(!autoRefreshEnabled);
  };

  // Memoized callback to prevent infinite re-render loop
  const handleLastUpdated = useCallback((date: Date) => {
    setLastUpdated(date);
  }, []);

  // State to force re-render for "Updated Xs ago" display
  const [, setTick] = useState(0);

  // Update the "Updated Xs ago" display every second
  useEffect(() => {
    const timer = setInterval(() => {
      setTick((t) => t + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Format last updated time
  const formatLastUpdated = () => {
    if (!lastUpdated) return '';
    const secondsAgo = Math.floor((new Date().getTime() - lastUpdated.getTime()) / 1000);
    if (secondsAgo < 60) return `Updated ${secondsAgo}s ago`;
    const minutesAgo = Math.floor(secondsAgo / 60);
    return `Updated ${minutesAgo}m ago`;
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'error':
        return <ErrorIcon color="error" />;
      case 'warning':
        return <Warning color="warning" />;
      case 'info':
      default:
        return <Info color="info" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'error';
      case 'error':
        return 'error';
      case 'warning':
        return 'warning';
      case 'info':
      default:
        return 'info';
    }
  };

  const getActionIcon = (action: string) => {
    if (action.includes('LOGIN')) return <Login />;
    if (action.includes('SCAN')) return <Scanner />;
    if (action.includes('USER')) return <Person />;
    if (action.includes('HOST')) return <Computer />;
    if (action.includes('ADMIN')) return <Settings />;
    return <Security />;
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  // Memoized StatCard to prevent unnecessary re-renders
  const StatCard = React.memo<{
    title: string;
    value: number;
    icon: React.ReactNode;
    color?: string;
  }>(({ title, value, icon, color = 'primary' }) => (
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
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {title}
            </Typography>
          </Box>
          <Avatar
            sx={{
              bgcolor: alpha((theme.palette as any)[color]?.main || '#000', 0.1),
              color: `${color}.main`,
            }}
          >
            {icon}
          </Avatar>
        </Box>
      </CardContent>
    </Card>
  ));
  StatCard.displayName = 'StatCard';

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        {/* WEEK 2 PHASE 2: Updated header with tabbed navigation */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              System Overview
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Security audit, compliance monitoring, and infrastructure visibility
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {lastUpdated && (
              <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
                {formatLastUpdated()}
              </Typography>
            )}
            {activeTab === 1 && (
              <Typography
                variant="caption"
                color="warning.main"
                sx={{ mr: 1, fontStyle: 'italic' }}
              >
                Manual refresh only
              </Typography>
            )}
            {activeTab === 0 && (
              <Tooltip
                title={
                  autoRefreshEnabled
                    ? 'Pause auto-refresh (Security Audit only)'
                    : 'Resume auto-refresh (Security Audit only)'
                }
              >
                <IconButton onClick={toggleAutoRefresh} color="primary" size="small">
                  {autoRefreshEnabled ? <Pause /> : <PlayArrow />}
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Refresh Now">
              <IconButton onClick={handleRefresh} disabled={loading} color="primary">
                <Refresh />
              </IconButton>
            </Tooltip>
            <Tooltip title="Export Report">
              <IconButton color="primary">
                <Download />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* WEEK 2 PHASE 2: Tab navigation */}
        <Paper sx={{ mb: 3 }}>
          <Tabs
            value={activeTab}
            onChange={(_, newValue) => setActiveTab(newValue)}
            indicatorColor="primary"
            textColor="primary"
            variant="fullWidth"
          >
            <Tab
              label="Security Audit"
              icon={<Assessment />}
              iconPosition="start"
              sx={{ textTransform: 'none', fontWeight: 600 }}
            />
            <Tab
              label="Host Monitoring"
              icon={<MonitorHeart />}
              iconPosition="start"
              sx={{ textTransform: 'none', fontWeight: 600 }}
            />
          </Tabs>
        </Paper>

        {/* WEEK 2 PHASE 2: Tab Panel 0 - Security Audit Dashboard (existing content) */}
        <TabPanel value={activeTab} index={0}>
          {/* Original audit dashboard content */}

          {/* Statistics Cards */}
          {stats && (
            <Grid container spacing={3} sx={{ mb: 4 }}>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Total Events"
                  value={stats.total_events}
                  icon={<Security />}
                  color="primary"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Login Attempts"
                  value={stats.login_attempts}
                  icon={<Login />}
                  color="info"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Failed Logins"
                  value={stats.failed_logins}
                  icon={<ErrorIcon />}
                  color="error"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Scan Operations"
                  value={stats.scan_operations}
                  icon={<Scanner />}
                  color="success"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Admin Actions"
                  value={stats.admin_actions}
                  icon={<Settings />}
                  color="warning"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Security Events"
                  value={stats.security_events}
                  icon={<Warning />}
                  color="error"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Unique Users"
                  value={stats.unique_users}
                  icon={<Person />}
                  color="info"
                />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <StatCard
                  title="Unique IPs"
                  value={stats.unique_ips}
                  icon={<Computer />}
                  color="secondary"
                />
              </Grid>
            </Grid>
          )}

          {/* Filters */}
          <Paper sx={{ p: 2, mb: 3 }}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={6} md={3}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search events..."
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
              <Grid item xs={12} sm={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={actionFilter}
                    onChange={(e) => setActionFilter(e.target.value)}
                    label="Action"
                  >
                    <MenuItem value="">All Actions</MenuItem>
                    <MenuItem value="LOGIN">Login</MenuItem>
                    <MenuItem value="SCAN">Scan</MenuItem>
                    <MenuItem value="ADMIN">Admin</MenuItem>
                    <MenuItem value="USER">User</MenuItem>
                    <MenuItem value="HOST">Host</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Resource</InputLabel>
                  <Select
                    value={resourceFilter}
                    onChange={(e) => setResourceFilter(e.target.value)}
                    label="Resource"
                  >
                    <MenuItem value="">All Resources</MenuItem>
                    <MenuItem value="auth">Authentication</MenuItem>
                    <MenuItem value="scan">Scans</MenuItem>
                    <MenuItem value="host">Hosts</MenuItem>
                    <MenuItem value="user">Users</MenuItem>
                    <MenuItem value="system">System</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    label="Severity"
                  >
                    <MenuItem value="">All Severities</MenuItem>
                    <MenuItem value="info">Info</MenuItem>
                    <MenuItem value="warning">Warning</MenuItem>
                    <MenuItem value="error">Error</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Filter by user..."
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                />
              </Grid>
            </Grid>
          </Paper>

          {/* Events Table */}
          <Paper>
            {error && (
              <Alert severity="error" sx={{ m: 2 }}>
                {error}
              </Alert>
            )}

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>IP Address</TableCell>
                    <TableCell>Details</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                        <CircularProgress />
                      </TableCell>
                    </TableRow>
                  ) : events.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                        <Typography color="text.secondary">No audit events found</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    events.map((event) => (
                      <TableRow key={event.id} hover>
                        <TableCell>
                          <Typography variant="body2">
                            {formatTimestamp(event.timestamp)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            icon={getSeverityIcon(event.severity)}
                            label={event.severity.toUpperCase()}
                            color={getSeverityColor(event.severity) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {getActionIcon(event.action)}
                            <Typography variant="body2">{event.action}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{event.username || 'System'}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {event.resource_type}
                            {event.resource_id && (
                              <Typography variant="caption" display="block" color="text.secondary">
                                ID: {event.resource_id}
                              </Typography>
                            )}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {event.ip_address}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}
                          >
                            {event.details || '-'}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Tooltip title="View Details">
                            <IconButton size="small">
                              <Visibility />
                            </IconButton>
                          </Tooltip>
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
              count={totalEvents}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={(_, newPage) => setPage(newPage)}
              onRowsPerPageChange={(e) => {
                setRowsPerPage(parseInt(e.target.value, 10));
                setPage(0);
              }}
            />
          </Paper>
        </TabPanel>

        {/* WEEK 2 PHASE 2: Tab Panel 1 - Host Monitoring (NEW) */}
        <TabPanel value={activeTab} index={1}>
          <HostMonitoringTab ref={hostMonitoringRef} onLastUpdated={handleLastUpdated} />
        </TabPanel>
      </Box>
    </Box>
  );
};

export default OView;
