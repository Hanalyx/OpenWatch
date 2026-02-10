import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  ArrowBack as ArrowBackIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkCheckIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Visibility as VisibilityIcon,
  Schedule as ScheduleIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Settings as SettingsIcon,
  Terminal as TerminalIcon,
} from '@mui/icons-material';
import { StatusChip, ComplianceRing, SSHKeyDisplay } from '../../components/design-system';
import type { StatusType } from '../../components/design-system/StatusChip';
import HostTerminal from '../../components/terminal/HostTerminal';
import ComplianceTrendChart from '../../components/baselines/ComplianceTrendChart';
import { api } from '../../services/api';
import { owcaService, type ComplianceScore as OWCAScore } from '../../services/owcaService';

interface Host {
  id: string;
  hostname: string;
  display_name: string;
  ip_address: string;
  operating_system: string;
  status: string;
  port: number;
  username: string;
  auth_method: string;
  created_at: string;
  updated_at: string;
  last_check: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  // Additional scan summary fields
  compliance_score?: number;
  latest_scan_id?: string;
  latest_scan_name?: string;
  scan_status?: string;
  scan_progress?: number;
  failed_rules?: number;
  passed_rules?: number;
  critical_issues?: number;
  high_issues?: number;
  medium_issues?: number;
  low_issues?: number;
  total_rules?: number;
  last_scan?: string;
}

interface Scan {
  id: string;
  name: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at: string;
  content_name: string;
  profile_id: string;
  results?: {
    total_rules: number;
    passed_rules: number;
    failed_rules: number;
    error_rules: number;
    score: string;
    severity_high: number;
    severity_medium: number;
    severity_low: number;
  };
}

interface ComplianceFinding {
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  detail: string | null;
  framework_section: string | null;
}

interface ComplianceState {
  host_id: string;
  hostname: string;
  scan_id: string | null;
  scan_date: string | null;
  total_rules: number;
  passed: number;
  failed: number;
  unknown: number;
  compliance_score: number;
  findings: ComplianceFinding[];
  severity_summary: {
    critical: { passed: number; failed: number };
    high: { passed: number; failed: number };
    medium: { passed: number; failed: number };
    low: { passed: number; failed: number };
  };
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`host-tabpanel-${index}`}
      aria-labelledby={`host-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const HostDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [host, setHost] = useState<Host | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [deletingSSHKey, setDeletingSSHKey] = useState(false);
  const [_owcaScore, setOwcaScore] = useState<OWCAScore | null>(null);
  const [complianceState, setComplianceState] = useState<ComplianceState | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(true);
  const [findingsFilter, setFindingsFilter] = useState<'all' | 'pass' | 'fail'>('all');
  const [findingsSearch, _setFindingsSearch] = useState('');

  // Fetch host data when component mounts or id changes
  // ESLint disable: Functions are not memoized to avoid complex dependency chain
  useEffect(() => {
    fetchHostDetails();
    fetchHostScans();
    // Fetch OWCA compliance score (canonical source for compliance calculations)
    fetchOWCAScore();
    // Also try to get enhanced host data from hosts list
    fetchEnhancedHostData();
    // Fetch Aegis compliance state
    fetchComplianceState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const fetchComplianceState = async () => {
    if (!id) return;
    setComplianceLoading(true);
    try {
      const data = await api.get<ComplianceState>(`/api/scans/aegis/compliance-state/${id}`);
      setComplianceState(data);
    } catch (error) {
      console.warn('Aegis compliance state not available:', error);
      setComplianceState(null);
    } finally {
      setComplianceLoading(false);
    }
  };

  const fetchEnhancedHostData = async () => {
    try {
      const hosts = await api.get<Host[]>('/api/hosts/');
      // Type-safe host lookup using existing Host interface which includes enhanced scan fields
      const enhancedHost = hosts.find((h: Host) => h.id === id);
      if (enhancedHost) {
        // Found enhanced host data including latest scan information
        // Update host with enhanced data
        setHost((prevHost) => ({
          ...prevHost,
          ...enhancedHost,
        }));

        // Check if host has associated scan data for display
        void enhancedHost.latest_scan_id; // Available for UI rendering
      }
    } catch (error) {
      console.error('Error fetching enhanced host data:', error);
    }
  };

  const fetchHostDetails = async () => {
    try {
      const hostData = await api.get<Host>(`/api/hosts/${id}`);
      setHost(hostData);
    } catch (error) {
      console.error('Error fetching host details:', error);
      setError('Failed to load host details');
    }
  };

  const fetchHostScans = async () => {
    try {
      // Use trailing slash to avoid redirect
      const data = await api.get<{ scans: Scan[] }>(`/api/scans/?host_id=${id}`);
      // Retrieved scan history for host display
      setScans(data.scans || []);
    } catch (error) {
      console.error('Error fetching host scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchOWCAScore = async () => {
    /**
     * Fetch OWCA compliance score for this host
     *
     * OWCA provides canonical compliance calculations including:
     * - Overall compliance percentage (0-100)
     * - Compliance tier classification (excellent/good/fair/poor)
     * - Severity breakdown (critical/high/medium/low passed/failed counts)
     * - Timestamp of calculation
     *
     * This is the single source of truth for compliance data.
     * Fallback to scan-based compliance if OWCA unavailable.
     */
    try {
      if (!id) return;

      const score = await owcaService.getHostComplianceScore(id);
      setOwcaScore(score);

      // Update host state with OWCA compliance data if available
      if (score && host) {
        setHost((prevHost) => ({
          ...prevHost!,
          compliance_score: score.overall_score,
          critical_issues: score.severity_breakdown.critical_failed,
          high_issues: score.severity_breakdown.high_failed,
          medium_issues: score.severity_breakdown.medium_failed,
          low_issues: score.severity_breakdown.low_failed,
          passed_rules: score.passed_rules,
          failed_rules: score.failed_rules,
          total_rules: score.total_rules,
        }));
      }
    } catch (error) {
      console.warn('OWCA compliance score not available, using scan-based compliance:', error);
      // Gracefully degrade to scan-based compliance data
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon color="success" />;
      case 'running':
        return <CircularProgress size={16} />;
      case 'failed':
        return <ErrorIcon color="error" />;
      case 'pending':
        return <ScheduleIcon color="warning" />;
      default:
        return <InfoIcon />;
    }
  };

  const getComplianceScore = (scan: Scan): number | null => {
    if (scan.results?.score) {
      const score = parseFloat(scan.results.score.replace('%', ''));
      return isNaN(score) ? null : score;
    }
    return null;
  };

  const getAuthMethodDisplay = (authMethod: string) => {
    switch (authMethod) {
      case 'system_default':
      case 'default':
        return {
          label: 'System Default',
          icon: <SettingsIcon fontSize="small" />,
          description: 'Uses system default SSH credentials',
        };
      case 'ssh_key':
        return {
          label: 'SSH Key',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Host-specific SSH key authentication',
        };
      case 'password':
        return {
          label: 'Password',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Host-specific password authentication',
        };
      case 'both':
        return {
          label: 'Password + SSH Key',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Both password and SSH key authentication',
        };
      default:
        return {
          label: authMethod,
          icon: <SecurityIcon fontSize="small" />,
          description: 'Custom authentication method',
        };
    }
  };

  const handleDeleteSSHKey = async () => {
    if (!host) return;

    setDeletingSSHKey(true);
    try {
      await api.delete(`/api/hosts/${host.id}/ssh-key`);

      // Update host state to remove SSH key metadata
      setHost((prev) =>
        prev
          ? {
              ...prev,
              ssh_key_fingerprint: undefined,
              ssh_key_type: undefined,
              ssh_key_bits: undefined,
              ssh_key_comment: undefined,
            }
          : null
      );
    } catch (error) {
      console.error('Error deleting SSH key:', error);
      setError('Error deleting SSH key');
    } finally {
      setDeletingSSHKey(false);
    }
  };

  if (loading) {
    return (
      <Container>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  if (error || !host) {
    return (
      <Container>
        <Alert severity="error" sx={{ mt: 2 }}>
          {error || 'Host not found'}
        </Alert>
      </Container>
    );
  }

  const latestScan = scans.length > 0 ? scans[0] : null;
  const runningScan = scans.find((scan) => scan.status === 'running' || scan.status === 'pending');

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <IconButton onClick={() => navigate('/hosts')} sx={{ mr: 2 }}>
          <ArrowBackIcon />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" component="h1">
            {host.display_name || host.hostname}
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            {host.hostname} • {host.ip_address}
          </Typography>
        </Box>
        {/* Manual scan buttons removed - compliance scans run automatically */}
        <StatusChip
          status={
            host.status === 'online' ? 'online' : host.status === 'offline' ? 'offline' : 'unknown'
          }
          label={host.status || 'Unknown'}
        />
      </Box>

      {/* Host Overview Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <ComputerIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">System</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Operating System
              </Typography>
              <Typography variant="body1">{host.operating_system}</Typography>
              <Box sx={{ mt: 2 }}>
                {/* Type-safe status prop - host.status matches StatusType union */}
                <StatusChip status={host.status as StatusType} size="small" />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <NetworkCheckIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Connectivity</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                SSH Connection
              </Typography>
              <Typography variant="body1">
                {host.username}@{host.hostname}:{host.port}
              </Typography>
              <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                {getAuthMethodDisplay(host.auth_method).icon}
                <Box>
                  <Typography variant="body2" fontWeight="medium">
                    {getAuthMethodDisplay(host.auth_method).label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {getAuthMethodDisplay(host.auth_method).description}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SecurityIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Compliance</Typography>
              </Box>
              {latestScan && getComplianceScore(latestScan) !== null ? (
                <ComplianceRing
                  score={getComplianceScore(latestScan)!}
                  size="medium"
                  trend="stable"
                />
              ) : host.compliance_score !== undefined && host.compliance_score !== null ? (
                <ComplianceRing score={host.compliance_score} size="medium" trend="stable" />
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No compliance data available
                </Typography>
              )}
              {host.critical_issues !== undefined && host.critical_issues > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Chip label={`${host.critical_issues} Critical`} size="small" color="error" />
                  {host.high_issues !== undefined && host.high_issues > 0 && (
                    <Chip
                      label={`${host.high_issues} High`}
                      size="small"
                      color="warning"
                      sx={{ ml: 1 }}
                    />
                  )}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <AssessmentIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Scans</Typography>
              </Box>
              <Typography variant="h4" color="primary">
                {scans.length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total scans performed
              </Typography>
              {runningScan && (
                <Box sx={{ mt: 1 }}>
                  <Chip
                    label={`${runningScan.progress}% Running`}
                    size="small"
                    color="primary"
                    icon={<CircularProgress size={12} />}
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
          <Tab label="Compliance State" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Scan History" />
          <Tab label="Host Information" />
          <Tab label="System Details" />
          <Tab label="Terminal" icon={<TerminalIcon />} iconPosition="start" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        {/* Compliance State Panel */}
        {complianceLoading ? (
          <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
            <CircularProgress />
          </Box>
        ) : !complianceState || complianceState.total_rules === 0 ? (
          <Alert severity="info" sx={{ mb: 2 }}>
            Awaiting first compliance scan. Scans run automatically based on the adaptive schedule.
          </Alert>
        ) : (
          <Box>
            {/* Compliance Summary */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography
                      variant="h3"
                      color={
                        complianceState.compliance_score >= 70
                          ? 'success.main'
                          : complianceState.compliance_score >= 40
                            ? 'warning.main'
                            : 'error.main'
                      }
                    >
                      {complianceState.compliance_score.toFixed(1)}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Compliance Score
                    </Typography>
                    {complianceState.scan_date && (
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        display="block"
                        sx={{ mt: 1 }}
                      >
                        Last scanned: {new Date(complianceState.scan_date).toLocaleString()}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 6, md: 2.25 }}>
                <Card>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="success.main">
                      {complianceState.passed}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Passed
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 6, md: 2.25 }}>
                <Card>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="error.main">
                      {complianceState.failed}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Failed
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4.5 }}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                      Severity Breakdown
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Tooltip
                        title={`${complianceState.severity_summary.critical.passed} passed, ${complianceState.severity_summary.critical.failed} failed`}
                      >
                        <Chip
                          size="small"
                          color="error"
                          label={`Critical: ${complianceState.severity_summary.critical.failed}`}
                        />
                      </Tooltip>
                      <Tooltip
                        title={`${complianceState.severity_summary.high.passed} passed, ${complianceState.severity_summary.high.failed} failed`}
                      >
                        <Chip
                          size="small"
                          color="warning"
                          label={`High: ${complianceState.severity_summary.high.failed}`}
                        />
                      </Tooltip>
                      <Tooltip
                        title={`${complianceState.severity_summary.medium.passed} passed, ${complianceState.severity_summary.medium.failed} failed`}
                      >
                        <Chip
                          size="small"
                          color="info"
                          label={`Medium: ${complianceState.severity_summary.medium.failed}`}
                        />
                      </Tooltip>
                      <Tooltip
                        title={`${complianceState.severity_summary.low.passed} passed, ${complianceState.severity_summary.low.failed} failed`}
                      >
                        <Chip
                          size="small"
                          variant="outlined"
                          label={`Low: ${complianceState.severity_summary.low.failed}`}
                        />
                      </Tooltip>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            {/* Filters */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
              <Typography variant="h6">
                Rule Findings (
                {
                  complianceState.findings
                    .filter((f) => {
                      if (findingsFilter === 'all') return true;
                      return f.status === findingsFilter;
                    })
                    .filter((f) => {
                      if (!findingsSearch) return true;
                      return (
                        f.title.toLowerCase().includes(findingsSearch.toLowerCase()) ||
                        f.rule_id.toLowerCase().includes(findingsSearch.toLowerCase())
                      );
                    }).length
                }
                )
              </Typography>
              <Box sx={{ flexGrow: 1 }} />
              <Chip
                label="All"
                variant={findingsFilter === 'all' ? 'filled' : 'outlined'}
                onClick={() => setFindingsFilter('all')}
                clickable
              />
              <Chip
                label="Failed"
                color="error"
                variant={findingsFilter === 'fail' ? 'filled' : 'outlined'}
                onClick={() => setFindingsFilter('fail')}
                clickable
              />
              <Chip
                label="Passed"
                color="success"
                variant={findingsFilter === 'pass' ? 'filled' : 'outlined'}
                onClick={() => setFindingsFilter('pass')}
                clickable
              />
            </Box>

            {/* Findings Table */}
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Rule ID</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Detail</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {complianceState.findings
                    .filter((f) => findingsFilter === 'all' || f.status === findingsFilter)
                    .filter(
                      (f) =>
                        !findingsSearch ||
                        f.title.toLowerCase().includes(findingsSearch.toLowerCase()) ||
                        f.rule_id.toLowerCase().includes(findingsSearch.toLowerCase())
                    )
                    .map((finding, idx) => (
                      <TableRow key={`${finding.rule_id}-${idx}`} hover>
                        <TableCell>
                          {finding.status === 'pass' ? (
                            <CheckCircleIcon color="success" fontSize="small" />
                          ) : finding.status === 'fail' ? (
                            <ErrorIcon color="error" fontSize="small" />
                          ) : (
                            <InfoIcon color="disabled" fontSize="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={finding.severity}
                            color={
                              finding.severity === 'critical'
                                ? 'error'
                                : finding.severity === 'high'
                                  ? 'warning'
                                  : finding.severity === 'medium'
                                    ? 'info'
                                    : 'default'
                            }
                          />
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                          >
                            {finding.rule_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{finding.title}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                              maxWidth: 300,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {finding.detail || '-'}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Scan History ({scans.length} scans)
        </Typography>
        {scans.length > 0 ? (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Scan Name</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Compliance Score</TableCell>
                  <TableCell>Issues</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scans.map((scan) => {
                  const complianceScore = getComplianceScore(scan);
                  const duration =
                    scan.completed_at && scan.started_at
                      ? Math.round(
                          (new Date(scan.completed_at).getTime() -
                            new Date(scan.started_at).getTime()) /
                            1000
                        )
                      : null;

                  return (
                    <TableRow key={scan.id} hover>
                      <TableCell>
                        <Box>
                          <Typography variant="body2" fontWeight="medium">
                            {scan.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {scan.content_name}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getStatusIcon(scan.status)}
                          <Box>
                            <Chip
                              label={scan.status}
                              size="small"
                              color={
                                scan.status === 'completed'
                                  ? 'success'
                                  : scan.status === 'running'
                                    ? 'primary'
                                    : scan.status === 'failed'
                                      ? 'error'
                                      : 'default'
                              }
                            />
                            {scan.status === 'running' && (
                              <LinearProgress
                                variant="determinate"
                                value={scan.progress}
                                sx={{ mt: 0.5, width: 80 }}
                              />
                            )}
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {complianceScore !== null ? (
                          <Chip
                            label={`${complianceScore.toFixed(1)}%`}
                            size="small"
                            color={
                              complianceScore >= 70
                                ? 'success'
                                : complianceScore >= 40
                                  ? 'warning'
                                  : 'error'
                            }
                          />
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            N/A
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        {scan.results ? (
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {scan.results.severity_high > 0 && (
                              <Chip
                                label={`${scan.results.severity_high} High`}
                                size="small"
                                color="error"
                              />
                            )}
                            {scan.results.severity_medium > 0 && (
                              <Chip
                                label={`${scan.results.severity_medium} Med`}
                                size="small"
                                color="warning"
                              />
                            )}
                            {scan.results.severity_low > 0 && (
                              <Chip
                                label={`${scan.results.severity_low} Low`}
                                size="small"
                                variant="outlined"
                              />
                            )}
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No data
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(scan.started_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{duration ? `${duration}s` : 'N/A'}</Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Scan Details">
                          <IconButton size="small" onClick={() => navigate(`/scans/${scan.id}`)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Alert severity="info">
            No scans have been performed on this host yet. Compliance scans run automatically based
            on the adaptive schedule.
          </Alert>
        )}

        {/* Compliance Trend Chart */}
        {scans.length > 0 && (
          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Compliance Trend
            </Typography>
            <Card>
              <CardContent>
                <ComplianceTrendChart
                  data={scans
                    .filter((scan) => scan.completed_at && scan.results)
                    .map((scan) => ({
                      timestamp: scan.completed_at,
                      score: parseFloat(scan.results?.score || '0'),
                      passed_rules: scan.results?.passed_rules || 0,
                      failed_rules: scan.results?.failed_rules || 0,
                      total_rules: scan.results?.total_rules || 0,
                      scan_id: scan.id,
                    }))}
                  height={300}
                />
              </CardContent>
            </Card>
          </Box>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Host Information
        </Typography>
        <List>
          <ListItem>
            <ListItemIcon>
              <ComputerIcon />
            </ListItemIcon>
            <ListItemText primary="Hostname" secondary={host.hostname} />
          </ListItem>
          <ListItem>
            <ListItemIcon>
              <NetworkCheckIcon />
            </ListItemIcon>
            <ListItemText primary="IP Address" secondary={host.ip_address} />
          </ListItem>
          <ListItem>
            <ListItemIcon>
              <StorageIcon />
            </ListItemIcon>
            <ListItemText primary="Operating System" secondary={host.operating_system} />
          </ListItem>
          <ListItem>
            <ListItemIcon>
              <SecurityIcon />
            </ListItemIcon>
            <ListItemText primary="SSH Port" secondary={host.port} />
          </ListItem>
          <ListItem>
            <ListItemIcon>{getAuthMethodDisplay(host.auth_method).icon}</ListItemIcon>
            <ListItemText
              primary="Authentication Method"
              secondary={
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                  <Typography variant="body2" fontWeight="medium">
                    {getAuthMethodDisplay(host.auth_method).label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {getAuthMethodDisplay(host.auth_method).description}
                  </Typography>
                  {host.ssh_key_fingerprint && (
                    <Box sx={{ mt: 1 }}>
                      <SSHKeyDisplay
                        sshKeyInfo={{
                          fingerprint: host.ssh_key_fingerprint,
                          keyType: host.ssh_key_type || 'Unknown',
                          keyBits: host.ssh_key_bits || 0,
                          keyComment: host.ssh_key_comment || '',
                          createdAt: host.created_at,
                        }}
                        onDelete={handleDeleteSSHKey}
                        loading={deletingSSHKey}
                        compact={false}
                      />
                    </Box>
                  )}
                </Box>
              }
            />
          </ListItem>
          <ListItem>
            <ListItemIcon>
              <ScheduleIcon />
            </ListItemIcon>
            <ListItemText primary="Added" secondary={new Date(host.created_at).toLocaleString()} />
          </ListItem>
          {host.last_check && (
            <ListItem>
              <ListItemIcon>
                <CheckCircleIcon />
              </ListItemIcon>
              <ListItemText
                primary="Last Check"
                secondary={new Date(host.last_check).toLocaleString()}
              />
            </ListItem>
          )}
        </List>
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          System Details
        </Typography>
        <Alert severity="info">
          System monitoring data will be displayed here once monitoring agents are deployed.
        </Alert>
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        <Box sx={{ height: '600px' }}>
          <HostTerminal hostId={host.id} hostname={host.hostname} ipAddress={host.ip_address} />
        </Box>
      </TabPanel>
    </Box>
  );
};

export default HostDetail;
