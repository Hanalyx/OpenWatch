import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Grid,
  Chip,
  Button,
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
  Divider,
  CircularProgress,
  Tooltip,
  Badge,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Memory as MemoryIcon,
  NetworkCheck as NetworkCheckIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  PlayArrow as PlayArrowIcon,
  Visibility as VisibilityIcon,
  GetApp as DownloadIcon,
  Schedule as ScheduleIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Settings as SettingsIcon,
  Terminal as TerminalIcon,
} from '@mui/icons-material';
import { StatusChip, ComplianceRing, SSHKeyDisplay, type SSHKeyInfo } from '../../components/design-system';
import HostTerminal from '../../components/terminal/HostTerminal';

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

  useEffect(() => {
    fetchHostDetails();
    fetchHostScans();
    // Also try to get enhanced host data from hosts list
    fetchEnhancedHostData();
  }, [id]);

  const fetchEnhancedHostData = async () => {
    try {
      const response = await fetch('/api/hosts/', {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const hosts = await response.json();
        const enhancedHost = hosts.find((h: any) => h.id === id);
        if (enhancedHost) {
          console.log('Found enhanced host data with scan info:', enhancedHost);
          // Update host with enhanced data
          setHost((prevHost) => ({
            ...prevHost,
            ...enhancedHost
          }));
          
          // Log scan information from host data
          if (enhancedHost.latest_scan_id) {
            console.log(`Host has scan data: ${enhancedHost.latest_scan_name}, Score: ${enhancedHost.compliance_score}%`);
          }
        }
      }
    } catch (error) {
      console.error('Error fetching enhanced host data:', error);
    }
  };

  const fetchHostDetails = async () => {
    try {
      const response = await fetch(`/api/hosts/${id}`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const hostData = await response.json();
        setHost(hostData);
      } else {
        setError('Host not found');
      }
    } catch (error) {
      console.error('Error fetching host details:', error);
      setError('Failed to load host details');
    }
  };

  const fetchHostScans = async () => {
    try {
      // Use trailing slash to avoid redirect
      const response = await fetch(`/api/scans/?host_id=${id}`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log(`Fetched ${data.scans?.length || 0} scans for host ${id}`);
        setScans(data.scans || []);
      } else {
        console.error('Failed to fetch host scans:', response.status, response.statusText);
        // Try without trailing slash as fallback
        const fallbackResponse = await fetch(`/api/scans?host_id=${id}`, {
          headers: {
            'Authorization': 'Bearer demo-token'
          }
        });
        if (fallbackResponse.ok) {
          const data = await fallbackResponse.json();
          setScans(data.scans || []);
        }
      }
    } catch (error) {
      console.error('Error fetching host scans:', error);
    } finally {
      setLoading(false);
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
          description: 'Uses system default SSH credentials'
        };
      case 'ssh_key':
        return {
          label: 'SSH Key',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Host-specific SSH key authentication'
        };
      case 'password':
        return {
          label: 'Password',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Host-specific password authentication'
        };
      case 'both':
        return {
          label: 'Password + SSH Key',
          icon: <SecurityIcon fontSize="small" />,
          description: 'Both password and SSH key authentication'
        };
      default:
        return {
          label: authMethod,
          icon: <SecurityIcon fontSize="small" />,
          description: 'Custom authentication method'
        };
    }
  };

  const handleStartScan = () => {
    navigate('/scans/new-scap', { state: { preselectedHostId: id } });
  };

  const handleDeleteSSHKey = async () => {
    if (!host) return;

    setDeletingSSHKey(true);
    try {
      const response = await fetch(`/api/hosts/${host.id}/ssh-key`, {
        method: 'DELETE',
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });

      if (response.ok) {
        // Update host state to remove SSH key metadata
        setHost(prev => prev ? {
          ...prev,
          ssh_key_fingerprint: undefined,
          ssh_key_type: undefined,
          ssh_key_bits: undefined,
          ssh_key_comment: undefined
        } : null);
      } else {
        const errorData = await response.json().catch(() => ({}));
        console.error('Failed to delete SSH key:', errorData);
        setError(errorData.detail || 'Failed to delete SSH key');
      }
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
  const runningScan = scans.find(scan => scan.status === 'running' || scan.status === 'pending');

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
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
        <Button
          variant="contained"
          startIcon={runningScan ? <VisibilityIcon /> : <PlayArrowIcon />}
          onClick={runningScan ? () => navigate(`/scans/${runningScan.id}`) : handleStartScan}
          sx={{ mr: 1 }}
        >
          {runningScan ? 'View Running Scan' : 'Start New Scan'}
        </Button>
      </Box>

      {/* Host Overview Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <ComputerIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">System</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Operating System
              </Typography>
              <Typography variant="body1">
                {host.operating_system}
              </Typography>
              <Box sx={{ mt: 2 }}>
                <StatusChip status={host.status as any} size="small" />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
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

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SecurityIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Compliance</Typography>
              </Box>
              {(latestScan && getComplianceScore(latestScan) !== null) ? (
                <ComplianceRing
                  score={getComplianceScore(latestScan)!}
                  size="medium"
                  trend="stable"
                />
              ) : host.compliance_score !== undefined && host.compliance_score !== null ? (
                <ComplianceRing
                  score={host.compliance_score}
                  size="medium"
                  trend="stable"
                />
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No compliance data available
                </Typography>
              )}
              {host.critical_issues !== undefined && host.critical_issues > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Chip 
                    label={`${host.critical_issues} Critical`} 
                    size="small" 
                    color="error" 
                  />
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

        <Grid item xs={12} sm={6} md={3}>
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
          <Tab label="Scan History" />
          <Tab label="Host Information" />
          <Tab label="System Details" />
          <Tab 
            label="Terminal" 
            icon={<TerminalIcon />}
            iconPosition="start"
          />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
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
                  const duration = scan.completed_at && scan.started_at
                    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
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
                                scan.status === 'completed' ? 'success' :
                                scan.status === 'running' ? 'primary' :
                                scan.status === 'failed' ? 'error' : 'default'
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
                              complianceScore >= 70 ? 'success' :
                              complianceScore >= 40 ? 'warning' : 'error'
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
                        <Typography variant="body2">
                          {duration ? `${duration}s` : 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Scan Details">
                          <IconButton
                            size="small"
                            onClick={() => navigate(`/scans/${scan.id}`)}
                          >
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
            No scans have been performed on this host yet.
            <Button
              variant="contained"
              size="small"
              startIcon={<PlayArrowIcon />}
              onClick={handleStartScan}
              sx={{ ml: 2 }}
            >
              Start First Scan
            </Button>
          </Alert>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Typography variant="h6" sx={{ mb: 2 }}>Host Information</Typography>
        <List>
          <ListItem>
            <ListItemIcon><ComputerIcon /></ListItemIcon>
            <ListItemText
              primary="Hostname"
              secondary={host.hostname}
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><NetworkCheckIcon /></ListItemIcon>
            <ListItemText
              primary="IP Address"
              secondary={host.ip_address}
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><StorageIcon /></ListItemIcon>
            <ListItemText
              primary="Operating System"
              secondary={host.operating_system}
            />
          </ListItem>
          <ListItem>
            <ListItemIcon><SecurityIcon /></ListItemIcon>
            <ListItemText
              primary="SSH Port"
              secondary={host.port}
            />
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
                          createdAt: host.created_at
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
            <ListItemIcon><ScheduleIcon /></ListItemIcon>
            <ListItemText
              primary="Added"
              secondary={new Date(host.created_at).toLocaleString()}
            />
          </ListItem>
          {host.last_check && (
            <ListItem>
              <ListItemIcon><CheckCircleIcon /></ListItemIcon>
              <ListItemText
                primary="Last Check"
                secondary={new Date(host.last_check).toLocaleString()}
              />
            </ListItem>
          )}
        </List>
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Typography variant="h6" sx={{ mb: 2 }}>System Details</Typography>
        <Alert severity="info">
          System monitoring data will be displayed here once monitoring agents are deployed.
        </Alert>
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Box sx={{ height: '600px' }}>
          <HostTerminal 
            hostId={host.id} 
            hostname={host.hostname} 
            ipAddress={host.ip_address} 
          />
        </Box>
      </TabPanel>
    </Container>
  );
};

export default HostDetail;