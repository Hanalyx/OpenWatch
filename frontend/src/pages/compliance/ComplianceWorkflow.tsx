import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Container,
  Typography,
  Grid,
  Chip,
  Alert,
  Snackbar,
  useTheme,
  alpha,
  CircularProgress,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  AutoFixHigh,
  Visibility,
  CheckCircle,
  Error,
  Warning,
  Refresh,
  Timeline,
  Assignment,
  VerifiedUser,
  Schedule,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';

// Types based on real database schema
interface Host {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  operating_system: string;
  status: string;
  last_seen: string;
}

interface ScanResult {
  id: string;
  scan_id: string;
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  error_rules: number;
  score: string;
  severity_high: number;
  severity_medium: number;
  severity_low: number;
  created_at: string;
}

interface Scan {
  id: string;
  name: string;
  host_id: string;
  host: Host;
  status: string;
  progress: number;
  started_at: string;
  completed_at: string;
  scan_result: ScanResult;
  remediation_requested: boolean;
  aegis_remediation_id: string;
  verification_scan: boolean;
  remediation_status: string;
}

interface FailedRule {
  id: string;
  rule_id: string;
  title: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  fix_text: string;
  check_text: string;
  remediation_available: boolean;
  estimated_fix_time: number;
}

const ComplianceWorkflow: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  // Tab selection state - reserved for future multi-tab workflow views
  const [_selectedTab, _setSelectedTab] = useState(0);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [failedRules, setFailedRules] = useState<FailedRule[]>([]);
  // Remediation dialog state - reserved for future inline remediation workflows
  const [_remediationDialog, _setRemediationDialog] = useState(false);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({ open: false, message: '', severity: 'info' });

  useEffect(() => {
    loadWorkflowData();
  }, []);

  const loadWorkflowData = async () => {
    try {
      setLoading(true);

      // Load recent scans with results
      const scansResponse = await api.get('/api/scans/', {
        params: { limit: 10, include_results: true },
      });
      setScans(scansResponse.data || []);
    } catch (error) {
      console.error('Failed to load workflow data:', error);
      setSnackbar({
        open: true,
        message: 'Failed to load compliance workflow data',
        severity: 'error',
      });
    } finally {
      setLoading(false);
    }
  };

  const loadFailedRules = async (scanId: string) => {
    try {
      const response = await api.get(`/api/scans/${scanId}/failed-rules`);
      setFailedRules(response.data || []);
    } catch (error) {
      console.error('Failed to load failed rules:', error);
      setSnackbar({
        open: true,
        message: 'Failed to load failed rules',
        severity: 'error',
      });
    }
  };

  const handleScanSelect = async (scan: Scan) => {
    setSelectedScan(scan);
    if (scan.scan_result && scan.scan_result.failed_rules > 0) {
      await loadFailedRules(scan.id);
    }
  };

  const handleStartRemediation = async (scanId: string) => {
    try {
      // Send failed rules to AEGIS for remediation
      const response = await api.post(`/api/scans/${scanId}/remediate`);

      setSnackbar({
        open: true,
        message: `Remediation job started: ${response.data.job_id}`,
        severity: 'success',
      });

      // Reload data to show updated status
      loadWorkflowData();
    } catch (error) {
      console.error('Failed to start remediation:', error);
      setSnackbar({
        open: true,
        message: 'Failed to start remediation job',
        severity: 'error',
      });
    }
  };

  const handleVerificationScan = async (hostId: string) => {
    try {
      // Start verification scan after remediation
      await api.post('/api/scans/verify', {
        host_id: hostId,
        verification_scan: true,
      });

      setSnackbar({
        open: true,
        message: 'Verification scan started',
        severity: 'success',
      });

      navigate('/scans');
    } catch (error) {
      console.error('Failed to start verification scan:', error);
      setSnackbar({
        open: true,
        message: 'Failed to start verification scan',
        severity: 'error',
      });
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return theme.palette.error.main;
      case 'medium':
        return theme.palette.warning.main;
      case 'low':
        return theme.palette.info.main;
      default:
        return theme.palette.grey[500];
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return theme.palette.success.main;
      case 'running':
        return theme.palette.info.main;
      case 'failed':
        return theme.palette.error.main;
      default:
        return theme.palette.grey[500];
    }
  };

  if (loading) {
    return (
      <Container maxWidth={false} sx={{ py: 4 }}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress size={60} />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth={false} sx={{ py: 4 }}>
      {/* Workflow Header */}
      <Card sx={{ mb: 4 }}>
        <CardHeader
          title={
            <Box display="flex" alignItems="center" gap={2}>
              <Timeline sx={{ color: theme.palette.primary.main, fontSize: 32 }} />
              <Box>
                <Typography variant="h4" fontWeight="bold" color="primary">
                  Compliance Workflow
                </Typography>
                <Typography variant="subtitle1" color="text.secondary">
                  Scan → Analyze → Remediate → Verify
                </Typography>
              </Box>
            </Box>
          }
          action={
            <Button variant="outlined" startIcon={<Refresh />} onClick={loadWorkflowData}>
              Refresh
            </Button>
          }
        />
      </Card>

      <Grid container spacing={3}>
        {/* Left Panel - Scan List */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardHeader title="Recent Scans" subheader={`${scans.length} scans available`} />
            <CardContent sx={{ p: 0 }}>
              <List>
                {scans.map((scan) => (
                  <ListItem
                    key={scan.id}
                    button
                    onClick={() => handleScanSelect(scan)}
                    selected={selectedScan?.id === scan.id}
                    sx={{
                      borderLeft: selectedScan?.id === scan.id ? 3 : 0,
                      borderLeftColor: 'primary.main',
                    }}
                  >
                    <ListItemIcon>
                      {scan.status === 'completed' ? (
                        <CheckCircle sx={{ color: theme.palette.success.main }} />
                      ) : scan.status === 'running' ? (
                        <CircularProgress size={20} />
                      ) : (
                        <Error sx={{ color: theme.palette.error.main }} />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={scan.name}
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {scan.host.hostname}
                          </Typography>
                          {scan.scan_result && (
                            <Box display="flex" gap={1} mt={0.5}>
                              <Chip
                                size="small"
                                label={`${scan.scan_result.failed_rules} Failed`}
                                color={scan.scan_result.failed_rules > 0 ? 'error' : 'success'}
                                variant="outlined"
                              />
                              {scan.remediation_requested && (
                                <Chip
                                  size="small"
                                  label="Remediation"
                                  color="warning"
                                  icon={<AutoFixHigh />}
                                />
                              )}
                            </Box>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Right Panel - Scan Details & Actions */}
        <Grid item xs={12} md={8}>
          {selectedScan ? (
            <Card>
              <CardHeader
                title={selectedScan.name}
                subheader={`Host: ${selectedScan.host.hostname} (${selectedScan.host.ip_address})`}
                action={
                  <Chip
                    label={selectedScan.status.toUpperCase()}
                    sx={{
                      backgroundColor: alpha(getStatusColor(selectedScan.status), 0.1),
                      color: getStatusColor(selectedScan.status),
                    }}
                  />
                }
              />
              <CardContent>
                {/* Scan Results Summary */}
                {selectedScan.scan_result && (
                  <Grid container spacing={3} sx={{ mb: 4 }}>
                    <Grid item xs={12} sm={6} md={3}>
                      <Paper
                        sx={{
                          p: 2,
                          textAlign: 'center',
                          backgroundColor: alpha(theme.palette.success.main, 0.1),
                        }}
                      >
                        <CheckCircle
                          sx={{ fontSize: 32, color: theme.palette.success.main, mb: 1 }}
                        />
                        <Typography variant="h5" fontWeight="bold" color="success.main">
                          {selectedScan.scan_result.passed_rules}
                        </Typography>
                        <Typography variant="caption">Passed</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <Paper
                        sx={{
                          p: 2,
                          textAlign: 'center',
                          backgroundColor: alpha(theme.palette.error.main, 0.1),
                        }}
                      >
                        <Error sx={{ fontSize: 32, color: theme.palette.error.main, mb: 1 }} />
                        <Typography variant="h5" fontWeight="bold" color="error.main">
                          {selectedScan.scan_result.failed_rules}
                        </Typography>
                        <Typography variant="caption">Failed</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <Paper
                        sx={{
                          p: 2,
                          textAlign: 'center',
                          backgroundColor: alpha(theme.palette.warning.main, 0.1),
                        }}
                      >
                        <Warning sx={{ fontSize: 32, color: theme.palette.warning.main, mb: 1 }} />
                        <Typography variant="h5" fontWeight="bold" color="warning.main">
                          {selectedScan.scan_result.severity_high}
                        </Typography>
                        <Typography variant="caption">High Risk</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <Paper
                        sx={{
                          p: 2,
                          textAlign: 'center',
                          backgroundColor: alpha(theme.palette.primary.main, 0.1),
                        }}
                      >
                        <VerifiedUser
                          sx={{ fontSize: 32, color: theme.palette.primary.main, mb: 1 }}
                        />
                        <Typography variant="h5" fontWeight="bold" color="primary.main">
                          {selectedScan.scan_result.score || 'N/A'}
                        </Typography>
                        <Typography variant="caption">Score</Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                )}

                {/* Action Buttons */}
                <Box display="flex" gap={2} sx={{ mb: 3 }}>
                  <Button
                    variant="contained"
                    startIcon={<Visibility />}
                    onClick={() => navigate(`/scans/${selectedScan.id}`)}
                    color="primary"
                  >
                    View Details
                  </Button>

                  {selectedScan.scan_result && selectedScan.scan_result.failed_rules > 0 && (
                    <>
                      {!selectedScan.remediation_requested ? (
                        <Button
                          variant="contained"
                          startIcon={<AutoFixHigh />}
                          onClick={() => handleStartRemediation(selectedScan.id)}
                          color="warning"
                        >
                          Start Remediation
                        </Button>
                      ) : (
                        <Button
                          variant="outlined"
                          startIcon={<Schedule />}
                          disabled
                          color="warning"
                        >
                          Remediation {selectedScan.remediation_status || 'In Progress'}
                        </Button>
                      )}
                    </>
                  )}

                  {selectedScan.remediation_status === 'completed' && (
                    <Button
                      variant="contained"
                      startIcon={<VerifiedUser />}
                      onClick={() => handleVerificationScan(selectedScan.host_id)}
                      color="success"
                    >
                      Verify Fixes
                    </Button>
                  )}
                </Box>

                {/* Failed Rules Table */}
                {failedRules.length > 0 && (
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      Failed Rules ({failedRules.length})
                    </Typography>
                    <TableContainer component={Paper} variant="outlined">
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Rule</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Fix Available</TableCell>
                            <TableCell>Est. Time</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {failedRules.slice(0, 10).map((rule) => (
                            <TableRow key={rule.id}>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2" fontWeight="medium">
                                    {rule.rule_id}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {rule.title}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  size="small"
                                  label={rule.severity.toUpperCase()}
                                  sx={{
                                    backgroundColor: alpha(getSeverityColor(rule.severity), 0.1),
                                    color: getSeverityColor(rule.severity),
                                  }}
                                />
                              </TableCell>
                              <TableCell>
                                {rule.remediation_available ? (
                                  <CheckCircle sx={{ color: theme.palette.success.main }} />
                                ) : (
                                  <Error sx={{ color: theme.palette.error.main }} />
                                )}
                              </TableCell>
                              <TableCell>{rule.estimated_fix_time}min</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                    {failedRules.length > 10 && (
                      <Button
                        variant="text"
                        onClick={() => navigate(`/scans/${selectedScan.id}`)}
                        sx={{ mt: 1 }}
                      >
                        View All {failedRules.length} Failed Rules
                      </Button>
                    )}
                  </Box>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 8 }}>
                <Assignment sx={{ fontSize: 64, color: theme.palette.grey[400], mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Select a scan to start the compliance workflow
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Choose from your recent scans to analyze results and start remediation
                </Typography>
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ComplianceWorkflow;
