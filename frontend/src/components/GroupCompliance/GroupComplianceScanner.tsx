import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  TextField,
  Alert,
  LinearProgress,
  Chip,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  PlayArrow,
  Schedule,
  Assessment,
  Security,
  Warning,
  CheckCircle,
  Error,
  Info,
  Refresh,
  Download,
  Settings
} from '@mui/icons-material';
import { useSnackbar } from 'notistack';

interface ComplianceScanRequest {
  scapContentId?: number;
  profileId?: string;
  complianceFramework?: string;
  remediationMode: string;
  emailNotifications: boolean;
  generateReports: boolean;
  concurrentScans: number;
  scanTimeout: number;
}

interface GroupComplianceProps {
  groupId: number;
  groupName: string;
  onScanStarted?: (sessionId: string) => void;
}

const ComplianceFrameworks = {
  'disa-stig': 'DISA STIG',
  'cis': 'CIS Benchmarks',
  'nist-800-53': 'NIST 800-53',
  'pci-dss': 'PCI DSS',
  'hipaa': 'HIPAA',
  'soc2': 'SOC 2',
  'iso-27001': 'ISO 27001',
  'cmmc': 'CMMC'
};

const RemediationModes = {
  'none': 'No Remediation',
  'report_only': 'Report Only',
  'auto_apply': 'Auto Apply (Caution)',
  'manual_review': 'Manual Review Required'
};

export const GroupComplianceScanner: React.FC<GroupComplianceProps> = ({
  groupId,
  groupName,
  onScanStarted
}) => {
  const { enqueueSnackbar } = useSnackbar();
  const [loading, setLoading] = useState(false);
  const [scapContents, setScapContents] = useState<any[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [currentScan, setCurrentScan] = useState<any>(null);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  const [scanRequest, setScanRequest] = useState<ComplianceScanRequest>({
    remediationMode: 'report_only',
    emailNotifications: true,
    generateReports: true,
    concurrentScans: 5,
    scanTimeout: 3600
  });

  useEffect(() => {
    loadScapContents();
    loadScanHistory();
    checkActiveScan();
  }, [groupId]);

  const loadScapContents = async () => {
    try {
      const response = await fetch('/api/scap-content/', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setScapContents(data);
      }
    } catch (error) {
      console.error('Failed to load SCAP contents:', error);
    }
  };

  const loadProfiles = async (contentId: number) => {
    try {
      const response = await fetch(`/api/scap-content/${contentId}/profiles`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setProfiles(data.profiles || []);
      }
    } catch (error) {
      console.error('Failed to load profiles:', error);
    }
  };

  const loadScanHistory = async () => {
    try {
      const response = await fetch(`/api/group-compliance/${groupId}/scan-history?limit=10`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setScanHistory(data);
      }
    } catch (error) {
      console.error('Failed to load scan history:', error);
    }
  };

  const checkActiveScan = async () => {
    try {
      const response = await fetch(`/api/group-compliance/${groupId}/active-scan`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        if (data.session_id) {
          setCurrentScan(data);
          monitorScanProgress(data.session_id);
        }
      }
    } catch (error) {
      // No active scan, which is fine
    }
  };

  const startComplianceScan = async () => {
    if (!scanRequest.scapContentId) {
      enqueueSnackbar('Please select SCAP content', { variant: 'error' });
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`/api/group-compliance/${groupId}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          scap_content_id: scanRequest.scapContentId,
          profile_id: scanRequest.profileId,
          compliance_framework: scanRequest.complianceFramework,
          remediation_mode: scanRequest.remediationMode,
          email_notifications: scanRequest.emailNotifications,
          generate_reports: scanRequest.generateReports,
          concurrent_scans: scanRequest.concurrentScans,
          scan_timeout: scanRequest.scanTimeout
        })
      });

      if (response.ok) {
        const data = await response.json();
        setCurrentScan(data);
        enqueueSnackbar('Compliance scan started successfully', { variant: 'success' });
        
        if (onScanStarted) {
          onScanStarted(data.session_id);
        }
        
        // Start monitoring progress
        monitorScanProgress(data.session_id);
      } else {
        const error = await response.json();
        enqueueSnackbar(`Failed to start scan: ${error.detail}`, { variant: 'error' });
      }
    } catch (error) {
      enqueueSnackbar('Failed to start compliance scan', { variant: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const monitorScanProgress = async (sessionId: string) => {
    const pollProgress = async () => {
      try {
        const response = await fetch(`/api/group-compliance/sessions/${sessionId}/progress`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
          }
        });
        
        if (response.ok) {
          const progress = await response.json();
          setCurrentScan(prev => ({ ...prev, ...progress }));
          
          if (progress.status === 'completed' || progress.status === 'failed') {
            loadScanHistory(); // Refresh history
            if (progress.status === 'completed') {
              enqueueSnackbar('Compliance scan completed', { variant: 'success' });
            } else {
              enqueueSnackbar('Compliance scan failed', { variant: 'error' });
            }
            return; // Stop polling
          }
          
          // Continue polling if still in progress
          setTimeout(pollProgress, 5000);
        }
      } catch (error) {
        console.error('Failed to poll scan progress:', error);
      }
    };
    
    pollProgress();
  };

  const cancelScan = async () => {
    if (!currentScan?.session_id) return;
    
    try {
      const response = await fetch(`/api/group-compliance/sessions/${currentScan.session_id}/cancel`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
      
      if (response.ok) {
        enqueueSnackbar('Scan cancelled', { variant: 'info' });
        setCurrentScan(null);
      }
    } catch (error) {
      enqueueSnackbar('Failed to cancel scan', { variant: 'error' });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle color="success" />;
      case 'failed': return <Error color="error" />;
      case 'in_progress': return <Info color="info" />;
      case 'cancelled': return <Warning color="warning" />;
      default: return <Info color="disabled" />;
    }
  };

  const getStatusColor = (status: string): 'success' | 'error' | 'warning' | 'info' | 'default' => {
    switch (status) {
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'cancelled': return 'warning';
      case 'in_progress': return 'info';
      default: return 'default';
    }
  };

  return (
    <Box>
      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="between" mb={2}>
            <Typography variant="h5" component="h2" display="flex" alignItems="center" gap={1}>
              <Security color="primary" />
              Group Compliance Scanning
            </Typography>
            <Box>
              <Tooltip title="View scan history">
                <IconButton onClick={() => setShowHistory(true)}>
                  <Assessment />
                </IconButton>
              </Tooltip>
              <Tooltip title="Advanced settings">
                <IconButton onClick={() => setShowAdvanced(true)}>
                  <Settings />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          <Typography variant="subtitle1" color="textSecondary" gutterBottom>
            {groupName} • Comprehensive compliance scanning for all hosts in group
          </Typography>

          {/* Current Scan Status */}
          {currentScan && (
            <Alert 
              severity={currentScan.status === 'in_progress' ? 'info' : 
                       currentScan.status === 'completed' ? 'success' : 'error'}
              sx={{ mb: 2 }}
              action={
                currentScan.status === 'in_progress' && (
                  <Button color="inherit" size="small" onClick={cancelScan}>
                    Cancel
                  </Button>
                )
              }
            >
              <Typography variant="body2">
                Scan Status: <strong>{currentScan.status}</strong> • 
                Progress: {currentScan.completed_hosts || 0}/{currentScan.total_hosts || 0} hosts
              </Typography>
              {currentScan.status === 'in_progress' && (
                <LinearProgress 
                  variant="determinate" 
                  value={(currentScan.completed_hosts || 0) / (currentScan.total_hosts || 1) * 100}
                  sx={{ mt: 1 }}
                />
              )}
            </Alert>
          )}

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>SCAP Content</InputLabel>
                <Select
                  value={scanRequest.scapContentId || ''}
                  onChange={(e) => {
                    const contentId = e.target.value as number;
                    setScanRequest(prev => ({ ...prev, scapContentId: contentId }));
                    if (contentId) {
                      loadProfiles(contentId);
                    }
                  }}
                  label="SCAP Content"
                >
                  {scapContents.map((content) => (
                    <MenuItem key={content.id} value={content.id}>
                      {content.title} ({content.compliance_framework})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Compliance Profile</InputLabel>
                <Select
                  value={scanRequest.profileId || ''}
                  onChange={(e) => setScanRequest(prev => ({ 
                    ...prev, 
                    profileId: e.target.value as string 
                  }))}
                  label="Compliance Profile"
                  disabled={!profiles.length}
                >
                  {profiles.map((profile) => (
                    <MenuItem key={profile.id} value={profile.id}>
                      {profile.title}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Compliance Framework</InputLabel>
                <Select
                  value={scanRequest.complianceFramework || ''}
                  onChange={(e) => setScanRequest(prev => ({ 
                    ...prev, 
                    complianceFramework: e.target.value as string 
                  }))}
                  label="Compliance Framework"
                >
                  {Object.entries(ComplianceFrameworks).map(([key, label]) => (
                    <MenuItem key={key} value={key}>{label}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Remediation Mode</InputLabel>
                <Select
                  value={scanRequest.remediationMode}
                  onChange={(e) => setScanRequest(prev => ({ 
                    ...prev, 
                    remediationMode: e.target.value as string 
                  }))}
                  label="Remediation Mode"
                >
                  {Object.entries(RemediationModes).map(([key, label]) => (
                    <MenuItem key={key} value={key}>{label}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>

          <Box mt={3}>
            <Grid container spacing={2}>
              <Grid item>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanRequest.emailNotifications}
                      onChange={(e) => setScanRequest(prev => ({ 
                        ...prev, 
                        emailNotifications: e.target.checked 
                      }))}
                    />
                  }
                  label="Email Notifications"
                />
              </Grid>
              <Grid item>
                <FormControlLabel
                  control={
                    <Switch
                      checked={scanRequest.generateReports}
                      onChange={(e) => setScanRequest(prev => ({ 
                        ...prev, 
                        generateReports: e.target.checked 
                      }))}
                    />
                  }
                  label="Generate Reports"
                />
              </Grid>
            </Grid>
          </Box>

          <Box mt={3} display="flex" gap={2}>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PlayArrow />}
              onClick={startComplianceScan}
              disabled={loading || (currentScan?.status === 'in_progress')}
              size="large"
            >
              {loading ? 'Starting...' : 'Start Compliance Scan'}
            </Button>
            
            <Button
              variant="outlined"
              startIcon={<Schedule />}
              onClick={() => {/* Open schedule dialog */}}
            >
              Schedule Scans
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Scan History Dialog */}
      <Dialog open={showHistory} onClose={() => setShowHistory(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Scan History - {groupName}</DialogTitle>
        <DialogContent>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Status</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Completed</TableCell>
                  <TableCell>Hosts</TableCell>
                  <TableCell>Success Rate</TableCell>
                  <TableCell>Framework</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scanHistory.map((scan) => (
                  <TableRow key={scan.session_id}>
                    <TableCell>
                      <Chip
                        icon={getStatusIcon(scan.status)}
                        label={scan.status}
                        color={getStatusColor(scan.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(scan.started_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}
                    </TableCell>
                    <TableCell>
                      {scan.hosts_scanned}/{scan.total_hosts}
                    </TableCell>
                    <TableCell>
                      {scan.total_hosts > 0 ? 
                        `${Math.round(scan.successful_hosts / scan.total_hosts * 100)}%` : '-'}
                    </TableCell>
                    <TableCell>
                      {scan.scan_config?.compliance_framework || '-'}
                    </TableCell>
                    <TableCell>
                      <Tooltip title="Download Report">
                        <IconButton size="small">
                          <Download />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowHistory(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Advanced Settings Dialog */}
      <Dialog open={showAdvanced} onClose={() => setShowAdvanced(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Advanced Scan Settings</DialogTitle>
        <DialogContent>
          <Box mt={2}>
            <TextField
              fullWidth
              label="Concurrent Scans"
              type="number"
              value={scanRequest.concurrentScans}
              onChange={(e) => setScanRequest(prev => ({ 
                ...prev, 
                concurrentScans: parseInt(e.target.value) || 5 
              }))}
              inputProps={{ min: 1, max: 20 }}
              helperText="Maximum number of simultaneous scans (1-20)"
              margin="normal"
            />
            <TextField
              fullWidth
              label="Scan Timeout (seconds)"
              type="number"
              value={scanRequest.scanTimeout}
              onChange={(e) => setScanRequest(prev => ({ 
                ...prev, 
                scanTimeout: parseInt(e.target.value) || 3600 
              }))}
              inputProps={{ min: 300, max: 7200 }}
              helperText="Timeout for individual host scans (300-7200 seconds)"
              margin="normal"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAdvanced(false)}>Cancel</Button>
          <Button onClick={() => setShowAdvanced(false)} variant="contained">Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};