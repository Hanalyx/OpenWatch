import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Typography,
  Button,
  Chip,
  Alert,
  CircularProgress,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
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
  LinearProgress,
  Tooltip
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  Build as BuildIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
  OpenInNew as OpenInNewIcon,
  Schedule as ScheduleIcon,
  Settings as SettingsIcon
} from '@mui/icons-material';
import { tokenService } from '../../services/tokenService';

interface RemediationJob {
  id: string;
  status: string;
  total_rules: number;
  successful_rules: number;
  failed_rules: number;
  skipped_rules: number;
  started_at: string;
  completed_at?: string;
  progress: number;
}

interface FailedRule {
  rule_id: string;
  rule_name: string;
  severity: string;
  can_remediate: boolean;
  description?: string;
}

interface RemediationPanelProps {
  scanId: string;
  hostId: string;
  scanStatus: string;
  onRemediationStarted?: () => void;
}

const RemediationPanel: React.FC<RemediationPanelProps> = ({
  scanId,
  hostId,
  scanStatus,
  onRemediationStarted
}) => {
  const [failedRules, setFailedRules] = useState<FailedRule[]>([]);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [remediationJob, setRemediationJob] = useState<RemediationJob | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState(false);
  const [activeStep, setActiveStep] = useState(0);

  // Load failed rules when scan is completed
  useEffect(() => {
    if (scanStatus === 'completed') {
      loadFailedRules();
    }
  }, [scanId, scanStatus]);

  const loadFailedRules = async () => {
    try {
      setLoading(true);
      const response = await tokenService.authenticatedFetch(`/api/scans/${scanId}/failed-rules`);
      
      if (!response.ok) {
        throw new Error('Failed to load failed rules');
      }
      
      const data = await response.json();
      setFailedRules(data.failed_rules || []);
      
      // Auto-select remediable rules
      const remediableRules = data.failed_rules
        .filter((rule: FailedRule) => rule.can_remediate)
        .map((rule: FailedRule) => rule.rule_id);
      setSelectedRules(remediableRules);
      
    } catch (err) {
      console.error('Error loading failed rules:', err);
      setError('Failed to load failed rules');
    } finally {
      setLoading(false);
    }
  };

  const startRemediation = async () => {
    if (selectedRules.length === 0) {
      setError('Please select at least one rule to remediate');
      return;
    }

    try {
      setLoading(true);
      setActiveStep(1);
      
      // Send remediation request to AEGIS
      const response = await fetch('http://localhost:8001/api/v1/remediation/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tokenService.getToken()}`
        },
        body: JSON.stringify({
          host_id: hostId,
          rule_ids: selectedRules,
          source_scan_id: scanId,
          auto_verify: true
        })
      });

      if (!response.ok) {
        throw new Error('Failed to start remediation');
      }

      const jobData = await response.json();
      setRemediationJob(jobData);
      setActiveStep(2);
      
      // Start polling for job status
      pollRemediationStatus(jobData.job_id);
      
      if (onRemediationStarted) {
        onRemediationStarted();
      }
      
    } catch (err) {
      console.error('Error starting remediation:', err);
      setError('Failed to start remediation');
      setActiveStep(0);
    } finally {
      setLoading(false);
      setConfirmDialog(false);
    }
  };

  const pollRemediationStatus = async (jobId: string) => {
    const poll = async () => {
      try {
        const response = await fetch(`http://localhost:8001/api/v1/remediation/jobs/${jobId}`, {
          headers: {
            'Authorization': `Bearer ${tokenService.getToken()}`
          }
        });

        if (response.ok) {
          const jobData = await response.json();
          setRemediationJob(jobData);
          
          if (jobData.status === 'completed' || jobData.status === 'failed') {
            setActiveStep(3);
            return; // Stop polling
          }
        }
      } catch (err) {
        console.error('Error polling remediation status:', err);
      }

      // Continue polling if job is still running
      setTimeout(poll, 3000);
    };

    poll();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
      case 'critical':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'running':
        return 'primary';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  if (scanStatus !== 'completed') {
    return (
      <Card>
        <CardHeader 
          title="Remediation" 
          avatar={<BuildIcon />}
        />
        <CardContent>
          <Alert severity="info">
            Remediation will be available after the scan completes.
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box>
      <Card>
        <CardHeader 
          title="Automated Remediation" 
          avatar={<BuildIcon />}
          action={
            <Button
              startIcon={<RefreshIcon />}
              onClick={loadFailedRules}
              disabled={loading}
            >
              Refresh
            </Button>
          }
        />
        <CardContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {/* Remediation Stepper */}
          <Stepper activeStep={activeStep} orientation="vertical" sx={{ mb: 3 }}>
            <Step>
              <StepLabel>Select Rules for Remediation</StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Review failed rules and select which ones to remediate automatically.
                </Typography>
              </StepContent>
            </Step>
            <Step>
              <StepLabel>Execute Remediation</StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary">
                  AEGIS is applying fixes to the selected security rules...
                </Typography>
              </StepContent>
            </Step>
            <Step>
              <StepLabel>Verify Results</StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary">
                  Remediation complete. A verification scan will be triggered automatically.
                </Typography>
              </StepContent>
            </Step>
          </Stepper>

          {/* Failed Rules Table */}
          {failedRules.length > 0 && activeStep === 0 && (
            <Box>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Failed Rules ({failedRules.filter(r => r.can_remediate).length} can be remediated)
              </Typography>
              
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Rule</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {failedRules.map((rule) => (
                      <TableRow key={rule.rule_id}>
                        <TableCell>
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {rule.rule_name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {rule.rule_id}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.severity.toUpperCase()}
                            color={getSeverityColor(rule.severity)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {rule.can_remediate ? (
                            <Chip
                              label="Can Remediate"
                              color="success"
                              size="small"
                              variant="outlined"
                            />
                          ) : (
                            <Chip
                              label="Manual Fix Required"
                              color="warning"
                              size="small"
                              variant="outlined"
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          {rule.can_remediate && (
                            <Tooltip title="Include in remediation">
                              <IconButton
                                size="small"
                                onClick={() => {
                                  if (selectedRules.includes(rule.rule_id)) {
                                    setSelectedRules(selectedRules.filter(id => id !== rule.rule_id));
                                  } else {
                                    setSelectedRules([...selectedRules, rule.rule_id]);
                                  }
                                }}
                              >
                                {selectedRules.includes(rule.rule_id) ? (
                                  <CheckCircleIcon color="primary" />
                                ) : (
                                  <PlayArrowIcon />
                                )}
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {selectedRules.length > 0 && (
                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2" color="text.secondary">
                    {selectedRules.length} rules selected for remediation
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<BuildIcon />}
                    onClick={() => setConfirmDialog(true)}
                    disabled={loading}
                  >
                    Start Remediation
                  </Button>
                </Box>
              )}
            </Box>
          )}

          {/* Remediation Job Status */}
          {remediationJob && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Remediation Job Status
              </Typography>
              
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Chip
                    label={remediationJob.status.toUpperCase()}
                    color={getStatusColor(remediationJob.status)}
                    sx={{ mr: 2 }}
                  />
                  <Typography variant="body2">
                    Job ID: {remediationJob.id}
                  </Typography>
                </Box>

                {remediationJob.status === 'running' && (
                  <Box sx={{ mb: 2 }}>
                    <LinearProgress 
                      variant="determinate" 
                      value={remediationJob.progress} 
                      sx={{ mb: 1 }}
                    />
                    <Typography variant="body2" color="text.secondary">
                      Progress: {remediationJob.progress}%
                    </Typography>
                  </Box>
                )}

                <Box sx={{ display: 'flex', gap: 3 }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Total Rules</Typography>
                    <Typography variant="h6">{remediationJob.total_rules}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Successful</Typography>
                    <Typography variant="h6" color="success.main">
                      {remediationJob.successful_rules}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Failed</Typography>
                    <Typography variant="h6" color="error.main">
                      {remediationJob.failed_rules}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Skipped</Typography>
                    <Typography variant="h6" color="warning.main">
                      {remediationJob.skipped_rules}
                    </Typography>
                  </Box>
                </Box>

                {remediationJob.completed_at && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Completed: {new Date(remediationJob.completed_at).toLocaleString()}
                  </Typography>
                )}
              </Paper>
            </Box>
          )}

          {loading && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
              <CircularProgress />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialog} onClose={() => setConfirmDialog(false)}>
        <DialogTitle>Confirm Remediation</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to start automated remediation for {selectedRules.length} selected rules?
          </Typography>
          <Alert severity="warning" sx={{ mt: 2 }}>
            This will make changes to the target host. Ensure you have appropriate backups and approvals.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDialog(false)}>Cancel</Button>
          <Button 
            onClick={startRemediation} 
            variant="contained" 
            disabled={loading}
            startIcon={loading ? <CircularProgress size={16} /> : <BuildIcon />}
          >
            {loading ? 'Starting...' : 'Start Remediation'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default RemediationPanel;