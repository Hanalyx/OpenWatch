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
  Alert,
  LinearProgress,
  Grid,
} from '@mui/material';
import { PlayArrow, Security, Warning, CheckCircle, Error, Info } from '@mui/icons-material';
// Remove notistack import - using state-based alerts instead

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

/**
 * SCAP content bundle - compliance framework bundle with profiles
 * Represents a compliance framework bundle loaded from MongoDB
 */
interface ScapContentBundle {
  id: number;
  name: string;
  description?: string;
  profiles: Array<{
    id: string;
    title: string;
    description?: string;
  }>;
  // Additional bundle metadata from backend
  [key: string]: string | number | boolean | object | undefined;
}

/**
 * Active compliance scan session data
 * Tracks progress and status of ongoing group compliance scan
 */
interface ScanSessionData {
  session_id: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  total_hosts?: number;
  completed_hosts?: number;
  failed_hosts?: number;
  progress_percentage?: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  // Additional scan metadata from backend
  [key: string]: string | number | boolean | undefined;
}

interface GroupComplianceProps {
  groupId: number;
  groupName: string;
  onScanStarted?: (sessionId: string) => void;
}

const ComplianceFrameworks = {
  'disa-stig': 'DISA STIG',
  cis: 'CIS Benchmarks',
  'nist-800-53': 'NIST 800-53',
  'pci-dss': 'PCI DSS',
  hipaa: 'HIPAA',
  soc2: 'SOC 2',
  'iso-27001': 'ISO 27001',
  cmmc: 'CMMC',
};

const RemediationModes = {
  none: 'No Remediation',
  report_only: 'Report Only',
  auto_apply: 'Auto Apply (Caution)',
  manual_review: 'Manual Review Required',
};

export const GroupComplianceScanner: React.FC<GroupComplianceProps> = ({
  groupId,
  groupName,
  onScanStarted,
}) => {
  const [loading, setLoading] = useState(false);
  // SCAP content bundles loaded from MongoDB compliance rules API
  const [scapContents, setScapContents] = useState<ScapContentBundle[]>([]);
  // Profiles from selected SCAP content bundle
  const [profiles, setProfiles] = useState<
    Array<{ id: string; title: string; description?: string }>
  >([]);
  // Current active scan session with progress tracking
  const [currentScan, setCurrentScan] = useState<ScanSessionData | null>(null);
  const [alertMessage, setAlertMessage] = useState<string | null>(null);
  const [alertSeverity, setAlertSeverity] = useState<'success' | 'error' | 'warning' | 'info'>(
    'info'
  );

  const [scanRequest, setScanRequest] = useState<ComplianceScanRequest>({
    remediationMode: 'report_only',
    emailNotifications: true,
    generateReports: true,
    concurrentScans: 5,
    scanTimeout: 3600,
  });

  const showAlert = (message: string, severity: 'success' | 'error' | 'warning' | 'info') => {
    setAlertMessage(message);
    setAlertSeverity(severity);
    setTimeout(() => setAlertMessage(null), 5000);
  };

  // Load SCAP content bundles and check for active scans when component mounts or groupId changes
  // ESLint disable: Functions loadScapContents and checkActiveScan are not memoized
  // to avoid complex dependency chains. They only need to run when groupId changes.
  useEffect(() => {
    loadScapContents();
    checkActiveScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupId]);

  const loadScapContents = async () => {
    try {
      // MongoDB compliance rules endpoint - returns bundles that can be used for scanning
      const response = await fetch('/api/compliance-rules/?view_mode=bundles', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        // MongoDB returns bundles in 'bundles' field
        setScapContents(
          Array.isArray(data.bundles) ? data.bundles : Array.isArray(data) ? data : []
        );
      } else {
        setScapContents([]);
        showAlert('Failed to load SCAP content', 'error');
      }
    } catch (error) {
      console.error('Failed to load SCAP contents:', error);
      setScapContents([]);
      showAlert('Failed to load SCAP content', 'error');
    }
  };

  const loadProfiles = async (contentId: number) => {
    try {
      // Get profiles from the selected bundle (bundles include profiles array)
      const selectedContent = scapContents.find((content) => content.id === contentId);
      if (selectedContent && selectedContent.profiles) {
        setProfiles(Array.isArray(selectedContent.profiles) ? selectedContent.profiles : []);
      } else {
        setProfiles([]);
        showAlert('No profiles found for selected content', 'warning');
      }
    } catch (error) {
      console.error('Failed to load profiles:', error);
      setProfiles([]);
      showAlert('Failed to load profiles', 'error');
    }
  };

  const checkActiveScan = async () => {
    try {
      const response = await fetch(`/api/group-compliance/${groupId}/active-scan`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        if (data.session_id) {
          setCurrentScan(data);
          monitorScanProgress(data.session_id);
        }
      }
    } catch {
      // No active scan found - this is an expected state (not an error condition)
    }
  };

  const startComplianceScan = async () => {
    if (!scanRequest.scapContentId) {
      showAlert('Please select SCAP content', 'error');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`/api/group-compliance/${groupId}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify({
          scap_content_id: scanRequest.scapContentId,
          profile_id: scanRequest.profileId,
          compliance_framework: scanRequest.complianceFramework,
          remediation_mode: scanRequest.remediationMode,
          email_notifications: scanRequest.emailNotifications,
          generate_reports: scanRequest.generateReports,
          concurrent_scans: scanRequest.concurrentScans,
          scan_timeout: scanRequest.scanTimeout,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setCurrentScan(data);
        showAlert('Compliance scan started successfully', 'success');

        if (onScanStarted) {
          onScanStarted(data.session_id);
        }

        // Start monitoring progress
        monitorScanProgress(data.session_id);
      } else {
        const error = await response.json();
        showAlert(`Failed to start scan: ${error.detail}`, 'error');
      }
    } catch {
      // Generic error fallback - specific error details already shown in if block above
      showAlert('Failed to start compliance scan', 'error');
    } finally {
      setLoading(false);
    }
  };

  const monitorScanProgress = async (sessionId: string) => {
    const pollProgress = async () => {
      try {
        const response = await fetch(`/api/group-compliance/sessions/${sessionId}/progress`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          },
        });

        if (response.ok) {
          const progress = await response.json();
          // Merge new progress data with existing scan session data
          setCurrentScan((prev) => (prev ? { ...prev, ...progress } : progress));

          if (progress.status === 'completed' || progress.status === 'failed') {
            if (progress.status === 'completed') {
              showAlert('Compliance scan completed', 'success');
            } else {
              showAlert('Compliance scan failed', 'error');
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
      const response = await fetch(
        `/api/group-compliance/sessions/${currentScan.session_id}/cancel`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          },
        }
      );

      if (response.ok) {
        showAlert('Scan cancelled', 'info');
        setCurrentScan(null);
      }
    } catch {
      // Network or other failure during cancellation
      showAlert('Failed to cancel scan', 'error');
    }
  };

  // Reserved for future status display enhancement
  // These helper functions will be used when adding status badges to scan results
  const _getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle color="success" />;
      case 'failed':
        return <Error color="error" />;
      case 'in_progress':
        return <Info color="info" />;
      case 'cancelled':
        return <Warning color="warning" />;
      default:
        return <Info color="disabled" />;
    }
  };

  const _getStatusColor = (
    status: string
  ): 'success' | 'error' | 'warning' | 'info' | 'default' => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'failed':
        return 'error';
      case 'cancelled':
        return 'warning';
      case 'in_progress':
        return 'info';
      default:
        return 'default';
    }
  };

  return (
    <Box>
      {/* Alert Messages */}
      {alertMessage && (
        <Alert severity={alertSeverity} sx={{ mb: 2 }} onClose={() => setAlertMessage(null)}>
          {alertMessage}
        </Alert>
      )}

      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="between" mb={2}>
            <Typography variant="h5" component="h2" display="flex" alignItems="center" gap={1}>
              <Security color="primary" />
              Group Compliance Scanning
            </Typography>
          </Box>

          <Typography variant="subtitle1" color="textSecondary" gutterBottom>
            {groupName} • Comprehensive compliance scanning for all hosts in group
          </Typography>

          {/* Current Scan Status */}
          {currentScan && (
            <Alert
              severity={
                currentScan.status === 'in_progress'
                  ? 'info'
                  : currentScan.status === 'completed'
                    ? 'success'
                    : 'error'
              }
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
                Scan Status: <strong>{currentScan.status}</strong> • Progress:{' '}
                {currentScan.completed_hosts || 0}/{currentScan.total_hosts || 0} hosts
              </Typography>
              {currentScan.status === 'in_progress' && (
                <LinearProgress
                  variant="determinate"
                  value={
                    ((currentScan.completed_hosts || 0) / (currentScan.total_hosts || 1)) * 100
                  }
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
                    setScanRequest((prev) => ({ ...prev, scapContentId: contentId }));
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
                  onChange={(e) =>
                    setScanRequest((prev) => ({
                      ...prev,
                      profileId: e.target.value as string,
                    }))
                  }
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
                  onChange={(e) =>
                    setScanRequest((prev) => ({
                      ...prev,
                      complianceFramework: e.target.value as string,
                    }))
                  }
                  label="Compliance Framework"
                >
                  {Object.entries(ComplianceFrameworks).map(([key, label]) => (
                    <MenuItem key={key} value={key}>
                      {label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Remediation Mode</InputLabel>
                <Select
                  value={scanRequest.remediationMode}
                  onChange={(e) =>
                    setScanRequest((prev) => ({
                      ...prev,
                      remediationMode: e.target.value as string,
                    }))
                  }
                  label="Remediation Mode"
                >
                  {Object.entries(RemediationModes).map(([key, label]) => (
                    <MenuItem key={key} value={key}>
                      {label}
                    </MenuItem>
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
                      onChange={(e) =>
                        setScanRequest((prev) => ({
                          ...prev,
                          emailNotifications: e.target.checked,
                        }))
                      }
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
                      onChange={(e) =>
                        setScanRequest((prev) => ({
                          ...prev,
                          generateReports: e.target.checked,
                        }))
                      }
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
              disabled={loading || currentScan?.status === 'in_progress'}
              size="large"
            >
              {loading ? 'Starting...' : 'Start Compliance Scan'}
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};
