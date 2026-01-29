import React, { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  LinearProgress,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  IconButton,
  Collapse,
  Alert,
  Divider,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  CheckCircle,
  Error as ErrorIcon,
  Schedule,
  PlayArrow,
  Pause,
  Stop,
  Close,
  ExpandMore,
  ExpandLess,
  Timer,
  Assessment,
} from '@mui/icons-material';

interface ScanProgress {
  scan_id: string;
  scan_name: string;
  hostname: string;
  display_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  started_at?: string;
  completed_at?: string;
  compliance_score?: number;
  failed_rules?: number;
  total_rules?: number;
}

interface BulkScanSession {
  session_id: string;
  session_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress_percent: number;
  total_hosts: number;
  completed_hosts: number;
  failed_hosts: number;
  running_hosts: number;
  started_at?: string;
  estimated_completion?: string;
  individual_scans: ScanProgress[];
}

interface BulkScanProgressProps {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  sessionName: string;
  onCancel?: (sessionId: string) => void;
}

const BulkScanProgress: React.FC<BulkScanProgressProps> = ({
  open,
  onClose,
  sessionId,
  sessionName,
  onCancel,
}) => {
  const [session, setSession] = useState<BulkScanSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch session progress
  const fetchProgress = useCallback(async () => {
    try {
      setError(null);

      const response = await fetch(`/api/scans/bulk-scan/${sessionId}/progress`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setSession(data);

        // Stop auto-refresh if session is completed or failed
        if (
          data.status === 'completed' ||
          data.status === 'failed' ||
          data.status === 'cancelled'
        ) {
          setAutoRefresh(false);
        }
      } else {
        const errorData: { detail?: string } = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch progress');
      }
    } catch (err: unknown) {
      // Handle progress fetch errors with proper type checking
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch progress';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  // Auto-refresh effect
  useEffect(() => {
    if (open && sessionId) {
      fetchProgress();

      if (autoRefresh) {
        const interval = setInterval(fetchProgress, 3000); // Refresh every 3 seconds
        return () => clearInterval(interval);
      }
    }
  }, [open, sessionId, autoRefresh, fetchProgress]);

  const handleCancel = async () => {
    if (onCancel) {
      onCancel(sessionId);
    } else {
      try {
        const response = await fetch(`/api/scans/bulk-scan/${sessionId}/cancel`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          },
        });

        if (response.ok) {
          setAutoRefresh(false);
          await fetchProgress(); // Refresh to show cancelled status
        }
      } catch (error) {
        console.error('Failed to cancel bulk scan:', error);
      }
    }
  };

  /**
   * Get MUI Chip color for bulk scan status
   * Maps scan session status to Material-UI color palette values
   */
  const getStatusColor = (status: string): 'success' | 'error' | 'primary' | 'default' => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'failed':
        return 'error';
      case 'running':
        return 'primary';
      case 'cancelled':
        return 'default';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle color="success" />;
      case 'failed':
        return <ErrorIcon color="error" />;
      case 'running':
        return <PlayArrow color="primary" />;
      case 'cancelled':
        return <Stop color="disabled" />;
      default:
        return <Schedule color="disabled" />;
    }
  };

  const formatDuration = (startTime?: string, endTime?: string) => {
    if (!startTime) return 'Not started';

    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const duration = Math.floor((end.getTime() - start.getTime()) / 1000);

    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;

    return `${minutes}m ${seconds}s`;
  };

  const calculateAverageScore = (scans: ScanProgress[]) => {
    const completedScans = scans.filter(
      (scan) => scan.status === 'completed' && scan.compliance_score !== undefined
    );
    if (completedScans.length === 0) return null;

    const totalScore = completedScans.reduce((sum, scan) => sum + (scan.compliance_score || 0), 0);
    return Math.round(totalScore / completedScans.length);
  };

  if (!session && loading) {
    return (
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogContent sx={{ textAlign: 'center', py: 4 }}>
          <LinearProgress sx={{ mb: 2 }} />
          <Typography>Loading scan progress...</Typography>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h6">Bulk Scan Progress</Typography>
            <Typography variant="body2" color="text.secondary">
              {session?.session_name || sessionName}
            </Typography>
          </Box>
          <IconButton onClick={onClose}>
            <Close />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {session && (
          <>
            {/* Overall Progress */}
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    mb: 2,
                  }}
                >
                  <Typography variant="h6">Overall Progress</Typography>
                  <Chip
                    label={session.status.toUpperCase()}
                    color={getStatusColor(session.status)}
                    size="small"
                  />
                </Box>

                <LinearProgress
                  variant="determinate"
                  value={session.progress_percent}
                  sx={{ mb: 2, height: 8, borderRadius: 4 }}
                />

                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {session.progress_percent}%
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Complete
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {session.completed_hosts}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Completed
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {session.running_hosts}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Running
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="error.main">
                        {session.failed_hosts}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Failed
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>

                {session.started_at && (
                  <Box sx={{ mt: 2, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                    <Chip
                      icon={<Timer />}
                      label={`Duration: ${formatDuration(
                        session.started_at,
                        session.status === 'completed' ? session.estimated_completion : undefined
                      )}`}
                      variant="outlined"
                      size="small"
                    />
                    {session.estimated_completion && session.status === 'running' && (
                      <Chip
                        icon={<Schedule />}
                        label={`ETA: ${new Date(session.estimated_completion).toLocaleTimeString()}`}
                        variant="outlined"
                        size="small"
                      />
                    )}
                    {session.completed_hosts > 0 && (
                      <Chip
                        icon={<Assessment />}
                        label={`Avg Score: ${calculateAverageScore(session.individual_scans) || 'N/A'}%`}
                        variant="outlined"
                        size="small"
                      />
                    )}
                  </Box>
                )}
              </CardContent>
            </Card>

            {/* Individual Scans */}
            <Card>
              <CardContent sx={{ pb: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                  }}
                  onClick={() => setExpanded(!expanded)}
                >
                  <Typography variant="h6">Individual Scans ({session.total_hosts})</Typography>
                  <IconButton size="small">{expanded ? <ExpandLess /> : <ExpandMore />}</IconButton>
                </Box>
              </CardContent>

              <Collapse in={expanded}>
                <List dense>
                  {session.individual_scans.map((scan, index) => (
                    <React.Fragment key={scan.scan_id}>
                      <ListItem>
                        <ListItemIcon>{getStatusIcon(scan.status)}</ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="body2" fontWeight="medium">
                                {scan.display_name || scan.hostname}
                              </Typography>
                              <Chip
                                label={scan.status}
                                size="small"
                                color={getStatusColor(scan.status)}
                                variant="outlined"
                              />
                            </Box>
                          }
                          secondary={
                            <Box sx={{ mt: 0.5 }}>
                              {scan.status === 'running' && (
                                <LinearProgress
                                  variant="determinate"
                                  value={scan.progress}
                                  sx={{ mb: 0.5, height: 4 }}
                                />
                              )}
                              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                {scan.started_at && (
                                  <Typography variant="caption" color="text.secondary">
                                    Duration: {formatDuration(scan.started_at, scan.completed_at)}
                                  </Typography>
                                )}
                                {scan.compliance_score !== undefined && (
                                  <Typography variant="caption" color="text.secondary">
                                    • Score: {scan.compliance_score}%
                                  </Typography>
                                )}
                                {scan.failed_rules !== undefined &&
                                  scan.total_rules !== undefined && (
                                    <Typography variant="caption" color="text.secondary">
                                      • {scan.total_rules - scan.failed_rules}/{scan.total_rules}{' '}
                                      passed
                                    </Typography>
                                  )}
                              </Box>
                            </Box>
                          }
                        />
                      </ListItem>
                      {index < session.individual_scans.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              </Collapse>
            </Card>
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button
          onClick={() => setAutoRefresh(!autoRefresh)}
          startIcon={autoRefresh ? <Pause /> : <PlayArrow />}
          variant="outlined"
          size="small"
        >
          {autoRefresh ? 'Pause Updates' : 'Resume Updates'}
        </Button>

        {session?.status === 'running' && (
          <Button
            onClick={handleCancel}
            startIcon={<Stop />}
            color="error"
            variant="outlined"
            size="small"
          >
            Cancel Session
          </Button>
        )}

        <Button onClick={onClose} variant="contained">
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkScanProgress;
