import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  Alert,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { api } from '../services/api';

interface ReadinessCheck {
  check_type: string;
  check_name: string;
  passed: boolean;
  severity: 'info' | 'warning' | 'error';
  message: string;
  details: Record<string, any>;
  check_duration_ms?: number;
}

interface ReadinessResult {
  host_id: string;
  hostname: string;
  ip_address?: string;
  status: 'ready' | 'not_ready' | 'degraded';
  overall_passed: boolean;
  checks: ReadinessCheck[];
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warnings_count: number;
  validation_duration_ms: number;
  completed_at: string;
}

interface ReadinessDialogProps {
  open: boolean;
  onClose: () => void;
  hostId: string; // Empty string = bulk validation (all hosts)
  hostname: string;
}

const ReadinessDialog: React.FC<ReadinessDialogProps> = ({ open, onClose, hostId, hostname }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReadinessResult | null>(null);

  const getSeverityIcon = (severity: string, passed: boolean) => {
    if (!passed && severity === 'error') return <ErrorIcon color="error" />;
    if (!passed && severity === 'warning') return <WarningIcon color="warning" />;
    if (passed) return <CheckCircleIcon color="success" />;
    return <InfoIcon color="info" />;
  };

  const getSeverityColor = (
    severity: string,
    passed: boolean
  ): 'success' | 'error' | 'warning' | 'info' => {
    if (!passed && severity === 'error') return 'error';
    if (!passed && severity === 'warning') return 'warning';
    if (passed) return 'success';
    return 'info';
  };

  const getStatusColor = (status: string): 'success' | 'error' | 'warning' => {
    switch (status) {
      case 'ready':
        return 'success';
      case 'not_ready':
        return 'error';
      case 'degraded':
        return 'warning';
      default:
        return 'warning';
    }
  };

  const handleValidate = async () => {
    try {
      setLoading(true);
      setError(null);

      // If hostId is empty, validate all hosts (bulk validation)
      const requestBody = hostId
        ? {
            host_ids: [hostId],
            parallel: false,
            use_cache: true,
            cache_ttl_hours: 1,
          }
        : {
            host_ids: [], // Empty = all hosts
            parallel: true,
            use_cache: true,
            cache_ttl_hours: 1,
          };

      const response = await api.post('/api/v1/scans/readiness/validate-bulk', requestBody);

      if (response.hosts && response.hosts.length > 0) {
        // For single host validation, show the first result
        // For bulk validation, we'll need to update the UI to show multiple results
        // For now, just show the first host's results
        setResult(response.hosts[0]);
      } else {
        setError('No validation results returned');
      }
    } catch (err: any) {
      console.error('Validation failed:', err);
      setError(err.message || 'Failed to validate host readiness');
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    if (open && !result) {
      handleValidate();
    }
  }, [open]);

  const handleClose = () => {
    setResult(null);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h6">Host Readiness Validation</Typography>
          {result && (
            <Chip
              label={result.status.replace('_', ' ').toUpperCase()}
              color={getStatusColor(result.status)}
              icon={result.overall_passed ? <CheckCircleIcon /> : <ErrorIcon />}
            />
          )}
        </Box>
        <Typography variant="body2" color="text.secondary">
          {hostname}
        </Typography>
      </DialogTitle>

      <DialogContent>
        {loading && (
          <Box sx={{ py: 4, textAlign: 'center' }}>
            <CircularProgress />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Running readiness checks...
            </Typography>
          </Box>
        )}

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {result && !loading && (
          <Box>
            {/* Summary Stats */}
            <Box
              sx={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, 1fr)',
                gap: 2,
                mb: 3,
              }}
            >
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Typography variant="h4" color="success.main">
                  {result.passed_checks}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Passed
                </Typography>
              </Paper>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Typography variant="h4" color="error.main">
                  {result.failed_checks}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Failed
                </Typography>
              </Paper>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Typography variant="h4" color="warning.main">
                  {result.warnings_count}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Warnings
                </Typography>
              </Paper>
              <Paper sx={{ p: 2, textAlign: 'center' }}>
                <Typography variant="h4">{result.total_checks}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Total Checks
                </Typography>
              </Paper>
            </Box>

            {/* Progress Bar */}
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2">
                  Compliance: {result.passed_checks} / {result.total_checks}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {result.total_checks > 0
                    ? `${((result.passed_checks / result.total_checks) * 100).toFixed(1)}%`
                    : '0%'}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={
                  result.total_checks > 0 ? (result.passed_checks / result.total_checks) * 100 : 0
                }
                color={result.overall_passed ? 'success' : 'error'}
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>

            {/* Check Results */}
            <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}>
              Check Results
            </Typography>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {result.checks.map((check, index) => (
                <Accordion key={index} defaultExpanded={!check.passed}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        width: '100%',
                        pr: 2,
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        {getSeverityIcon(check.severity, check.passed)}
                        <Typography variant="body1" fontWeight="medium">
                          {check.check_name}
                        </Typography>
                      </Box>
                      <Chip
                        label={check.passed ? 'PASS' : 'FAIL'}
                        color={getSeverityColor(check.severity, check.passed)}
                        size="small"
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {check.message}
                      </Typography>

                      {/* Details */}
                      {Object.keys(check.details).length > 0 && (
                        <TableContainer component={Paper} variant="outlined" sx={{ mb: 2 }}>
                          <Table size="small">
                            <TableBody>
                              {Object.entries(check.details).map(([key, value]) => (
                                <TableRow key={key}>
                                  <TableCell sx={{ fontWeight: 'medium', width: '30%' }}>
                                    {key.replace(/_/g, ' ').toUpperCase()}
                                  </TableCell>
                                  <TableCell>
                                    {typeof value === 'object'
                                      ? JSON.stringify(value, null, 2)
                                      : String(value)}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      )}

                      {/* Remediation */}
                      {check.details.remediation && (
                        <Alert severity="info" sx={{ mt: 2 }}>
                          <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                            Remediation
                          </Typography>
                          <Typography
                            variant="body2"
                            component="pre"
                            sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}
                          >
                            {check.details.remediation}
                          </Typography>
                        </Alert>
                      )}

                      {/* Duration */}
                      {check.check_duration_ms && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: 'block', mt: 1 }}
                        >
                          Check completed in {check.check_duration_ms.toFixed(0)}ms
                        </Typography>
                      )}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>

            {/* Validation Duration */}
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
              Total validation time: {result.validation_duration_ms.toFixed(0)}ms
            </Typography>
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        {result && (
          <Button onClick={handleValidate} disabled={loading}>
            Re-validate
          </Button>
        )}
        <Button onClick={handleClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ReadinessDialog;
