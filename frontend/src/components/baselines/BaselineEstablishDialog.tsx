/**
 * Baseline Establishment Dialog
 *
 * Allows users to establish a compliance baseline from a completed scan.
 * Baselines are used for drift detection per NIST SP 800-137 Continuous Monitoring.
 *
 * Security:
 * - Requires scan_manager or super_admin role
 * - Validates scan belongs to host
 * - Confirms scan is completed before allowing baseline establishment
 */

import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Typography,
  Alert,
  Box,
  CircularProgress,
  Table,
  TableBody,
  TableRow,
  TableCell,
} from '@mui/material';
import { Check as CheckIcon, Warning as WarningIcon } from '@mui/icons-material';
import { api } from '../../services/api';

interface BaselineEstablishDialogProps {
  open: boolean;
  onClose: () => void;
  hostId: string;
  hostname: string;
  onBaselineEstablished?: () => void;
}

interface Scan {
  id: string;
  profile_id: string;
  status: string;
  score: number;
  passed_rules: number;
  failed_rules: number;
  total_rules: number;
  completed_at: string;
  severity_critical_passed: number;
  severity_critical_failed: number;
  severity_high_passed: number;
  severity_high_failed: number;
  severity_medium_passed: number;
  severity_medium_failed: number;
  severity_low_passed: number;
  severity_low_failed: number;
}

const BaselineEstablishDialog: React.FC<BaselineEstablishDialogProps> = ({
  open,
  onClose,
  hostId,
  hostname,
  onBaselineEstablished,
}) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [baselineType, setBaselineType] = useState<string>('manual');
  const [error, setError] = useState<string>('');
  const [establishing, setEstablishing] = useState<boolean>(false);

  useEffect(() => {
    if (open && hostId) {
      fetchCompletedScans();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, hostId]);

  const fetchCompletedScans = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await api.get(`/api/scans`, {
        params: {
          host_id: hostId,
          status: 'completed',
          limit: 10,
        },
      });

      const completedScans = response.data.scans || [];
      setScans(completedScans);

      if (completedScans.length > 0) {
        setSelectedScan(completedScans[0].id);
      }
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to fetch scans');
    } finally {
      setLoading(false);
    }
  };

  const handleEstablishBaseline = async () => {
    if (!selectedScan) {
      setError('Please select a scan to use as baseline');
      return;
    }

    setEstablishing(true);
    setError('');

    try {
      await api.post(`/api/hosts/${hostId}/baseline`, {
        scan_id: selectedScan,
        baseline_type: baselineType,
      });

      if (onBaselineEstablished) {
        onBaselineEstablished();
      }

      onClose();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || 'Failed to establish baseline');
    } finally {
      setEstablishing(false);
    }
  };

  const selectedScanData = scans.find((s) => s.id === selectedScan);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Establish Compliance Baseline - {hostname}</DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="body2">
            Establishing a baseline allows OpenWatch to detect compliance drift over time. When
            future scans deviate significantly from this baseline, alerts will be triggered.
          </Typography>
        </Alert>

        {loading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : scans.length === 0 ? (
          <Alert severity="warning">
            <Typography variant="body2">
              No completed scans found for this host. Please run a scan before establishing a
              baseline.
            </Typography>
          </Alert>
        ) : (
          <>
            <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
              <FormLabel component="legend">Select Scan for Baseline</FormLabel>
              <RadioGroup value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)}>
                {scans.map((scan) => (
                  <FormControlLabel
                    key={scan.id}
                    value={scan.id}
                    control={<Radio />}
                    label={
                      <Box>
                        <Typography variant="body2">
                          <strong>{new Date(scan.completed_at).toLocaleString()}</strong> - Score:{' '}
                          {scan.score.toFixed(1)}% ({scan.passed_rules}/{scan.total_rules} rules
                          passed)
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {scan.profile_id}
                        </Typography>
                      </Box>
                    }
                  />
                ))}
              </RadioGroup>
            </FormControl>

            <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
              <FormLabel component="legend">Baseline Type</FormLabel>
              <RadioGroup value={baselineType} onChange={(e) => setBaselineType(e.target.value)}>
                <FormControlLabel
                  value="manual"
                  control={<Radio />}
                  label={
                    <Box>
                      <Typography variant="body2">
                        <strong>Manual Baseline</strong>
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Explicitly chosen baseline for this host
                      </Typography>
                    </Box>
                  }
                />
                <FormControlLabel
                  value="initial"
                  control={<Radio />}
                  label={
                    <Box>
                      <Typography variant="body2">
                        <strong>Initial Baseline</strong>
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        First baseline established for this host
                      </Typography>
                    </Box>
                  }
                />
              </RadioGroup>
            </FormControl>

            {selectedScanData && (
              <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Baseline Summary
                </Typography>
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell>Overall Score</TableCell>
                      <TableCell align="right">
                        <strong>{selectedScanData.score.toFixed(1)}%</strong>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Total Rules</TableCell>
                      <TableCell align="right">{selectedScanData.total_rules}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Passed Rules</TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          <CheckIcon fontSize="small" color="success" sx={{ mr: 0.5 }} />
                          {selectedScanData.passed_rules}
                        </Box>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Failed Rules</TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          <WarningIcon fontSize="small" color="error" sx={{ mr: 0.5 }} />
                          {selectedScanData.failed_rules}
                        </Box>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Critical (Pass/Fail)</TableCell>
                      <TableCell align="right">
                        {selectedScanData.severity_critical_passed || 0} /{' '}
                        {selectedScanData.severity_critical_failed || 0}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>High (Pass/Fail)</TableCell>
                      <TableCell align="right">
                        {selectedScanData.severity_high_passed || 0} /{' '}
                        {selectedScanData.severity_high_failed || 0}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Medium (Pass/Fail)</TableCell>
                      <TableCell align="right">
                        {selectedScanData.severity_medium_passed || 0} /{' '}
                        {selectedScanData.severity_medium_failed || 0}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Low (Pass/Fail)</TableCell>
                      <TableCell align="right">
                        {selectedScanData.severity_low_passed || 0} /{' '}
                        {selectedScanData.severity_low_failed || 0}
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </Box>
            )}
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={establishing}>
          Cancel
        </Button>
        <Button
          onClick={handleEstablishBaseline}
          variant="contained"
          color="primary"
          disabled={loading || scans.length === 0 || !selectedScan || establishing}
          startIcon={establishing ? <CircularProgress size={20} /> : null}
        >
          {establishing ? 'Establishing...' : 'Establish Baseline'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BaselineEstablishDialog;
