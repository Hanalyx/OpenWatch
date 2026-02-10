/**
 * History Tab
 *
 * Displays scan history with compliance scores and results.
 * Includes compliance trend chart.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/HistoryTab
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  LinearProgress,
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  HourglassEmpty as HourglassEmptyIcon,
  PlayArrow as PlayArrowIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import ComplianceTrendChart from '../../../../components/baselines/ComplianceTrendChart';
import type { ScanHistoryItem } from '../../../../types/hostDetail';

interface HistoryTabProps {
  scanHistory: ScanHistoryItem[];
  isLoading?: boolean;
}

/**
 * Get icon for scan status
 */
function getStatusIcon(status: string) {
  switch (status) {
    case 'completed':
      return <CheckCircleIcon color="success" fontSize="small" />;
    case 'running':
      return <PlayArrowIcon color="primary" fontSize="small" />;
    case 'failed':
      return <ErrorIcon color="error" fontSize="small" />;
    case 'cancelled':
      return <CancelIcon color="disabled" fontSize="small" />;
    default:
      return <HourglassEmptyIcon color="disabled" fontSize="small" />;
  }
}

/**
 * Get color for status chip
 */
function getStatusColor(status: string): 'success' | 'primary' | 'error' | 'default' {
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
}

/**
 * Calculate scan duration
 */
function getDuration(startedAt: string, completedAt: string | null): string {
  if (!completedAt) return '-';
  const start = new Date(startedAt);
  const end = new Date(completedAt);
  const seconds = Math.round((end.getTime() - start.getTime()) / 1000);

  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

const HistoryTab: React.FC<HistoryTabProps> = ({ scanHistory, isLoading }) => {
  const navigate = useNavigate();

  // Transform scan history for trend chart
  const trendData = scanHistory
    .filter((scan) => scan.completedAt && scan.results)
    .map((scan) => ({
      timestamp: scan.completedAt!,
      score: parseFloat(scan.results?.score || '0'),
      passed_rules: scan.results?.passedRules || 0,
      failed_rules: scan.results?.failedRules || 0,
      total_rules: scan.results?.totalRules || 0,
      scan_id: scan.id,
    }))
    .reverse(); // Oldest first for chart

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  if (scanHistory.length === 0) {
    return (
      <Alert severity="info">
        No scans have been performed on this host yet. Compliance scans run automatically based on
        the adaptive schedule.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan History ({scanHistory.length} scans)
      </Typography>

      {/* Scan History Table */}
      <TableContainer component={Paper} sx={{ mb: 4 }}>
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
            {scanHistory.map((scan) => {
              const score = scan.results?.score ? parseFloat(scan.results.score) : null;

              return (
                <TableRow key={scan.id} hover>
                  <TableCell>
                    <Box>
                      <Typography variant="body2" fontWeight="medium">
                        {scan.name}
                      </Typography>
                      {scan.contentName && (
                        <Typography variant="caption" color="text.secondary">
                          {scan.contentName}
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getStatusIcon(scan.status)}
                      <Box>
                        <Chip
                          label={scan.status}
                          size="small"
                          color={getStatusColor(scan.status)}
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
                    {score !== null ? (
                      <Chip
                        label={`${score.toFixed(1)}%`}
                        size="small"
                        color={score >= 80 ? 'success' : score >= 60 ? 'warning' : 'error'}
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
                        {(scan.results.severityCritical ?? 0) > 0 && (
                          <Chip
                            label={`${scan.results.severityCritical} Critical`}
                            size="small"
                            color="error"
                          />
                        )}
                        {scan.results.severityHigh > 0 && (
                          <Chip
                            label={`${scan.results.severityHigh} High`}
                            size="small"
                            color="warning"
                          />
                        )}
                        {scan.results.severityMedium > 0 && (
                          <Chip
                            label={`${scan.results.severityMedium} Med`}
                            size="small"
                            color="info"
                          />
                        )}
                      </Box>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        -
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(scan.startedAt).toLocaleString()}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {getDuration(scan.startedAt, scan.completedAt)}
                    </Typography>
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

      {/* Compliance Trend Chart */}
      {trendData.length > 1 && (
        <Box>
          <Typography variant="h6" gutterBottom>
            Compliance Trend
          </Typography>
          <Card>
            <CardContent>
              <ComplianceTrendChart data={trendData} height={300} />
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
};

export default HistoryTab;
