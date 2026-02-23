/**
 * Compliance Tab
 *
 * Displays detailed compliance findings from the most recent Kensa scan
 * with filtering and search capabilities.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/ComplianceTab
 */

import React, { useState, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  TextField,
  InputAdornment,
  Alert,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Search as SearchIcon,
} from '@mui/icons-material';
import type { ComplianceState } from '../../../../types/hostDetail';

interface ComplianceTabProps {
  complianceState: ComplianceState | null | undefined;
  isLoading?: boolean;
}

type FilterType = 'all' | 'pass' | 'fail';

/**
 * Get icon for finding status
 */
function getStatusIcon(status: string) {
  switch (status) {
    case 'pass':
      return <CheckCircleIcon color="success" fontSize="small" />;
    case 'fail':
      return <ErrorIcon color="error" fontSize="small" />;
    default:
      return <InfoIcon color="disabled" fontSize="small" />;
  }
}

/**
 * Get color for severity chip
 */
function getSeverityColor(severity: string): 'error' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'critical':
      return 'error';
    case 'high':
      return 'warning';
    case 'medium':
      return 'info';
    default:
      return 'default';
  }
}

const ComplianceTab: React.FC<ComplianceTabProps> = ({ complianceState, isLoading }) => {
  const [filter, setFilter] = useState<FilterType>('all');
  const [search, setSearch] = useState('');

  // Filter and search findings
  const filteredFindings = useMemo(() => {
    const findings = complianceState?.findings ?? [];
    return findings.filter((finding) => {
      // Apply status filter
      if (filter !== 'all' && finding.status !== filter) {
        return false;
      }

      // Apply search
      if (search) {
        const searchLower = search.toLowerCase();
        return (
          finding.title.toLowerCase().includes(searchLower) ||
          finding.ruleId.toLowerCase().includes(searchLower) ||
          (finding.detail?.toLowerCase().includes(searchLower) ?? false)
        );
      }

      return true;
    });
  }, [complianceState, filter, search]);

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  if (!complianceState || complianceState.totalRules === 0) {
    return (
      <Alert severity="info">
        Awaiting first compliance scan. Scans run automatically based on the adaptive schedule.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography
                variant="h3"
                color={
                  complianceState.complianceScore >= 80
                    ? 'success.main'
                    : complianceState.complianceScore >= 60
                      ? 'warning.main'
                      : 'error.main'
                }
              >
                {complianceState.complianceScore.toFixed(1)}%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Compliance Score
              </Typography>
              {complianceState.scanDate && (
                <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                  Last scanned: {new Date(complianceState.scanDate).toLocaleString()}
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
                  title={`${complianceState.severitySummary.critical.passed} passed, ${complianceState.severitySummary.critical.failed} failed`}
                >
                  <Chip
                    size="small"
                    color="error"
                    label={`Critical: ${complianceState.severitySummary.critical.failed}`}
                  />
                </Tooltip>
                <Tooltip
                  title={`${complianceState.severitySummary.high.passed} passed, ${complianceState.severitySummary.high.failed} failed`}
                >
                  <Chip
                    size="small"
                    color="warning"
                    label={`High: ${complianceState.severitySummary.high.failed}`}
                  />
                </Tooltip>
                <Tooltip
                  title={`${complianceState.severitySummary.medium.passed} passed, ${complianceState.severitySummary.medium.failed} failed`}
                >
                  <Chip
                    size="small"
                    color="info"
                    label={`Medium: ${complianceState.severitySummary.medium.failed}`}
                  />
                </Tooltip>
                <Tooltip
                  title={`${complianceState.severitySummary.low.passed} passed, ${complianceState.severitySummary.low.failed} failed`}
                >
                  <Chip
                    size="small"
                    variant="outlined"
                    label={`Low: ${complianceState.severitySummary.low.failed}`}
                  />
                </Tooltip>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters and Search */}
      <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center', flexWrap: 'wrap' }}>
        <Typography variant="h6">Rule Findings ({filteredFindings.length})</Typography>
        <Box sx={{ flexGrow: 1 }} />
        <TextField
          size="small"
          placeholder="Search rules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
          sx={{ width: 200 }}
        />
        <Chip
          label="All"
          variant={filter === 'all' ? 'filled' : 'outlined'}
          onClick={() => setFilter('all')}
          clickable
        />
        <Chip
          label="Failed"
          color="error"
          variant={filter === 'fail' ? 'filled' : 'outlined'}
          onClick={() => setFilter('fail')}
          clickable
        />
        <Chip
          label="Passed"
          color="success"
          variant={filter === 'pass' ? 'filled' : 'outlined'}
          onClick={() => setFilter('pass')}
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
            {filteredFindings.map((finding, idx) => (
              <TableRow key={`${finding.ruleId}-${idx}`} hover>
                <TableCell>{getStatusIcon(finding.status)}</TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={finding.severity}
                    color={getSeverityColor(finding.severity)}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {finding.ruleId}
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
            {filteredFindings.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} align="center">
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No findings match the current filter
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default ComplianceTab;
