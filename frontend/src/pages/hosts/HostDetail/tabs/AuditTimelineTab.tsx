/**
 * Audit Timeline Tab
 *
 * Displays a reverse-chronological list of compliance transactions for a host.
 * Supports filtering by phase, status, framework, and date range.
 * Provides an export button to queue an audit export for the host.
 *
 * Part of OpenWatch OS - Host Detail Page.
 *
 * @module pages/hosts/HostDetail/tabs/AuditTimelineTab
 */

import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  Button,
  TextField,
  MenuItem,
  TablePagination,
  Snackbar,
} from '@mui/material';
import { FileDownload as ExportIcon } from '@mui/icons-material';
import { transactionService } from '../../../../services/adapters/transactionAdapter';
import { auditAdapter } from '../../../../services/adapters/auditAdapter';
import type { Transaction, TransactionListResponse } from '../../../../services/adapters/transactionAdapter';

interface AuditTimelineTabProps {
  hostId: string;
}

/** Filter state for the timeline */
interface TimelineFilters {
  phase: string;
  status: string;
  framework: string;
  start_date: string;
  end_date: string;
}

const PHASE_OPTIONS = ['', 'check', 'remediate', 'validate', 'rollback'];
const STATUS_OPTIONS = ['', 'pass', 'fail', 'error', 'skip', 'running', 'pending'];

/**
 * Get color for status chip display
 */
function getStatusColor(status: string): 'success' | 'error' | 'warning' | 'info' | 'default' {
  switch (status) {
    case 'pass':
      return 'success';
    case 'fail':
      return 'error';
    case 'error':
      return 'warning';
    case 'running':
      return 'info';
    default:
      return 'default';
  }
}

/**
 * Get color for severity chip display
 */
function getSeverityColor(severity: string | null): 'error' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'default';
  }
}

const AuditTimelineTab: React.FC<AuditTimelineTabProps> = ({ hostId }) => {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [exportSnackbar, setExportSnackbar] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const [filters, setFilters] = useState<TimelineFilters>({
    phase: '',
    status: '',
    framework: '',
    start_date: '',
    end_date: '',
  });

  // Build query params from filters
  const queryParams: Record<string, string | number | boolean | undefined> = {
    page: page + 1,
    per_page: rowsPerPage,
    sort: '-started_at',
  };
  if (filters.phase) queryParams.phase = filters.phase;
  if (filters.status) queryParams.status = filters.status;
  if (filters.framework) queryParams.framework = filters.framework;
  if (filters.start_date) queryParams.start_date = filters.start_date;
  if (filters.end_date) queryParams.end_date = filters.end_date;

  const { data, isLoading, error } = useQuery<TransactionListResponse>({
    queryKey: ['host-audit-timeline', hostId, page, rowsPerPage, filters],
    queryFn: async () => {
      const response = await transactionService.listByHost(hostId, queryParams);
      return response as unknown as TransactionListResponse;
    },
    staleTime: 30_000,
  });

  const handleFilterChange = useCallback(
    (field: keyof TimelineFilters) => (event: React.ChangeEvent<HTMLInputElement>) => {
      setFilters((prev) => ({ ...prev, [field]: event.target.value }));
      setPage(0);
    },
    []
  );

  const handleRowClick = useCallback(
    (transaction: Transaction) => {
      navigate(`/transactions/${transaction.id}`);
    },
    [navigate]
  );

  const handleExport = useCallback(async () => {
    try {
      setExportError(null);
      await auditAdapter.createExport({
        query_definition: {
          hosts: [hostId],
          ...(filters.start_date && filters.end_date
            ? {
                date_range: {
                  start_date: filters.start_date,
                  end_date: filters.end_date,
                },
              }
            : {}),
          ...(filters.status ? { statuses: [filters.status] } : {}),
        },
        format: 'json',
      });
      setExportSnackbar('Audit export queued successfully.');
    } catch {
      setExportError('Failed to queue audit export.');
    }
  }, [hostId, filters]);

  const handleChangePage = useCallback((_: unknown, newPage: number) => {
    setPage(newPage);
  }, []);

  const handleChangeRowsPerPage = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  }, []);

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load audit timeline. Please try again.
      </Alert>
    );
  }

  const transactions = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Audit Timeline</Typography>
        <Button
          variant="outlined"
          startIcon={<ExportIcon />}
          onClick={handleExport}
        >
          Export
        </Button>
      </Box>

      {exportError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setExportError(null)}>
          {exportError}
        </Alert>
      )}

      {/* Filter Controls */}
      <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
        <TextField
          select
          label="Phase"
          value={filters.phase}
          onChange={handleFilterChange('phase')}
          size="small"
          sx={{ minWidth: 140 }}
        >
          <MenuItem value="">All Phases</MenuItem>
          {PHASE_OPTIONS.filter(Boolean).map((phase) => (
            <MenuItem key={phase} value={phase}>
              {phase.charAt(0).toUpperCase() + phase.slice(1)}
            </MenuItem>
          ))}
        </TextField>

        <TextField
          select
          label="Status"
          value={filters.status}
          onChange={handleFilterChange('status')}
          size="small"
          sx={{ minWidth: 140 }}
        >
          <MenuItem value="">All Statuses</MenuItem>
          {STATUS_OPTIONS.filter(Boolean).map((status) => (
            <MenuItem key={status} value={status}>
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </MenuItem>
          ))}
        </TextField>

        <TextField
          label="Framework"
          value={filters.framework}
          onChange={handleFilterChange('framework')}
          size="small"
          placeholder="e.g. cis-rhel9-v2.0.0"
          sx={{ minWidth: 200 }}
        />

        <TextField
          label="Start Date"
          type="date"
          value={filters.start_date}
          onChange={handleFilterChange('start_date')}
          size="small"
          slotProps={{ inputLabel: { shrink: true } }}
          sx={{ minWidth: 160 }}
        />

        <TextField
          label="End Date"
          type="date"
          value={filters.end_date}
          onChange={handleFilterChange('end_date')}
          size="small"
          slotProps={{ inputLabel: { shrink: true } }}
          sx={{ minWidth: 160 }}
        />
      </Box>

      {/* Timeline Table */}
      {transactions.length === 0 ? (
        <Alert severity="info">
          No transactions found for this host with the current filters.
        </Alert>
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Rule ID</TableCell>
                  <TableCell>Phase</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {transactions.map((txn) => (
                  <TableRow
                    key={txn.id}
                    hover
                    sx={{ cursor: 'pointer' }}
                    onClick={() => handleRowClick(txn)}
                  >
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {txn.rule_id || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={txn.phase}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={txn.status}
                        size="small"
                        color={getStatusColor(txn.status)}
                      />
                    </TableCell>
                    <TableCell>
                      {txn.severity ? (
                        <Chip
                          label={txn.severity}
                          size="small"
                          color={getSeverityColor(txn.severity)}
                        />
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {new Date(txn.started_at).toLocaleString()}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {txn.duration_ms != null ? `${(txn.duration_ms / 1000).toFixed(1)}s` : '-'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            component="div"
            count={total}
            page={page}
            onPageChange={handleChangePage}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
          />
        </>
      )}

      <Snackbar
        open={!!exportSnackbar}
        autoHideDuration={4000}
        onClose={() => setExportSnackbar(null)}
        message={exportSnackbar}
      />
    </Box>
  );
};

export default AuditTimelineTab;
