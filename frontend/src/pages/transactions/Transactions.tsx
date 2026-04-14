/**
 * Transactions Page — Rules Summary View
 *
 * Shows each unique compliance rule once with summary stats
 * (hosts passing/failing, state change count). Click on a rule
 * to see its change history across hosts.
 */

import React, { useState, useMemo, useCallback } from 'react';
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
  TablePagination,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  TextField,
  MenuItem,
  Stack,
  LinearProgress,
} from '@mui/material';
import {
  transactionService,
  type RuleSummaryListResponse,
  type RuleSummary,
} from '../../services/adapters/transactionAdapter';

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'] as const;
const STATUS_OPTIONS = ['all', 'pass', 'fail'] as const;
const DEFAULT_PER_PAGE = 50;

function severityColor(s: string | null): 'error' | 'warning' | 'info' | 'default' {
  switch (s) {
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

function formatDate(d: string | null): string {
  if (!d) return '-';
  return new Date(d).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const Transactions: React.FC = () => {
  const navigate = useNavigate();

  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(DEFAULT_PER_PAGE);

  const queryParams = useMemo(() => {
    const params: Record<string, string | number> = {
      page: page + 1,
      per_page: rowsPerPage,
    };
    if (severityFilter !== 'all') params.severity = severityFilter;
    if (statusFilter !== 'all') params.status = statusFilter;
    return params;
  }, [page, rowsPerPage, severityFilter, statusFilter]);

  const { data, isLoading, error } = useQuery<RuleSummaryListResponse>({
    queryKey: ['transaction-rules', queryParams],
    queryFn: () =>
      transactionService.listRules(queryParams) as unknown as Promise<RuleSummaryListResponse>,
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });

  const rules: RuleSummary[] = data?.items || [];
  const total = data?.total || 0;

  const handleRowClick = useCallback(
    (ruleId: string) => {
      navigate(`/transactions/rule/${encodeURIComponent(ruleId)}`);
    },
    [navigate]
  );

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Transactions
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Compliance rules and their state changes across your infrastructure
        </Typography>
      </Box>

      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <TextField
          select
          label="Status"
          value={statusFilter}
          size="small"
          sx={{ minWidth: 150 }}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
        >
          {STATUS_OPTIONS.map((o) => (
            <MenuItem key={o} value={o}>
              {o === 'all' ? 'All Statuses' : o === 'fail' ? 'Has Failures' : 'All Passing'}
            </MenuItem>
          ))}
        </TextField>

        <TextField
          select
          label="Severity"
          value={severityFilter}
          size="small"
          sx={{ minWidth: 150 }}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(0);
          }}
        >
          {SEVERITY_OPTIONS.map((o) => (
            <MenuItem key={o} value={o}>
              {o === 'all' ? 'All Severities' : o.charAt(0).toUpperCase() + o.slice(1)}
            </MenuItem>
          ))}
        </TextField>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Failed to load rules
        </Alert>
      )}

      <TableContainer component={Paper}>
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
            <CircularProgress />
          </Box>
        ) : rules.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 6 }}>
            <Typography color="text.secondary">No rules found</Typography>
          </Box>
        ) : (
          <>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rule</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Compliance</TableCell>
                  <TableCell align="center">Hosts</TableCell>
                  <TableCell align="center">Changes</TableCell>
                  <TableCell>Last Checked</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.map((rule) => {
                  const total_hosts = rule.hosts_passing + rule.hosts_failing + rule.hosts_skipped;
                  const passRate = total_hosts > 0 ? (rule.hosts_passing / total_hosts) * 100 : 0;
                  return (
                    <TableRow
                      key={rule.rule_id}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => handleRowClick(rule.rule_id)}
                    >
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {rule.rule_id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={rule.severity || 'medium'}
                          color={severityColor(rule.severity)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell sx={{ minWidth: 180 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={passRate}
                            color={
                              passRate === 100 ? 'success' : passRate >= 50 ? 'warning' : 'error'
                            }
                            sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
                          />
                          <Typography variant="caption" sx={{ minWidth: 45, textAlign: 'right' }}>
                            {rule.hosts_passing}/{total_hosts}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell align="center">
                        <Typography variant="body2">{rule.host_count}</Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Typography
                          variant="body2"
                          color={rule.change_count > 10 ? 'warning.main' : 'text.primary'}
                        >
                          {rule.change_count}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{formatDate(rule.last_checked_at)}</Typography>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <TablePagination
              component="div"
              count={total}
              page={page}
              onPageChange={(_, p) => setPage(p)}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={(e) => {
                setRowsPerPage(parseInt(e.target.value, 10));
                setPage(0);
              }}
              rowsPerPageOptions={[25, 50, 100]}
            />
          </>
        )}
      </TableContainer>
    </Box>
  );
};

export default Transactions;
