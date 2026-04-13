import React, { useState, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
  IconButton,
  Stack,
} from '@mui/material';
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';
import {
  transactionService,
  type TransactionListResponse,
  type Transaction,
} from '../../services/adapters/transactionAdapter';

const statusColor = (s: string) => (s === 'pass' ? 'success' : s === 'fail' ? 'error' : 'default');

const RuleTransactions: React.FC = () => {
  const { ruleId } = useParams<{ ruleId: string }>();
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);

  const queryParams = useMemo(
    () => ({
      page: page + 1,
      per_page: rowsPerPage,
    }),
    [page, rowsPerPage]
  );

  const { data, isLoading, error } = useQuery<TransactionListResponse>({
    queryKey: ['rule-transactions', ruleId, queryParams],
    queryFn: () =>
      transactionService.getRuleTransactions(
        ruleId || '',
        queryParams
      ) as unknown as Promise<TransactionListResponse>,
    enabled: !!ruleId,
    staleTime: 30_000,
  });

  const transactions = (data?.items || []) as Array<Transaction & { host_name?: string }>;
  const total = data?.total || 0;

  const handleRowClick = useCallback(
    (id: string) => {
      navigate(`/transactions/${id}`);
    },
    [navigate]
  );

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
          <IconButton onClick={() => navigate('/transactions')} size="small">
            <ArrowBackIcon />
          </IconButton>
          <Typography variant="h4" component="h1">
            {ruleId}
          </Typography>
        </Stack>
        <Typography variant="body1" color="text.secondary">
          State changes for this rule across all hosts
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Failed to load rule transactions
        </Alert>
      )}

      <TableContainer component={Paper}>
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
            <CircularProgress />
          </Box>
        ) : transactions.length === 0 ? (
          <Box sx={{ py: 6, textAlign: 'center' }}>
            <Typography color="text.secondary">No state changes recorded for this rule</Typography>
          </Box>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Host</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Changed At</TableCell>
                <TableCell>Initiator</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {transactions.map((t) => (
                <TableRow
                  key={t.id}
                  hover
                  sx={{ cursor: 'pointer' }}
                  onClick={() => handleRowClick(t.id)}
                >
                  <TableCell>
                    {(t as unknown as Record<string, string>).host_name || t.host_id}
                  </TableCell>
                  <TableCell>
                    <Chip label={t.status} color={statusColor(t.status)} size="small" />
                  </TableCell>
                  <TableCell>{t.severity}</TableCell>
                  <TableCell>
                    {t.started_at ? new Date(t.started_at).toLocaleString() : '-'}
                  </TableCell>
                  <TableCell>{t.initiator_type}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
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
      </TableContainer>
    </Box>
  );
};

export default RuleTransactions;
