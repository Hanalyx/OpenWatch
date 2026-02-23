/**
 * Audit Queries Page
 *
 * Displays a list of saved audit queries with options to create, edit, and execute.
 *
 * Part of Phase 6: Audit Queries (Kensa Integration Plan)
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  Tooltip,
  Typography,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogContentText,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  PlayArrow as ExecuteIcon,
  Share as ShareIcon,
  Lock as PrivateIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { useSavedQueries, useQueryStats, useDeleteQuery } from '../../hooks/useAuditQueries';
import type { SavedQuery } from '../../types/audit';

const AuditQueriesPage: React.FC = () => {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [queryToDelete, setQueryToDelete] = useState<SavedQuery | null>(null);

  // Fetch queries
  const {
    data: queriesData,
    isLoading,
    error,
  } = useSavedQueries({
    page: page + 1,
    per_page: rowsPerPage,
  });

  // Fetch stats
  const { data: stats } = useQueryStats();

  // Delete mutation
  const deleteQuery = useDeleteQuery();

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleCreateQuery = () => {
    navigate('/audit/queries/new');
  };

  const handleEditQuery = (queryId: string) => {
    navigate(`/audit/queries/${queryId}/edit`);
  };

  const handleExecuteQuery = (queryId: string) => {
    navigate(`/audit/queries/${queryId}/execute`);
  };

  const handleDeleteClick = (query: SavedQuery) => {
    setQueryToDelete(query);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (queryToDelete) {
      await deleteQuery.mutateAsync(queryToDelete.id);
      setDeleteDialogOpen(false);
      setQueryToDelete(null);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Failed to load queries: {error.message}
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Audit Queries</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreateQuery}>
          Create Query
        </Button>
      </Box>

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="primary">
                  {stats.total_queries}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Queries
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="info.main">
                  {stats.my_queries}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  My Queries
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="secondary.main">
                  {stats.shared_queries}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Shared Queries
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="success.main">
                  {stats.total_executions}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Executions
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Queries Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell align="center">Visibility</TableCell>
              <TableCell align="center">Executions</TableCell>
              <TableCell>Last Executed</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {queriesData?.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                  <Typography color="text.secondary">
                    No queries found. Create your first query to get started.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              queriesData?.items.map((query) => (
                <TableRow key={query.id} hover>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body1" fontWeight="medium">
                        {query.name}
                      </Typography>
                      {query.has_date_range && (
                        <Tooltip title="Uses date range filter (OpenWatch+)">
                          <ScheduleIcon fontSize="small" color="info" />
                        </Tooltip>
                      )}
                    </Box>
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
                      {query.description || '-'}
                    </Typography>
                  </TableCell>
                  <TableCell align="center">
                    {query.visibility === 'shared' ? (
                      <Chip
                        icon={<ShareIcon />}
                        label="Shared"
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    ) : (
                      <Chip
                        icon={<PrivateIcon />}
                        label="Private"
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </TableCell>
                  <TableCell align="center">
                    <Typography variant="body2">{query.execution_count}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {formatDate(query.last_executed_at)}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Execute Query">
                      <IconButton
                        size="small"
                        color="primary"
                        onClick={() => handleExecuteQuery(query.id)}
                      >
                        <ExecuteIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Edit Query">
                      <IconButton size="small" onClick={() => handleEditQuery(query.id)}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete Query">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteClick(query)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={queriesData?.total || 0}
          page={page}
          onPageChange={handleChangePage}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          rowsPerPageOptions={[5, 10, 25, 50]}
        />
      </TableContainer>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Query</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete the query &quot;{queryToDelete?.name}&quot;? This action
            cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleDeleteConfirm} color="error" disabled={deleteQuery.isPending}>
            {deleteQuery.isPending ? <CircularProgress size={20} /> : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AuditQueriesPage;
