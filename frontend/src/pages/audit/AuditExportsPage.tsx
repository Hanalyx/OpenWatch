/**
 * Audit Exports Page
 *
 * Displays export history with status polling and download links.
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
  LinearProgress,
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
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  CheckCircle as CompleteIcon,
  Error as ErrorIcon,
  HourglassEmpty as PendingIcon,
  Sync as ProcessingIcon,
} from '@mui/icons-material';
import {
  useExports,
  useExportStats,
  useDownloadExport,
  auditQueryKeys,
} from '../../hooks/useAuditQueries';
import { useQueryClient } from '@tanstack/react-query';
import type { AuditExport, ExportStatus } from '../../types/audit';

const AuditExportsPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  // Fetch exports
  const {
    data: exportsData,
    isLoading,
    error,
  } = useExports({
    page: page + 1,
    per_page: rowsPerPage,
  });

  // Fetch stats
  const { data: stats } = useExportStats();

  // Download mutation
  const downloadExport = useDownloadExport();

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: auditQueryKeys.exports() });
  };

  const handleDownload = async (exportItem: AuditExport) => {
    const filename = `audit_export_${exportItem.id}.${exportItem.format}`;
    await downloadExport.mutateAsync({ exportId: exportItem.id, filename });
  };

  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return '-';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusIcon = (status: ExportStatus) => {
    switch (status) {
      case 'completed':
        return <CompleteIcon color="success" />;
      case 'failed':
        return <ErrorIcon color="error" />;
      case 'processing':
        return <ProcessingIcon color="info" />;
      case 'pending':
      default:
        return <PendingIcon color="action" />;
    }
  };

  const getStatusChip = (status: ExportStatus) => {
    const statusConfig = {
      pending: { label: 'Pending', color: 'default' as const },
      processing: { label: 'Processing', color: 'info' as const },
      completed: { label: 'Completed', color: 'success' as const },
      failed: { label: 'Failed', color: 'error' as const },
    };

    const config = statusConfig[status] || statusConfig.pending;

    return (
      <Chip
        icon={getStatusIcon(status)}
        label={config.label}
        size="small"
        color={config.color}
        variant="outlined"
      />
    );
  };

  const getFormatLabel = (format: string) => {
    switch (format) {
      case 'csv':
        return 'CSV';
      case 'json':
        return 'JSON';
      case 'pdf':
        return 'PDF';
      default:
        return format.toUpperCase();
    }
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
        Failed to load exports: {error.message}
      </Alert>
    );
  }

  const hasProcessing = exportsData?.items.some(
    (e) => e.status === 'pending' || e.status === 'processing'
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Audit Exports</Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={handleRefresh}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => navigate('/audit/queries/new')}
          >
            Create Export
          </Button>
        </Box>
      </Box>

      {/* Processing indicator */}
      {hasProcessing && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <CircularProgress size={20} />
            <Typography variant="body2">
              Exports are being processed. This page will auto-refresh.
            </Typography>
          </Box>
        </Alert>
      )}

      {/* Stats Cards */}
      {stats && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid size={{ xs: 6, sm: 2.4 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="primary">
                  {stats.total_exports}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Exports
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 2.4 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="text.secondary">
                  {stats.pending}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Pending
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 2.4 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="info.main">
                  {stats.processing}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Processing
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 2.4 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="success.main">
                  {stats.completed}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Completed
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 2.4 }}>
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" color="error.main">
                  {stats.failed}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Failed
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Exports Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Format</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Size</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Completed</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {exportsData?.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                  <Typography color="text.secondary">
                    No exports found. Create a query to export results.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              exportsData?.items.map((exportItem) => (
                <TableRow key={exportItem.id} hover>
                  <TableCell>
                    <Chip
                      label={getFormatLabel(exportItem.format)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    {exportItem.status === 'processing' ? (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusChip(exportItem.status)}
                        <Box sx={{ width: 60 }}>
                          <LinearProgress />
                        </Box>
                      </Box>
                    ) : (
                      getStatusChip(exportItem.status)
                    )}
                    {exportItem.error_message && (
                      <Typography
                        variant="caption"
                        color="error"
                        sx={{ display: 'block', mt: 0.5 }}
                      >
                        {exportItem.error_message}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{formatFileSize(exportItem.file_size_bytes)}</TableCell>
                  <TableCell>
                    <Typography variant="body2">{formatDate(exportItem.created_at)}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {formatDate(exportItem.completed_at)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="body2"
                      color={exportItem.is_expired ? 'error' : 'text.secondary'}
                    >
                      {formatDate(exportItem.expires_at)}
                      {exportItem.is_expired && (
                        <Chip label="Expired" size="small" color="error" sx={{ ml: 1 }} />
                      )}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    {exportItem.is_ready && !exportItem.is_expired && (
                      <Tooltip title="Download">
                        <IconButton
                          color="primary"
                          onClick={() => handleDownload(exportItem)}
                          disabled={downloadExport.isPending}
                        >
                          {downloadExport.isPending ? (
                            <CircularProgress size={20} />
                          ) : (
                            <DownloadIcon />
                          )}
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={exportsData?.total || 0}
          page={page}
          onPageChange={handleChangePage}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          rowsPerPageOptions={[5, 10, 25, 50]}
        />
      </TableContainer>
    </Box>
  );
};

export default AuditExportsPage;
