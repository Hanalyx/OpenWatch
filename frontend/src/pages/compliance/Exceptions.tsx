/**
 * Compliance Exceptions Page
 *
 * Displays a paginated, filterable table of compliance exceptions with
 * approval workflow actions. Provides request form dialog and detail view.
 *
 * Spec: specs/frontend/exception-workflow.spec.yaml
 * AC-1: Paginated exception list at /compliance/exceptions
 * AC-2: Request form with justification, risk assessment, expiration
 * AC-3: Approval metadata display
 * AC-4: Escalate button for pending exceptions
 * AC-5: Re-remediation button for excepted rules
 * AC-6: Filter bar (status, rule_id, host_id)
 * AC-7: SECURITY_ADMIN role gating for approve/reject
 *
 * @module pages/compliance/Exceptions
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Paper,
  Chip,
  TextField,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  type SelectChangeEvent,
} from '@mui/material';
import {
  Add,
  CheckCircle,
  Cancel,
  Close,
  ArrowUpward,
  Build,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '../../store/useAuthStore';
import {
  exceptionService,
  type ComplianceException,
  type ExceptionCreateRequest,
} from '../../services/adapters/exceptionAdapter';
import { api } from '../../services/api';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STATUS_OPTIONS = ['all', 'pending', 'approved', 'rejected', 'expired', 'revoked'] as const;

const STATUS_COLORS: Record<string, 'warning' | 'success' | 'error' | 'default' | 'info'> = {
  pending: 'warning',
  approved: 'success',
  rejected: 'error',
  expired: 'default',
  revoked: 'info',
};

/** Roles allowed to approve/reject exceptions */
const ADMIN_ROLES = ['super_admin', 'security_admin', 'compliance_officer'];

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface FilterBarProps {
  statusFilter: string;
  ruleIdFilter: string;
  hostIdFilter: string;
  onStatusChange: (value: string) => void;
  onRuleIdChange: (value: string) => void;
  onHostIdChange: (value: string) => void;
}

/** AC-6: Filter bar with status, rule_id, and host_id filters */
function FilterBar({
  statusFilter,
  ruleIdFilter,
  hostIdFilter,
  onStatusChange,
  onRuleIdChange,
  onHostIdChange,
}: FilterBarProps) {
  return (
    <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
      <FormControl size="small" sx={{ minWidth: 150 }}>
        <InputLabel id="status-filter-label">Status</InputLabel>
        <Select
          labelId="status-filter-label"
          value={statusFilter}
          label="Status"
          onChange={(e: SelectChangeEvent) => onStatusChange(e.target.value)}
          data-testid="status-filter"
        >
          {STATUS_OPTIONS.map((s) => (
            <MenuItem key={s} value={s}>
              {s === 'all' ? 'All Statuses' : s.charAt(0).toUpperCase() + s.slice(1)}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <TextField
        size="small"
        label="Rule ID"
        value={ruleIdFilter}
        onChange={(e) => onRuleIdChange(e.target.value)}
        placeholder="Filter by rule ID"
        data-testid="rule-id-filter"
        sx={{ minWidth: 200 }}
      />

      <TextField
        size="small"
        label="Host ID"
        value={hostIdFilter}
        onChange={(e) => onHostIdChange(e.target.value)}
        placeholder="Filter by host ID"
        data-testid="host-id-filter"
        sx={{ minWidth: 250 }}
      />
    </Box>
  );
}

interface ExceptionDetailDialogProps {
  exception: ComplianceException | null;
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  onRevoke: (id: string) => void;
  onEscalate: (id: string) => void;
  onReRemediate: (id: string) => void;
}

/** AC-3: Detail dialog showing approval metadata */
function ExceptionDetailDialog({
  exception,
  open,
  onClose,
  isAdmin,
  onApprove,
  onReject,
  onRevoke,
  onEscalate,
  onReRemediate,
}: ExceptionDetailDialogProps) {
  if (!exception) return null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Exception Detail</span>
        <IconButton onClick={onClose} size="small">
          <Close />
        </IconButton>
      </DialogTitle>
      <DialogContent dividers>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              Rule ID
            </Typography>
            <Typography>{exception.rule_id}</Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              Status
            </Typography>
            <Chip
              label={exception.status}
              color={STATUS_COLORS[exception.status] || 'default'}
              size="small"
            />
          </Box>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              Host ID
            </Typography>
            <Typography>{exception.host_id || 'Fleet-wide'}</Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              Expires At
            </Typography>
            <Typography>{new Date(exception.expires_at).toLocaleDateString()}</Typography>
          </Box>
          {exception.days_until_expiry != null && (
            <Box>
              <Typography variant="subtitle2" color="text.secondary">
                Days Until Expiry
              </Typography>
              <Typography>{exception.days_until_expiry}</Typography>
            </Box>
          )}
          <Box>
            <Typography variant="subtitle2" color="text.secondary">
              Requested By
            </Typography>
            <Typography>User #{exception.requested_by}</Typography>
          </Box>
        </Box>

        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle2" color="text.secondary">
            Justification
          </Typography>
          <Typography sx={{ whiteSpace: 'pre-wrap' }}>{exception.justification}</Typography>
        </Box>

        {exception.risk_acceptance && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" color="text.secondary">
              Risk Acceptance
            </Typography>
            <Typography sx={{ whiteSpace: 'pre-wrap' }}>{exception.risk_acceptance}</Typography>
          </Box>
        )}

        {exception.compensating_controls && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" color="text.secondary">
              Compensating Controls
            </Typography>
            <Typography sx={{ whiteSpace: 'pre-wrap' }}>
              {exception.compensating_controls}
            </Typography>
          </Box>
        )}

        {exception.business_impact && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" color="text.secondary">
              Business Impact
            </Typography>
            <Typography sx={{ whiteSpace: 'pre-wrap' }}>{exception.business_impact}</Typography>
          </Box>
        )}

        {/* AC-3: Approval metadata */}
        {exception.approved_by != null && (
          <Box sx={{ mt: 3, p: 2, bgcolor: 'success.main', borderRadius: 1, color: 'success.contrastText' }}>
            <Typography variant="subtitle2">Approval Details</Typography>
            <Typography>Approver: User #{exception.approved_by}</Typography>
            {exception.approved_at && (
              <Typography>
                Approved At: {new Date(exception.approved_at).toLocaleString()}
              </Typography>
            )}
          </Box>
        )}

        {exception.rejected_by != null && (
          <Box sx={{ mt: 3, p: 2, bgcolor: 'error.main', borderRadius: 1, color: 'error.contrastText' }}>
            <Typography variant="subtitle2">Rejection Details</Typography>
            <Typography>Rejected By: User #{exception.rejected_by}</Typography>
            {exception.rejected_at && (
              <Typography>
                Rejected At: {new Date(exception.rejected_at).toLocaleString()}
              </Typography>
            )}
            {exception.rejection_reason && (
              <Typography>Reason: {exception.rejection_reason}</Typography>
            )}
          </Box>
        )}

        {exception.revoked_by != null && (
          <Box sx={{ mt: 3, p: 2, bgcolor: 'info.main', borderRadius: 1, color: 'info.contrastText' }}>
            <Typography variant="subtitle2">Revocation Details</Typography>
            <Typography>Revoked By: User #{exception.revoked_by}</Typography>
            {exception.revoked_at && (
              <Typography>
                Revoked At: {new Date(exception.revoked_at).toLocaleString()}
              </Typography>
            )}
            {exception.revocation_reason && (
              <Typography>Reason: {exception.revocation_reason}</Typography>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        {/* AC-4: Escalate button for pending exceptions */}
        {exception.status === 'pending' && (
          <Button
            startIcon={<ArrowUpward />}
            onClick={() => onEscalate(exception.id)}
            data-testid="escalate-button"
          >
            Escalate
          </Button>
        )}

        {/* AC-5: Re-remediation button for excepted (approved) rules */}
        {exception.status === 'approved' && (
          <Button
            startIcon={<Build />}
            onClick={() => onReRemediate(exception.id)}
            data-testid="re-remediation-button"
          >
            Re-remediate
          </Button>
        )}

        {/* AC-7: Approve/Reject/Revoke gated by admin role */}
        {isAdmin && exception.status === 'pending' && (
          <>
            <Button
              variant="contained"
              color="success"
              startIcon={<CheckCircle />}
              onClick={() => onApprove(exception.id)}
              data-testid="approve-button"
            >
              Approve
            </Button>
            <Button
              variant="contained"
              color="error"
              startIcon={<Cancel />}
              onClick={() => onReject(exception.id)}
              data-testid="reject-button"
            >
              Reject
            </Button>
          </>
        )}

        {isAdmin && exception.status === 'approved' && (
          <Button
            variant="outlined"
            color="error"
            onClick={() => onRevoke(exception.id)}
            data-testid="revoke-button"
          >
            Revoke
          </Button>
        )}

        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

interface RequestFormDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: ExceptionCreateRequest) => void;
  isSubmitting: boolean;
}

/** AC-2: Exception request form with required fields */
function RequestFormDialog({ open, onClose, onSubmit, isSubmitting }: RequestFormDialogProps) {
  const [ruleId, setRuleId] = useState('');
  const [hostId, setHostId] = useState('');
  const [justification, setJustification] = useState('');
  const [riskAcceptance, setRiskAcceptance] = useState('');
  const [compensatingControls, setCompensatingControls] = useState('');
  const [businessImpact, setBusinessImpact] = useState('');
  const [durationDays, setDurationDays] = useState(30);

  const isValid = ruleId.trim() !== '' && justification.trim().length >= 20 && durationDays >= 1;

  const handleSubmit = () => {
    const data: ExceptionCreateRequest = {
      rule_id: ruleId.trim(),
      host_id: hostId.trim() || null,
      justification: justification.trim(),
      risk_acceptance: riskAcceptance.trim() || null,
      compensating_controls: compensatingControls.trim() || null,
      business_impact: businessImpact.trim() || null,
      duration_days: durationDays,
    };
    onSubmit(data);
  };

  const handleClose = () => {
    setRuleId('');
    setHostId('');
    setJustification('');
    setRiskAcceptance('');
    setCompensatingControls('');
    setBusinessImpact('');
    setDurationDays(30);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>Request Compliance Exception</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          <TextField
            label="Rule ID"
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            required
            fullWidth
            data-testid="rule-id-input"
          />

          <TextField
            label="Host ID (optional - leave empty for fleet-wide)"
            value={hostId}
            onChange={(e) => setHostId(e.target.value)}
            fullWidth
            data-testid="host-id-input"
          />

          <TextField
            label="Justification"
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            required
            multiline
            rows={3}
            fullWidth
            helperText="Minimum 20 characters. Explain why this exception is needed."
            data-testid="justification-input"
          />

          <TextField
            label="Risk Acceptance"
            value={riskAcceptance}
            onChange={(e) => setRiskAcceptance(e.target.value)}
            multiline
            rows={2}
            fullWidth
            helperText="Describe the accepted risk."
            data-testid="risk-acceptance-input"
          />

          <TextField
            label="Compensating Controls"
            value={compensatingControls}
            onChange={(e) => setCompensatingControls(e.target.value)}
            multiline
            rows={2}
            fullWidth
            data-testid="compensating-controls-input"
          />

          <TextField
            label="Business Impact"
            value={businessImpact}
            onChange={(e) => setBusinessImpact(e.target.value)}
            multiline
            rows={2}
            fullWidth
          />

          <TextField
            label="Duration (days)"
            type="number"
            value={durationDays}
            onChange={(e) => setDurationDays(Math.max(1, parseInt(e.target.value) || 1))}
            required
            fullWidth
            inputProps={{ min: 1, max: 365 }}
            helperText="Number of days until the exception expires (max 365)."
            data-testid="duration-days-input"
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={!isValid || isSubmitting}
          data-testid="submit-exception-button"
        >
          {isSubmitting ? 'Submitting...' : 'Submit Request'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Reject / Revoke reason dialog
// ---------------------------------------------------------------------------

interface ReasonDialogProps {
  open: boolean;
  title: string;
  label: string;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}

function ReasonDialog({ open, title, label, onClose, onConfirm }: ReasonDialogProps) {
  const [reason, setReason] = useState('');

  const handleConfirm = () => {
    onConfirm(reason);
    setReason('');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <TextField
          label={label}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          multiline
          rows={3}
          fullWidth
          required
          helperText="Minimum 10 characters."
          sx={{ mt: 1 }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          color="error"
          onClick={handleConfirm}
          disabled={reason.trim().length < 10}
        >
          Confirm
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

const Exceptions: React.FC = () => {
  const queryClient = useQueryClient();
  const user = useAuthStore((state) => state.user);
  const userRole = user?.role || 'guest';

  /** AC-7: Only SECURITY_ADMIN or higher see approve/reject */
  const isAdmin = ADMIN_ROLES.includes(userRole);

  // Filter state
  const [statusFilter, setStatusFilter] = useState('all');
  const [ruleIdFilter, setRuleIdFilter] = useState('');
  const [hostIdFilter, setHostIdFilter] = useState('');

  // Pagination state
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);

  // Dialog state
  const [requestDialogOpen, setRequestDialogOpen] = useState(false);
  const [selectedExceptionId, setSelectedExceptionId] = useState<string | null>(null);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [actionTargetId, setActionTargetId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Build query params
  const queryParams = {
    page: page + 1, // API is 1-indexed
    per_page: rowsPerPage,
    ...(statusFilter !== 'all' ? { status: statusFilter } : {}),
    ...(ruleIdFilter ? { rule_id: ruleIdFilter } : {}),
    ...(hostIdFilter ? { host_id: hostIdFilter } : {}),
  };

  // Fetch exceptions list
  const { data, isLoading, error } = useQuery({
    queryKey: ['exceptions', queryParams],
    queryFn: () => exceptionService.list(queryParams),
  });

  // Fetch selected exception detail
  const { data: selectedExceptionDetail } = useQuery({
    queryKey: ['exception', selectedExceptionId],
    queryFn: () => exceptionService.get(selectedExceptionId!),
    enabled: !!selectedExceptionId,
  });

  // Mutations
  const requestMutation = useMutation({
    mutationFn: (data: ExceptionCreateRequest) => exceptionService.request(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] });
      setRequestDialogOpen(false);
      setErrorMessage(null);
    },
    onError: (err: Error) => {
      setErrorMessage(err.message || 'Failed to create exception request');
    },
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => exceptionService.approve(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] });
      queryClient.invalidateQueries({ queryKey: ['exception', selectedExceptionId] });
      setErrorMessage(null);
    },
    onError: (err: Error) => {
      setErrorMessage(err.message || 'Failed to approve exception');
    },
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      exceptionService.reject(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] });
      queryClient.invalidateQueries({ queryKey: ['exception', selectedExceptionId] });
      setRejectDialogOpen(false);
      setErrorMessage(null);
    },
    onError: (err: Error) => {
      setErrorMessage(err.message || 'Failed to reject exception');
    },
  });

  const revokeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      exceptionService.revoke(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] });
      queryClient.invalidateQueries({ queryKey: ['exception', selectedExceptionId] });
      setRevokeDialogOpen(false);
      setErrorMessage(null);
    },
    onError: (err: Error) => {
      setErrorMessage(err.message || 'Failed to revoke exception');
    },
  });

  // Handlers
  const handleRowClick = useCallback((id: string) => {
    setSelectedExceptionId(id);
  }, []);

  const handleApprove = useCallback((id: string) => {
    approveMutation.mutate(id);
  }, [approveMutation]);

  const handleRejectOpen = useCallback((id: string) => {
    setActionTargetId(id);
    setRejectDialogOpen(true);
  }, []);

  const handleRejectConfirm = useCallback(
    (reason: string) => {
      if (actionTargetId) {
        rejectMutation.mutate({ id: actionTargetId, reason });
      }
    },
    [actionTargetId, rejectMutation]
  );

  const handleRevokeOpen = useCallback((id: string) => {
    setActionTargetId(id);
    setRevokeDialogOpen(true);
  }, []);

  const handleRevokeConfirm = useCallback(
    (reason: string) => {
      if (actionTargetId) {
        revokeMutation.mutate({ id: actionTargetId, reason });
      }
    },
    [actionTargetId, revokeMutation]
  );

  /** AC-4: Escalate routes exception to higher-role approver */
  const handleEscalate = useCallback(
    async (id: string) => {
      try {
        // Escalation notifies higher-role approvers via the backend
        await api.post(`/api/compliance/exceptions/${id}/escalate`);
        queryClient.invalidateQueries({ queryKey: ['exceptions'] });
        queryClient.invalidateQueries({ queryKey: ['exception', id] });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Escalation failed';
        setErrorMessage(message);
      }
    },
    [queryClient]
  );

  /** AC-5: Re-remediation triggers remediation for the excepted rule */
  const handleReRemediate = useCallback(
    async (id: string) => {
      const exception = data?.items.find((e) => e.id === id) || selectedExceptionDetail;
      if (!exception) return;

      try {
        await api.post('/api/remediation/trigger', {
          rule_id: exception.rule_id,
          host_id: exception.host_id,
        });
        setErrorMessage(null);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Re-remediation failed';
        setErrorMessage(message);
      }
    },
    [data, selectedExceptionDetail]
  );

  const handlePageChange = useCallback((_: unknown, newPage: number) => {
    setPage(newPage);
  }, []);

  const handleRowsPerPageChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      setRowsPerPage(parseInt(event.target.value, 10));
      setPage(0);
    },
    []
  );

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">Compliance Exceptions</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setRequestDialogOpen(true)}
          data-testid="request-exception-button"
        >
          Request Exception
        </Button>
      </Box>

      {errorMessage && (
        <Alert severity="error" onClose={() => setErrorMessage(null)} sx={{ mb: 2 }}>
          {errorMessage}
        </Alert>
      )}

      {/* AC-6: Filter bar */}
      <FilterBar
        statusFilter={statusFilter}
        ruleIdFilter={ruleIdFilter}
        hostIdFilter={hostIdFilter}
        onStatusChange={(v) => {
          setStatusFilter(v);
          setPage(0);
        }}
        onRuleIdChange={(v) => {
          setRuleIdFilter(v);
          setPage(0);
        }}
        onHostIdChange={(v) => {
          setHostIdFilter(v);
          setPage(0);
        }}
      />

      {/* AC-1: Paginated exception table */}
      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      ) : error ? (
        <Alert severity="error">Failed to load exceptions: {(error as Error).message}</Alert>
      ) : (
        <Paper>
          <TableContainer>
            <Table data-testid="exceptions-table">
              <TableHead>
                <TableRow>
                  <TableCell>Rule ID</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Justification</TableCell>
                  <TableCell>Requested By</TableCell>
                  <TableCell>Expires At</TableCell>
                  {isAdmin && <TableCell align="right">Actions</TableCell>}
                </TableRow>
              </TableHead>
              <TableBody>
                {data?.items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 6 : 5} align="center">
                      <Typography color="text.secondary" sx={{ py: 2 }}>
                        No exceptions found
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  data?.items.map((exception) => (
                    <TableRow
                      key={exception.id}
                      hover
                      onClick={() => handleRowClick(exception.id)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>{exception.rule_id}</TableCell>
                      <TableCell>
                        <Chip
                          label={exception.status}
                          color={STATUS_COLORS[exception.status] || 'default'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell sx={{ maxWidth: 300 }}>
                        <Typography noWrap title={exception.justification}>
                          {exception.justification}
                        </Typography>
                      </TableCell>
                      <TableCell>User #{exception.requested_by}</TableCell>
                      <TableCell>{new Date(exception.expires_at).toLocaleDateString()}</TableCell>
                      {/* AC-7: Approve/reject only for admin */}
                      {isAdmin && (
                        <TableCell align="right">
                          {exception.status === 'pending' && (
                            <>
                              <Tooltip title="Approve">
                                <IconButton
                                  size="small"
                                  color="success"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleApprove(exception.id);
                                  }}
                                  data-testid="approve-button"
                                >
                                  <CheckCircle />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Reject">
                                <IconButton
                                  size="small"
                                  color="error"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleRejectOpen(exception.id);
                                  }}
                                  data-testid="reject-button"
                                >
                                  <Cancel />
                                </IconButton>
                              </Tooltip>
                            </>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            component="div"
            count={data?.total || 0}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handlePageChange}
            onRowsPerPageChange={handleRowsPerPageChange}
            rowsPerPageOptions={[10, 20, 50]}
          />
        </Paper>
      )}

      {/* Request form dialog */}
      <RequestFormDialog
        open={requestDialogOpen}
        onClose={() => setRequestDialogOpen(false)}
        onSubmit={(data) => requestMutation.mutate(data)}
        isSubmitting={requestMutation.isPending}
      />

      {/* Detail dialog */}
      <ExceptionDetailDialog
        exception={selectedExceptionDetail || null}
        open={!!selectedExceptionId}
        onClose={() => setSelectedExceptionId(null)}
        isAdmin={isAdmin}
        onApprove={handleApprove}
        onReject={handleRejectOpen}
        onRevoke={handleRevokeOpen}
        onEscalate={handleEscalate}
        onReRemediate={handleReRemediate}
      />

      {/* Reject reason dialog */}
      <ReasonDialog
        open={rejectDialogOpen}
        title="Reject Exception"
        label="Rejection Reason"
        onClose={() => setRejectDialogOpen(false)}
        onConfirm={handleRejectConfirm}
      />

      {/* Revoke reason dialog */}
      <ReasonDialog
        open={revokeDialogOpen}
        title="Revoke Exception"
        label="Revocation Reason"
        onClose={() => setRevokeDialogOpen(false)}
        onConfirm={handleRevokeConfirm}
      />
    </Box>
  );
};

export default Exceptions;
