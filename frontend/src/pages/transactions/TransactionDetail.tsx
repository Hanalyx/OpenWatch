/**
 * Transaction Detail Page
 *
 * Shows full details for a single compliance transaction with 4 tabs:
 * Execution timeline, Evidence (JSON), Controls (framework refs), Related links.
 *
 * @module pages/transactions/TransactionDetail
 */

import React, { useState, useCallback } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  IconButton,
  Alert,
  CircularProgress,
  Divider,
  Link,
} from '@mui/material';
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';
import {
  transactionService,
  type TransactionDetail as TransactionDetailType,
} from '../../services/adapters/transactionAdapter';

// ---------------------------------------------------------------------------
// TabPanel helper
// ---------------------------------------------------------------------------

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index, ...other }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`txn-tabpanel-${index}`}
      aria-labelledby={`txn-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Status color helper
// ---------------------------------------------------------------------------

function getStatusColor(status: string): 'success' | 'error' | 'default' | 'warning' {
  switch (status) {
    case 'pass':
      return 'success';
    case 'fail':
      return 'error';
    case 'skipped':
      return 'default';
    case 'error':
      return 'warning';
    default:
      return 'default';
  }
}

function formatDate(dateString: string | null): string {
  if (!dateString) return '--';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatDuration(ms: number | null): string {
  if (ms === null) return '--';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

// ---------------------------------------------------------------------------
// Sub-components for each tab
// ---------------------------------------------------------------------------

/** Execution tab: phase timeline */
function ExecutionTab({ txn }: { txn: TransactionDetailType }) {
  const envelope = txn.evidence_envelope?.phases || {};
  const phases = [
    { name: 'capture', label: 'Capture', data: envelope.capture || txn.pre_state },
    { name: 'validate', label: 'Validate', data: envelope.validate || txn.validate_result },
    { name: 'commit', label: 'Commit', data: envelope.commit || txn.post_state },
  ];

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Execution Timeline
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {/* Summary row */}
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Started
              </Typography>
              <Typography variant="body2">{formatDate(txn.started_at)}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Completed
              </Typography>
              <Typography variant="body2">{formatDate(txn.completed_at)}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Duration
              </Typography>
              <Typography variant="body2">{formatDuration(txn.duration_ms)}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">
                Current Phase
              </Typography>
              <Typography variant="body2">{txn.phase}</Typography>
            </Box>
          </Box>
        </Paper>

        {/* Phase cards */}
        {phases.map((phase) => (
          <Paper key={phase.name} variant="outlined" sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Chip
                label={phase.label}
                size="small"
                color={txn.phase === phase.name ? 'primary' : 'default'}
                variant={txn.phase === phase.name ? 'filled' : 'outlined'}
              />
              {phase.data && (
                <Typography variant="caption" color="text.secondary">
                  Data captured
                </Typography>
              )}
            </Box>
            {phase.data ? (
              <Box
                component="pre"
                sx={{
                  fontSize: '0.75rem',
                  overflow: 'auto',
                  maxHeight: 200,
                  bgcolor: 'action.hover',
                  p: 1,
                  borderRadius: 1,
                  m: 0,
                }}
              >
                {JSON.stringify(phase.data, null, 2)}
              </Box>
            ) : (
              <Typography variant="body2" color="text.secondary">
                No data for this phase
              </Typography>
            )}
          </Paper>
        ))}
      </Box>
    </Box>
  );
}

/** Evidence tab: pretty-printed JSON of evidence_envelope */
function EvidenceTab({ txn }: { txn: TransactionDetailType }) {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Evidence Envelope
      </Typography>
      {txn.evidence_envelope ? (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Box
            component="pre"
            sx={{
              fontSize: '0.8rem',
              overflow: 'auto',
              maxHeight: 600,
              m: 0,
            }}
          >
            {JSON.stringify(txn.evidence_envelope, null, 2)}
          </Box>
        </Paper>
      ) : (
        <Typography variant="body1" color="text.secondary">
          No evidence data available for this transaction.
        </Typography>
      )}
    </Box>
  );
}

/** Controls tab: framework_refs as chips */
function ControlsTab({ txn }: { txn: TransactionDetailType }) {
  const refs = txn.framework_refs;

  if (!refs || Object.keys(refs).length === 0) {
    return (
      <Box>
        <Typography variant="h6" gutterBottom>
          Framework Controls
        </Typography>
        <Typography variant="body1" color="text.secondary">
          No framework references mapped to this transaction.
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Framework Controls
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {Object.entries(refs).map(([framework, controls]) => (
          <Paper key={framework} variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              {framework}
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {Array.isArray(controls) ? (
                controls.map((control: string, idx: number) => (
                  <Chip
                    key={idx}
                    label={`${framework}: ${control}`}
                    size="small"
                    variant="outlined"
                  />
                ))
              ) : (
                <Chip label={String(controls)} size="small" variant="outlined" />
              )}
            </Box>
          </Paper>
        ))}
      </Box>
    </Box>
  );
}

/** Related tab: links to host, scan, etc. */
function RelatedTab({ txn }: { txn: TransactionDetailType }) {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Related Resources
      </Typography>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Host
            </Typography>
            <Box>
              <Link component={RouterLink} to={`/hosts/${txn.host_id}`} underline="hover">
                {txn.host_id}
              </Link>
            </Box>
          </Box>

          {txn.scan_id && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Scan
              </Typography>
              <Box>
                <Link component={RouterLink} to={`/scans/${txn.scan_id}`} underline="hover">
                  {txn.scan_id}
                </Link>
              </Box>
            </Box>
          )}

          {txn.rule_id && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Rule
              </Typography>
              <Typography variant="body2">{txn.rule_id}</Typography>
            </Box>
          )}

          {txn.baseline_id && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Baseline
              </Typography>
              <Typography variant="body2">{txn.baseline_id}</Typography>
            </Box>
          )}

          {txn.remediation_job_id && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Remediation Job
              </Typography>
              <Typography variant="body2">{txn.remediation_job_id}</Typography>
            </Box>
          )}

          <Divider sx={{ my: 1 }} />

          <Box>
            <Typography variant="caption" color="text.secondary">
              Initiator
            </Typography>
            <Typography variant="body2">
              {txn.initiator_type}
              {txn.initiator_id ? ` (${txn.initiator_id})` : ''}
            </Typography>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

const TransactionDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  }, []);

  const {
    data: txn,
    isLoading,
    error,
  } = useQuery<TransactionDetailType>({
    queryKey: ['transaction', id],
    queryFn: () => transactionService.get(id!),
    enabled: !!id,
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (error || !txn) {
    return (
      <Box>
        <Alert severity="error">Transaction not found</Alert>
        <Box sx={{ mt: 2 }}>
          <IconButton onClick={() => navigate('/transactions')}>
            <ArrowBackIcon />
          </IconButton>
          <Typography component="span" sx={{ ml: 1 }}>
            Back to Transactions
          </Typography>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <IconButton onClick={() => navigate('/transactions')}>
            <ArrowBackIcon />
          </IconButton>
          <Typography variant="h4" component="h1">
            Transaction Detail
          </Typography>
          <Chip label={txn.status.toUpperCase()} color={getStatusColor(txn.status)} size="small" />
          {txn.severity && <Chip label={txn.severity} size="small" variant="outlined" />}
        </Box>
      </Box>

      {/* Summary info */}
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Rule
            </Typography>
            <Typography variant="body2">{txn.rule_id || '--'}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Phase
            </Typography>
            <Typography variant="body2">{txn.phase}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Duration
            </Typography>
            <Typography variant="body2">{formatDuration(txn.duration_ms)}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Initiator
            </Typography>
            <Typography variant="body2">{txn.initiator_type}</Typography>
          </Box>
        </Box>
      </Paper>

      {/* Tabs */}
      <Paper sx={{ width: '100%' }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Execution" />
          <Tab label="Evidence" />
          <Tab label="Controls" />
          <Tab label="Related" />
        </Tabs>

        <Box sx={{ p: 2 }}>
          <TabPanel value={tabValue} index={0}>
            <ExecutionTab txn={txn} />
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <EvidenceTab txn={txn} />
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <ControlsTab txn={txn} />
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <RelatedTab txn={txn} />
          </TabPanel>
        </Box>
      </Paper>
    </Box>
  );
};

export default TransactionDetail;
