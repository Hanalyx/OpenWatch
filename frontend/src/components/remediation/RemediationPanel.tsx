import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Typography,
  Button,
  Chip,
  Alert,
  CircularProgress,
  Paper,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Tooltip,
  Collapse,
  Checkbox,
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Undo as UndoIcon,
  Preview as PreviewIcon,
} from '@mui/icons-material';
import {
  useRemediationPlan,
  useCreateRemediationJob,
  useRemediationJob,
  useRemediationSteps,
  useRollback,
} from '../../hooks/useRemediation';
import { remediationAdapter } from '../../services/adapters/remediationAdapter';
import type {
  RemediationPlan,
  PlanRuleDetail,
  RemediationResult,
} from '../../services/adapters/remediationAdapter';

// =============================================================================
// Types
// =============================================================================

interface FailedRule {
  rule_id: string;
  rule_name: string;
  severity: string;
  can_remediate: boolean;
  description?: string;
}

interface ComplianceFindingInput {
  ruleId: string;
  title: string;
  severity: string;
  status: string;
}

interface RemediationPanelProps {
  hostId: string;
  failedRuleIds?: string[];
  failedFindings?: ComplianceFindingInput[];
  scanId?: string;
  scanStatus?: string;
  onRemediationStarted?: () => void;
}

// =============================================================================
// Sub-components
// =============================================================================

function RiskBadge({ level }: { level: string | null }) {
  if (!level || level === 'na') return null;
  const colorMap: Record<string, 'error' | 'warning' | 'success' | 'default'> = {
    high: 'error',
    medium: 'warning',
    low: 'success',
  };
  return (
    <Chip
      label={level.toUpperCase()}
      color={colorMap[level] || 'default'}
      size="small"
      variant="outlined"
    />
  );
}

function RiskSummary({ summary }: { summary: Record<string, number> }) {
  const entries = Object.entries(summary).filter(([, count]) => count > 0);
  if (entries.length === 0) return null;
  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
      {entries.map(([level, count]) => (
        <Chip
          key={level}
          label={`${count} ${level}`}
          color={level === 'high' ? 'error' : level === 'medium' ? 'warning' : 'success'}
          size="small"
        />
      ))}
    </Box>
  );
}

function EvidenceSection({ result }: { result: RemediationResult }) {
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);
  const [showJson, setShowJson] = useState(false);
  const hasEvidence = result.evidence && result.evidence.length > 0;
  const hasFrameworkRefs = result.frameworkRefs && Object.keys(result.frameworkRefs).length > 0;

  if (!hasEvidence && !hasFrameworkRefs) return null;

  const jsonData = {
    ...(hasEvidence ? { evidence: result.evidence } : {}),
    ...(hasFrameworkRefs ? { framework_refs: result.frameworkRefs } : {}),
  };

  return (
    <Box sx={{ mt: 1 }}>
      <Box
        sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer', mb: 0.5 }}
        onClick={() => setEvidenceExpanded(!evidenceExpanded)}
      >
        <IconButton size="small">
          {evidenceExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
        <Typography variant="body2" fontWeight="medium">
          Evidence
        </Typography>
      </Box>
      <Collapse in={evidenceExpanded}>
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 0.5 }}>
            <Button
              size="small"
              variant={showJson ? 'contained' : 'outlined'}
              onClick={() => setShowJson(!showJson)}
              sx={{ textTransform: 'none', fontSize: '0.7rem', minWidth: 0, px: 1, py: 0.25 }}
            >
              {showJson ? 'Formatted' : 'JSON'}
            </Button>
          </Box>

          {showJson ? (
            <Box
              component="pre"
              sx={{
                fontFamily: 'monospace',
                fontSize: '0.7rem',
                m: 0,
                p: 1,
                bgcolor: 'background.default',
                borderRadius: 0.5,
                overflow: 'auto',
                maxHeight: 400,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(jsonData, null, 2)}
            </Box>
          ) : (
            <>
              {result.remediationDetail && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {result.remediationDetail}
                </Typography>
              )}
              {hasFrameworkRefs && (
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                  {Object.entries(result.frameworkRefs!).map(([framework, refs]) => (
                    <Chip
                      key={framework}
                      label={`${framework}: ${refs}`}
                      size="small"
                      variant="outlined"
                    />
                  ))}
                </Box>
              )}
              {hasEvidence &&
                result.evidence!.map((entry, idx) => (
                  <Paper key={idx} variant="outlined" sx={{ p: 1, mb: 1, bgcolor: 'action.hover' }}>
                    {entry.command && (
                      <Box sx={{ mb: 0.5 }}>
                        <Typography variant="caption" color="text.secondary">
                          Command:
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.75rem',
                            whiteSpace: 'pre-wrap',
                          }}
                        >
                          {entry.command}
                        </Typography>
                      </Box>
                    )}
                    {entry.stdout && (
                      <Box sx={{ mb: 0.5 }}>
                        <Typography variant="caption" color="text.secondary">
                          stdout:
                        </Typography>
                        <Box
                          component="pre"
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.7rem',
                            m: 0,
                            p: 0.5,
                            bgcolor: 'background.default',
                            borderRadius: 0.5,
                            overflow: 'auto',
                            maxHeight: 150,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                          }}
                        >
                          {entry.stdout}
                        </Box>
                      </Box>
                    )}
                    {entry.stderr && (
                      <Box sx={{ mb: 0.5 }}>
                        <Typography variant="caption" color="error.main">
                          stderr:
                        </Typography>
                        <Box
                          component="pre"
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.7rem',
                            m: 0,
                            p: 0.5,
                            bgcolor: 'background.default',
                            borderRadius: 0.5,
                            overflow: 'auto',
                            maxHeight: 150,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                          }}
                        >
                          {entry.stderr}
                        </Box>
                      </Box>
                    )}
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 0.5 }}>
                      {entry.exit_code != null && (
                        <Chip
                          label={`exit: ${entry.exit_code}`}
                          size="small"
                          color={entry.exit_code === 0 ? 'success' : 'error'}
                          variant="outlined"
                        />
                      )}
                      {entry.method && (
                        <Chip label={entry.method} size="small" variant="outlined" />
                      )}
                      {entry.expected && entry.actual && (
                        <Typography variant="caption" color="text.secondary">
                          expected: {entry.expected} | actual: {entry.actual}
                        </Typography>
                      )}
                    </Box>
                  </Paper>
                ))}
            </>
          )}
        </Paper>
      </Collapse>
    </Box>
  );
}

function StepDetailRow({ jobId, result }: { jobId: string; result: RemediationResult }) {
  const [expanded, setExpanded] = useState(false);
  const { data: steps, isLoading } = useRemediationSteps(
    expanded ? jobId : null,
    expanded ? result.id : null
  );

  const hasExpandableContent =
    (result.stepCount ?? 0) > 0 ||
    (result.evidence && result.evidence.length > 0) ||
    (result.frameworkRefs && Object.keys(result.frameworkRefs).length > 0);

  return (
    <>
      <TableRow>
        <TableCell>
          <Box>
            <Typography variant="body2" fontWeight="medium">
              {result.ruleId}
            </Typography>
          </Box>
        </TableCell>
        <TableCell>
          <Chip
            label={result.status === 'manual' ? 'MANUAL' : result.status.toUpperCase()}
            color={
              result.status === 'completed'
                ? 'success'
                : result.status === 'manual'
                  ? 'warning'
                  : 'error'
            }
            size="small"
          />
        </TableCell>
        <TableCell>
          <RiskBadge level={result.riskLevel} />
        </TableCell>
        <TableCell>{result.durationMs != null ? `${result.durationMs}ms` : '-'}</TableCell>
        <TableCell>
          {hasExpandableContent && (
            <IconButton size="small" onClick={() => setExpanded(!expanded)}>
              {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          )}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={5} sx={{ py: 0 }}>
            <Collapse in={expanded}>
              <Box sx={{ p: 1 }}>
                {isLoading ? (
                  <CircularProgress size={20} />
                ) : steps && steps.length > 0 ? (
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Step</TableCell>
                        <TableCell>Mechanism</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Risk</TableCell>
                        <TableCell>Verified</TableCell>
                        <TableCell>Detail</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {steps.map((step) => (
                        <TableRow key={step.id}>
                          <TableCell>{step.stepIndex}</TableCell>
                          <TableCell>
                            <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                              {step.mechanism}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={
                                step.success
                                  ? 'OK'
                                  : step.mechanism === 'manual'
                                    ? 'MANUAL'
                                    : 'FAIL'
                              }
                              color={
                                step.success
                                  ? 'success'
                                  : step.mechanism === 'manual'
                                    ? 'warning'
                                    : 'error'
                              }
                              size="small"
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell>
                            <RiskBadge level={step.riskLevel} />
                          </TableCell>
                          <TableCell>
                            {step.verified === true && (
                              <Chip
                                label="Verified"
                                color="success"
                                size="small"
                                variant="outlined"
                              />
                            )}
                            {step.verified === false && (
                              <Chip
                                label="Unverified"
                                color="warning"
                                size="small"
                                variant="outlined"
                              />
                            )}
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption" color="text.secondary">
                              {step.detail || '-'}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No step data available.
                  </Typography>
                )}
                <EvidenceSection result={result} />
              </Box>
            </Collapse>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

// =============================================================================
// Dry-Run Preview
// =============================================================================

function DryRunPreview({
  plan,
  onConfirm,
  onBack,
  loading,
}: {
  plan: RemediationPlan;
  onConfirm: () => void;
  onBack: () => void;
  loading: boolean;
}) {
  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 2 }}>
        Remediation Plan Preview
      </Typography>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
          <Typography variant="body2">
            {plan.ruleCount} rules, ~{plan.estimatedDurationSeconds}s estimated
          </Typography>
          <RiskSummary summary={plan.riskSummary} />
        </Box>
        {plan.requiresReboot && (
          <Alert severity="warning" sx={{ mb: 1 }}>
            Some rules may require a system reboot.
          </Alert>
        )}
        {plan.warnings.length > 0 && (
          <Alert severity="info" sx={{ mb: 1 }}>
            {plan.warnings.join('; ')}
          </Alert>
        )}
      </Paper>

      <TableContainer component={Paper} variant="outlined" sx={{ mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Rule</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Risk</TableCell>
              <TableCell>Steps</TableCell>
              <TableCell>Est. Duration</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {plan.rules.map((rule: PlanRuleDetail) => (
              <TableRow key={rule.ruleId}>
                <TableCell>
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      {rule.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {rule.ruleId}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={rule.severity.toUpperCase()}
                    color={
                      rule.severity === 'high' || rule.severity === 'critical'
                        ? 'error'
                        : rule.severity === 'medium'
                          ? 'warning'
                          : 'info'
                    }
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <RiskBadge level={rule.riskLevel} />
                </TableCell>
                <TableCell>
                  {rule.steps.length} step{rule.steps.length !== 1 ? 's' : ''}
                  {rule.steps.length > 0 && (
                    <Box sx={{ mt: 0.5 }}>
                      {rule.steps.map((s, i) => (
                        <Typography
                          key={i}
                          variant="caption"
                          color="text.secondary"
                          display="block"
                          sx={{ fontFamily: 'monospace' }}
                        >
                          {s.mechanism}
                        </Typography>
                      ))}
                    </Box>
                  )}
                </TableCell>
                <TableCell>{rule.estimatedDurationSeconds}s</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button onClick={onBack}>Back to Selection</Button>
        <Button
          variant="contained"
          color="primary"
          onClick={onConfirm}
          disabled={loading}
          startIcon={loading ? <CircularProgress size={16} /> : <PlayArrowIcon />}
        >
          {loading ? 'Starting...' : 'Execute Remediation'}
        </Button>
      </Box>
    </Box>
  );
}

// =============================================================================
// Main Component
// =============================================================================

const RemediationPanel: React.FC<RemediationPanelProps> = ({
  hostId,
  failedRuleIds = [],
  failedFindings = [],
  scanId,
  scanStatus,
  onRemediationStarted,
}) => {
  const [failedRules, _setFailedRules] = useState<FailedRule[]>([]);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<'select' | 'preview' | 'running' | 'done'>('select');
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [rollbackConfirmOpen, setRollbackConfirmOpen] = useState(false);
  const [canRemediate, setCanRemediate] = useState<Record<string, boolean>>({});

  // React Query hooks
  const planMutation = useRemediationPlan();
  const createJobMutation = useCreateRemediationJob();
  const rollbackMutation = useRollback();
  const { data: jobDetail } = useRemediationJob(activeJobId);

  // Auto-transition to done when job completes
  useEffect(() => {
    if (jobDetail?.job.status === 'completed' || jobDetail?.job.status === 'failed') {
      setPhase('done');
    }
  }, [jobDetail?.job.status]);

  // Track whether initial selection has been set
  const initializedRef = useRef(false);

  // Load failed rules from props or scan findings (only on mount / explicit refresh)
  const loadFailedRules = useCallback(async () => {
    if (!scanId && failedFindings.length === 0 && failedRuleIds.length === 0) return;

    try {
      setLoading(true);

      // Collect all rule IDs to check
      const allRuleIds =
        failedFindings.length > 0 ? failedFindings.map((f) => f.ruleId) : failedRuleIds;

      // Check which rules support auto-remediation
      let availability: Record<string, boolean> = {};
      try {
        availability = await remediationAdapter.checkRules(allRuleIds);
      } catch {
        // If check fails, assume all are remediable (graceful degradation)
        allRuleIds.forEach((id) => (availability[id] = true));
      }
      setCanRemediate(availability);

      // Only pre-select rules that support auto-remediation
      const autoRuleIds = allRuleIds.filter((id) => availability[id] !== false);
      setSelectedRules(autoRuleIds);
    } catch (err) {
      console.error('Error loading failed rules:', err);
      setError('Failed to load failed rules');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  // Initialize selection once on mount
  useEffect(() => {
    if (initializedRef.current) return;
    if (scanStatus === 'completed' || failedFindings.length > 0 || failedRuleIds.length > 0) {
      initializedRef.current = true;
      loadFailedRules();
    }
  }, [scanStatus, failedFindings, failedRuleIds, loadFailedRules]);

  // Generate dry-run preview
  const handlePreview = async () => {
    if (selectedRules.length === 0) {
      setError('Please select at least one rule to remediate');
      return;
    }

    setError(null);
    try {
      const result = await planMutation.mutateAsync({
        host_id: hostId,
        rule_ids: selectedRules,
        dry_run: true,
      });
      setPlan(result);
      setPhase('preview');
    } catch (err) {
      setError('Failed to generate remediation plan');
      console.error('Plan error:', err);
    }
  };

  // Execute remediation
  const handleExecute = async () => {
    setError(null);
    try {
      const job = await createJobMutation.mutateAsync({
        host_id: hostId,
        rule_ids: selectedRules,
        scan_id: scanId,
        dry_run: false,
      });
      setActiveJobId(job.id);
      setPhase('running');
      if (onRemediationStarted) onRemediationStarted();
    } catch (err) {
      setError('Failed to start remediation');
      console.error('Execute error:', err);
    }
  };

  // Rollback
  const handleRollback = async () => {
    if (!activeJobId) return;
    setRollbackConfirmOpen(false);
    try {
      await rollbackMutation.mutateAsync({ job_id: activeJobId });
    } catch (err) {
      setError('Failed to initiate rollback');
      console.error('Rollback error:', err);
    }
  };

  const getSeverityColor = (severity: string): 'error' | 'warning' | 'info' | 'default' => {
    switch (severity.toLowerCase()) {
      case 'high':
      case 'critical':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  // If no scan completed and no rule IDs passed, show placeholder
  if (
    scanStatus &&
    scanStatus !== 'completed' &&
    failedFindings.length === 0 &&
    failedRuleIds.length === 0
  ) {
    return (
      <Card>
        <CardHeader title="Remediation" />
        <CardContent>
          <Alert severity="info">Remediation will be available after the scan completes.</Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box>
      <Card>
        <CardHeader
          title="Automated Remediation"
          action={
            phase === 'select' ? (
              <Button startIcon={<RefreshIcon />} onClick={loadFailedRules} disabled={loading}>
                Refresh
              </Button>
            ) : phase === 'done' ? (
              <Button
                onClick={() => {
                  setPhase('select');
                  setActiveJobId(null);
                  setPlan(null);
                }}
              >
                New Remediation
              </Button>
            ) : undefined
          }
        />
        <CardContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {/* Phase 1: Rule Selection */}
          {phase === 'select' && (
            <>
              {failedRules.length > 0 ? (
                <Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {failedRules.filter((r) => r.can_remediate).length} of {failedRules.length}{' '}
                    failed rules can be remediated automatically.
                  </Typography>

                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Rule</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {failedRules.map((rule) => (
                          <TableRow key={rule.rule_id}>
                            <TableCell>
                              <Box>
                                <Typography variant="body2" fontWeight="medium">
                                  {rule.rule_name}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {rule.rule_id}
                                </Typography>
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={rule.severity.toUpperCase()}
                                color={getSeverityColor(rule.severity)}
                                size="small"
                              />
                            </TableCell>
                            <TableCell>
                              {rule.can_remediate ? (
                                <Chip
                                  label="Can Remediate"
                                  color="success"
                                  size="small"
                                  variant="outlined"
                                />
                              ) : (
                                <Chip
                                  label="Manual Fix Required"
                                  color="warning"
                                  size="small"
                                  variant="outlined"
                                />
                              )}
                            </TableCell>
                            <TableCell>
                              {rule.can_remediate && (
                                <Tooltip title="Include in remediation">
                                  <IconButton
                                    size="small"
                                    onClick={() => {
                                      if (selectedRules.includes(rule.rule_id)) {
                                        setSelectedRules(
                                          selectedRules.filter((id) => id !== rule.rule_id)
                                        );
                                      } else {
                                        setSelectedRules([...selectedRules, rule.rule_id]);
                                      }
                                    }}
                                  >
                                    {selectedRules.includes(rule.rule_id) ? (
                                      <CheckCircleIcon color="primary" />
                                    ) : (
                                      <PlayArrowIcon />
                                    )}
                                  </IconButton>
                                </Tooltip>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {selectedRules.length > 0 && (
                    <Box
                      sx={{
                        mt: 2,
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <Typography variant="body2" color="text.secondary">
                        {selectedRules.length} rules selected
                      </Typography>
                      <Button
                        variant="contained"
                        startIcon={<PreviewIcon />}
                        onClick={handlePreview}
                        disabled={planMutation.isPending}
                      >
                        {planMutation.isPending ? 'Generating Preview...' : 'Preview Plan'}
                      </Button>
                    </Box>
                  )}
                </Box>
              ) : failedFindings.length > 0 ? (
                /* Findings passed from HostDetail — show selection table */
                <Box>
                  {(() => {
                    const autoCount = failedFindings.filter(
                      (f) => canRemediate[f.ruleId] !== false
                    ).length;
                    const manualCount = failedFindings.length - autoCount;
                    return (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {selectedRules.length} of {autoCount} auto-remediable rules selected.
                        {manualCount > 0 &&
                          ` ${manualCount} rule${manualCount > 1 ? 's' : ''} require manual remediation.`}
                      </Typography>
                    );
                  })()}

                  <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 400 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell padding="checkbox">
                            <Checkbox
                              indeterminate={
                                selectedRules.length > 0 &&
                                selectedRules.length <
                                  failedFindings.filter((f) => canRemediate[f.ruleId] !== false)
                                    .length
                              }
                              checked={
                                selectedRules.length ===
                                failedFindings.filter((f) => canRemediate[f.ruleId] !== false)
                                  .length
                              }
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedRules(
                                    failedFindings
                                      .filter((f) => canRemediate[f.ruleId] !== false)
                                      .map((f) => f.ruleId)
                                  );
                                } else {
                                  setSelectedRules([]);
                                }
                              }}
                            />
                          </TableCell>
                          <TableCell>Rule</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Type</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {failedFindings.map((finding) => {
                          const isAuto = canRemediate[finding.ruleId] !== false;
                          return (
                            <TableRow
                              key={finding.ruleId}
                              hover={isAuto}
                              onClick={() => {
                                if (!isAuto) return;
                                setSelectedRules((prev) =>
                                  prev.includes(finding.ruleId)
                                    ? prev.filter((id) => id !== finding.ruleId)
                                    : [...prev, finding.ruleId]
                                );
                              }}
                              sx={{
                                cursor: isAuto ? 'pointer' : 'default',
                                opacity: isAuto ? 1 : 0.6,
                              }}
                            >
                              <TableCell padding="checkbox">
                                <Checkbox
                                  checked={selectedRules.includes(finding.ruleId)}
                                  disabled={!isAuto}
                                />
                              </TableCell>
                              <TableCell>
                                <Box>
                                  <Typography variant="body2" fontWeight="medium">
                                    {finding.title || finding.ruleId}
                                  </Typography>
                                  {finding.title && (
                                    <Typography variant="caption" color="text.secondary">
                                      {finding.ruleId}
                                    </Typography>
                                  )}
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={finding.severity.toUpperCase()}
                                  color={getSeverityColor(finding.severity)}
                                  size="small"
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={isAuto ? 'Auto' : 'Manual'}
                                  color={isAuto ? 'success' : 'default'}
                                  size="small"
                                  variant="outlined"
                                />
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {selectedRules.length > 0 && (
                    <Box
                      sx={{
                        mt: 2,
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <Typography variant="body2" color="text.secondary">
                        {selectedRules.length} rules selected
                      </Typography>
                      <Button
                        variant="contained"
                        startIcon={<PreviewIcon />}
                        onClick={handlePreview}
                        disabled={planMutation.isPending}
                      >
                        {planMutation.isPending ? 'Generating Preview...' : 'Preview Plan'}
                      </Button>
                    </Box>
                  )}
                </Box>
              ) : selectedRules.length > 0 ? (
                /* Rule IDs only, no finding metadata */
                <Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {selectedRules.length} rules selected for remediation.
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<PreviewIcon />}
                    onClick={handlePreview}
                    disabled={planMutation.isPending}
                  >
                    {planMutation.isPending ? 'Generating Preview...' : 'Preview Plan'}
                  </Button>
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No failed rules to remediate.
                </Typography>
              )}
            </>
          )}

          {/* Phase 2: Dry-Run Preview */}
          {phase === 'preview' && plan && (
            <DryRunPreview
              plan={plan}
              onConfirm={handleExecute}
              onBack={() => setPhase('select')}
              loading={createJobMutation.isPending}
            />
          )}

          {/* Phase 3: Running */}
          {phase === 'running' && jobDetail && (
            <Box>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Remediation In Progress
              </Typography>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Chip label={jobDetail.job.status.toUpperCase()} color="primary" sx={{ mr: 2 }} />
                  <Typography variant="body2">Job ID: {jobDetail.job.id}</Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={jobDetail.job.progress}
                  sx={{ mb: 1 }}
                />
                <Typography variant="body2" color="text.secondary">
                  Progress: {jobDetail.job.progress}% ({jobDetail.job.completedRules} completed,{' '}
                  {jobDetail.job.failedRules} failed, {jobDetail.job.skippedRules} skipped)
                </Typography>
              </Paper>
            </Box>
          )}

          {/* Phase 4: Done */}
          {phase === 'done' && jobDetail && (
            <Box>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Remediation Results
              </Typography>

              <Paper sx={{ p: 2, mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2, gap: 2 }}>
                  <Chip
                    label={jobDetail.job.status.toUpperCase()}
                    color={jobDetail.job.status === 'completed' ? 'success' : 'error'}
                  />
                  {jobDetail.job.durationSeconds != null && (
                    <Typography variant="body2" color="text.secondary">
                      Duration: {jobDetail.job.durationSeconds.toFixed(1)}s
                    </Typography>
                  )}
                </Box>

                <Box sx={{ display: 'flex', gap: 3, mb: 2 }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Total
                    </Typography>
                    <Typography variant="h6">{jobDetail.job.totalRules}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Completed
                    </Typography>
                    <Typography variant="h6" color="success.main">
                      {jobDetail.job.completedRules}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Failed
                    </Typography>
                    <Typography variant="h6" color="error.main">
                      {jobDetail.job.failedRules}
                    </Typography>
                  </Box>
                </Box>

                {jobDetail.job.rollbackAvailable && (
                  <Button
                    variant="outlined"
                    color="warning"
                    startIcon={<UndoIcon />}
                    onClick={() => setRollbackConfirmOpen(true)}
                    disabled={rollbackMutation.isPending}
                    sx={{ mt: 1 }}
                  >
                    Rollback Changes
                  </Button>
                )}
              </Paper>

              {/* Per-rule results with expandable steps */}
              {jobDetail.results.length > 0 && (
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Rule</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Risk</TableCell>
                        <TableCell>Duration</TableCell>
                        <TableCell>Steps</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {jobDetail.results.map((result) => (
                        <StepDetailRow key={result.id} jobId={jobDetail.job.id} result={result} />
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Box>
          )}

          {loading && !planMutation.isPending && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
              <CircularProgress />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Rollback Confirmation Dialog */}
      <Dialog open={rollbackConfirmOpen} onClose={() => setRollbackConfirmOpen(false)}>
        <DialogTitle>Confirm Rollback</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to rollback all changes made by this remediation job?
          </Typography>
          <Alert severity="warning" sx={{ mt: 2 }}>
            This will restore the host to its pre-remediation state for all rules that captured
            rollback data.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRollbackConfirmOpen(false)}>Cancel</Button>
          <Button
            onClick={handleRollback}
            variant="contained"
            color="warning"
            disabled={rollbackMutation.isPending}
            startIcon={rollbackMutation.isPending ? <CircularProgress size={16} /> : <UndoIcon />}
          >
            {rollbackMutation.isPending ? 'Rolling Back...' : 'Confirm Rollback'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default RemediationPanel;
