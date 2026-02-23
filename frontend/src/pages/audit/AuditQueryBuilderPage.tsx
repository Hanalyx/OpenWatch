/**
 * Audit Query Builder Page
 *
 * Multi-step wizard for creating and editing audit queries.
 * Steps: Scope -> Criteria -> Preview -> Save/Export
 *
 * Part of Phase 6: Audit Queries (Kensa Integration Plan)
 */

import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  Alert,
  Autocomplete,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Search as SearchIcon,
  Save as SaveIcon,
  Download as ExportIcon,
  NavigateNext as NextIcon,
  NavigateBefore as BackIcon,
} from '@mui/icons-material';
import {
  useSavedQuery,
  useCreateQuery,
  useUpdateQuery,
  useQueryPreview,
  useCreateExport,
} from '../../hooks/useAuditQueries';
import type {
  QueryDefinition,
  SavedQueryCreate,
  FindingResult,
  ExportFormat,
} from '../../types/audit';
import {
  SEVERITY_OPTIONS,
  STATUS_OPTIONS,
  VISIBILITY_OPTIONS,
  EXPORT_FORMAT_OPTIONS,
} from '../../types/audit';

const AuditQueryBuilderPage: React.FC = () => {
  const navigate = useNavigate();
  const { queryId } = useParams<{ queryId: string }>();
  const isEditMode = queryId && queryId !== 'new';

  const [activeStep, setActiveStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Query definition state
  const [queryDefinition, setQueryDefinition] = useState<QueryDefinition>({});

  // Save dialog state
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [queryName, setQueryName] = useState('');
  const [queryDescription, setQueryDescription] = useState('');
  const [queryVisibility, setQueryVisibility] = useState<'private' | 'shared'>('private');

  // Export dialog state
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState<ExportFormat>('csv');

  // Preview state
  const [previewResults, setPreviewResults] = useState<FindingResult[]>([]);
  const [previewTotal, setPreviewTotal] = useState(0);

  // Fetch existing query if editing
  const { data: existingQuery, isLoading: loadingQuery } = useSavedQuery(isEditMode ? queryId : '');

  // Mutations
  const createQuery = useCreateQuery();
  const updateQuery = useUpdateQuery();
  const previewQuery = useQueryPreview();
  const createExport = useCreateExport();

  // Track if we've loaded the existing query data
  const initializedRef = useRef(false);

  // Load existing query data only once when it first becomes available
  useEffect(() => {
    if (existingQuery && !initializedRef.current) {
      initializedRef.current = true;
      // Use setTimeout to defer state updates out of the effect
      setTimeout(() => {
        setQueryDefinition(existingQuery.query_definition);
        setQueryName(existingQuery.name);
        setQueryDescription(existingQuery.description || '');
        setQueryVisibility(existingQuery.visibility);
      }, 0);
    }
  }, [existingQuery]);

  const handleNext = async () => {
    setError(null);

    // Validate current step
    if (activeStep === 2) {
      // Run preview before showing results
      try {
        const result = await previewQuery.mutateAsync({
          query_definition: queryDefinition,
          limit: 20,
        });
        setPreviewResults(result.sample_results);
        setPreviewTotal(result.total_count);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Preview failed';
        setError(errorMessage);
        return;
      }
    }

    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setActiveStep((prev) => prev - 1);
  };

  const handleSave = async () => {
    if (!queryName.trim()) {
      setError('Query name is required');
      return;
    }

    try {
      const data: SavedQueryCreate = {
        name: queryName,
        description: queryDescription || undefined,
        query_definition: queryDefinition,
        visibility: queryVisibility,
      };

      if (isEditMode && queryId) {
        await updateQuery.mutateAsync({ queryId, data });
      } else {
        await createQuery.mutateAsync(data);
      }

      setSaveDialogOpen(false);
      navigate('/audit/queries');
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Save failed';
      setError(errorMessage);
    }
  };

  const handleExport = async () => {
    try {
      await createExport.mutateAsync({
        query_definition: queryDefinition,
        format: exportFormat,
      });

      setExportDialogOpen(false);
      navigate('/audit/exports');
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Export creation failed';
      setError(errorMessage);
    }
  };

  const updateDefinition = (updates: Partial<QueryDefinition>) => {
    setQueryDefinition((prev) => ({ ...prev, ...updates }));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pass':
        return 'success';
      case 'fail':
        return 'error';
      case 'error':
        return 'warning';
      default:
        return 'default';
    }
  };

  if (loadingQuery) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4">{isEditMode ? 'Edit Query' : 'Create Audit Query'}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Build a query to search and analyze compliance findings
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Stepper */}
      <Stepper activeStep={activeStep} orientation="vertical">
        {/* Step 1: Define Scope */}
        <Step>
          <StepLabel>Define Scope</StepLabel>
          <StepContent>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Select which hosts or host groups to include in your query
                </Typography>
                <Grid container spacing={3}>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Host IDs (comma-separated UUIDs)"
                      fullWidth
                      placeholder="e.g., 550e8400-e29b-41d4-a716-446655440000"
                      value={queryDefinition.hosts?.join(', ') || ''}
                      onChange={(e) => {
                        const hosts = e.target.value
                          .split(',')
                          .map((h) => h.trim())
                          .filter((h) => h);
                        updateDefinition({ hosts: hosts.length > 0 ? hosts : undefined });
                      }}
                      helperText="Leave empty to include all hosts"
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Host Group IDs (comma-separated)"
                      fullWidth
                      placeholder="e.g., 1, 2, 3"
                      value={queryDefinition.host_groups?.join(', ') || ''}
                      onChange={(e) => {
                        const groups = e.target.value
                          .split(',')
                          .map((g) => parseInt(g.trim(), 10))
                          .filter((g) => !isNaN(g));
                        updateDefinition({ host_groups: groups.length > 0 ? groups : undefined });
                      }}
                      helperText="Leave empty to include all host groups"
                    />
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button variant="contained" onClick={handleNext} endIcon={<NextIcon />}>
                Continue
              </Button>
            </Box>
          </StepContent>
        </Step>

        {/* Step 2: Set Criteria */}
        <Step>
          <StepLabel>Set Criteria</StepLabel>
          <StepContent>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Filter findings by rule, severity, or status
                </Typography>
                <Grid container spacing={3}>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Rule IDs (comma-separated)"
                      fullWidth
                      placeholder="e.g., sshd_strong_ciphers, audit_enabled"
                      value={queryDefinition.rules?.join(', ') || ''}
                      onChange={(e) => {
                        const rules = e.target.value
                          .split(',')
                          .map((r) => r.trim())
                          .filter((r) => r);
                        updateDefinition({ rules: rules.length > 0 ? rules : undefined });
                      }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Frameworks (comma-separated)"
                      fullWidth
                      placeholder="e.g., cis_rhel9, stig_rhel9"
                      value={queryDefinition.frameworks?.join(', ') || ''}
                      onChange={(e) => {
                        const frameworks = e.target.value
                          .split(',')
                          .map((f) => f.trim())
                          .filter((f) => f);
                        updateDefinition({
                          frameworks: frameworks.length > 0 ? frameworks : undefined,
                        });
                      }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <Autocomplete
                      multiple
                      options={SEVERITY_OPTIONS}
                      getOptionLabel={(option) => option.label}
                      value={SEVERITY_OPTIONS.filter((o) =>
                        queryDefinition.severities?.includes(o.value)
                      )}
                      onChange={(_, newValue) => {
                        updateDefinition({
                          severities:
                            newValue.length > 0 ? newValue.map((v) => v.value) : undefined,
                        });
                      }}
                      renderInput={(params) => <TextField {...params} label="Severities" />}
                      renderTags={(value, getTagProps) =>
                        value.map((option, index) => (
                          <Chip
                            {...getTagProps({ index })}
                            key={option.value}
                            label={option.label}
                            size="small"
                            color={
                              getSeverityColor(option.value) as
                                | 'error'
                                | 'warning'
                                | 'info'
                                | 'success'
                                | 'default'
                            }
                          />
                        ))
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <Autocomplete
                      multiple
                      options={STATUS_OPTIONS}
                      getOptionLabel={(option) => option.label}
                      value={STATUS_OPTIONS.filter((o) =>
                        queryDefinition.statuses?.includes(o.value)
                      )}
                      onChange={(_, newValue) => {
                        updateDefinition({
                          statuses: newValue.length > 0 ? newValue.map((v) => v.value) : undefined,
                        });
                      }}
                      renderInput={(params) => <TextField {...params} label="Statuses" />}
                      renderTags={(value, getTagProps) =>
                        value.map((option, index) => (
                          <Chip
                            {...getTagProps({ index })}
                            key={option.value}
                            label={option.label}
                            size="small"
                            color={
                              getStatusColor(option.value) as
                                | 'error'
                                | 'warning'
                                | 'success'
                                | 'default'
                            }
                          />
                        ))
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <Alert severity="info" sx={{ mt: 1 }}>
                      Date range filtering requires OpenWatch+ subscription
                    </Alert>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={handleBack} startIcon={<BackIcon />}>
                Back
              </Button>
              <Button
                variant="contained"
                onClick={handleNext}
                endIcon={<NextIcon />}
                disabled={previewQuery.isPending}
              >
                {previewQuery.isPending ? <CircularProgress size={20} /> : 'Preview'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        {/* Step 3: Preview Results */}
        <Step>
          <StepLabel>Preview Results</StepLabel>
          <StepContent>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                  <SearchIcon color="primary" />
                  <Typography variant="h6">
                    {previewTotal.toLocaleString()} findings match your query
                  </Typography>
                </Box>

                {previewResults.length > 0 ? (
                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Host</TableCell>
                          <TableCell>Rule</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Scanned</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {previewResults.map((finding, index) => (
                          <TableRow key={`${finding.scan_id}-${finding.rule_id}-${index}`}>
                            <TableCell>{finding.hostname}</TableCell>
                            <TableCell sx={{ maxWidth: 200 }}>
                              <Typography
                                variant="body2"
                                sx={{
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                              >
                                {finding.rule_id}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={finding.severity}
                                size="small"
                                color={
                                  getSeverityColor(finding.severity) as
                                    | 'error'
                                    | 'warning'
                                    | 'info'
                                    | 'success'
                                    | 'default'
                                }
                              />
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={finding.status}
                                size="small"
                                color={
                                  getStatusColor(finding.status) as
                                    | 'error'
                                    | 'warning'
                                    | 'success'
                                    | 'default'
                                }
                              />
                            </TableCell>
                            <TableCell>
                              {new Date(finding.scanned_at).toLocaleDateString()}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                ) : (
                  <Alert severity="warning">
                    No findings match your query criteria. Try broadening your filters.
                  </Alert>
                )}
              </CardContent>
            </Card>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={handleBack} startIcon={<BackIcon />}>
                Back
              </Button>
              <Button variant="contained" onClick={handleNext} endIcon={<NextIcon />}>
                Continue
              </Button>
            </Box>
          </StepContent>
        </Step>

        {/* Step 4: Save or Export */}
        <Step>
          <StepLabel>Save or Export</StepLabel>
          <StepContent>
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  What would you like to do with this query?
                </Typography>
                <Grid container spacing={2} sx={{ mt: 1 }}>
                  <Grid size={{ xs: 12, sm: 6 }}>
                    <Button
                      variant="outlined"
                      fullWidth
                      size="large"
                      startIcon={<SaveIcon />}
                      onClick={() => setSaveDialogOpen(true)}
                      sx={{ py: 2 }}
                    >
                      Save Query
                    </Button>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ mt: 1, display: 'block' }}
                    >
                      Save for later reuse and sharing
                    </Typography>
                  </Grid>
                  <Grid size={{ xs: 12, sm: 6 }}>
                    <Button
                      variant="outlined"
                      fullWidth
                      size="large"
                      startIcon={<ExportIcon />}
                      onClick={() => setExportDialogOpen(true)}
                      sx={{ py: 2 }}
                    >
                      Export Results
                    </Button>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ mt: 1, display: 'block' }}
                    >
                      Download as CSV, JSON, or PDF
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={handleBack} startIcon={<BackIcon />}>
                Back
              </Button>
            </Box>
          </StepContent>
        </Step>
      </Stepper>

      {/* Save Dialog */}
      <Dialog
        open={saveDialogOpen}
        onClose={() => setSaveDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{isEditMode ? 'Update Query' : 'Save Query'}</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Query Name"
              fullWidth
              required
              value={queryName}
              onChange={(e) => setQueryName(e.target.value)}
              placeholder="e.g., Failed Critical Rules"
            />
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={2}
              value={queryDescription}
              onChange={(e) => setQueryDescription(e.target.value)}
              placeholder="Optional description of what this query finds"
            />
            <FormControl fullWidth>
              <InputLabel>Visibility</InputLabel>
              <Select
                value={queryVisibility}
                label="Visibility"
                onChange={(e) => setQueryVisibility(e.target.value as 'private' | 'shared')}
              >
                {VISIBILITY_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSaveDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={createQuery.isPending || updateQuery.isPending}
          >
            {createQuery.isPending || updateQuery.isPending ? (
              <CircularProgress size={20} />
            ) : (
              'Save'
            )}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Export Dialog */}
      <Dialog
        open={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Export Results</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Export {previewTotal.toLocaleString()} findings in your preferred format
            </Typography>
            <FormControl fullWidth sx={{ mt: 2 }}>
              <InputLabel>Export Format</InputLabel>
              <Select
                value={exportFormat}
                label="Export Format"
                onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
              >
                {EXPORT_FORMAT_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleExport}
            disabled={createExport.isPending}
            startIcon={<ExportIcon />}
          >
            {createExport.isPending ? <CircularProgress size={20} /> : 'Export'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AuditQueryBuilderPage;
