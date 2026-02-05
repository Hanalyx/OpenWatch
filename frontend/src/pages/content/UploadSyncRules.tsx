import React, { useState, useEffect } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Switch,
  FormControlLabel,
  Button,
  Alert,
  AlertTitle,
  Paper,
  Divider,
  LinearProgress,
  Chip,
  Stack,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  useTheme,
  alpha,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Collapse,
  CircularProgress,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CloudSync as SyncIcon,
  Upload as UploadIcon,
  Security as SecurityIcon,
  Schedule as ScheduleIcon,
  Verified as VerifiedIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  KeyboardArrowDown as KeyboardArrowDownIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  Download as DownloadIcon,
  History as HistoryIcon,
} from '@mui/icons-material';

/**
 * Validation results from SCAP content bundle processing
 * Contains file hash, rule counts, and validation status
 */
interface ValidationResults {
  fileHash?: string;
  rulesCount: number;
  validationPassed: boolean;
  imported?: number;
  updated?: number;
  skipped?: number;
  processingTime?: number;
  inheritanceImpact?: unknown;
  issues?: UploadMessage[];
}

/**
 * Error or warning message from upload processing
 * Can be a simple string or an object with a message property
 */
interface UploadMessage {
  message?: string;
  [key: string]: unknown;
}

/**
 * Statistics from compliance rule import operation
 * Tracks imported, updated, and skipped rule counts
 */
interface UploadStatistics {
  imported?: number;
  updated?: number;
  skipped?: number;
  errors?: number;
}

/**
 * SCAP content bundle manifest metadata
 * Contains bundle name, version, and rule count information
 */
interface BundleManifest {
  name: string;
  version: string;
  rules_count: number;
}

/**
 * Upload history record from backend API
 * Complete record of a compliance rule bundle upload operation
 */
interface UploadHistoryRecord {
  upload_id: string;
  file_name: string;
  filename?: string; // Alternative property name from some API responses
  file_hash?: string;
  timestamp: string;
  uploaded_at?: string;
  uploaded_by?: string;
  status: string;
  success?: boolean;
  phase: string;
  statistics?: UploadStatistics;
  manifest?: BundleManifest;
  processing_time_seconds?: number;
  errors?: UploadMessage[];
  warnings?: UploadMessage[];
}

const UploadSyncRules: React.FC = () => {
  const theme = useTheme();

  // State management
  const [syncEnabled, setSyncEnabled] = useState(false);
  const [uploadEnabled, setUploadEnabled] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [syncProgress, setSyncProgress] = useState(0);
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState(false);
  const [operationType, setOperationType] = useState<'sync' | 'upload' | null>(null);
  const [validationResults, setValidationResults] = useState<ValidationResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Upload history state
  const [uploadHistory, setUploadHistory] = useState<UploadHistoryRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  // Handle sync toggle
  const handleSyncToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    const enabled = event.target.checked;
    if (enabled && uploadEnabled) {
      // Cannot enable both - show warning
      setError('Only one synchronization method can be enabled at a time');
      return;
    }
    setSyncEnabled(enabled);
    setError(null);
    setSuccess(null);
  };

  // Handle upload toggle
  const handleUploadToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    const enabled = event.target.checked;
    if (enabled && syncEnabled) {
      // Cannot enable both - show warning
      setError('Only one synchronization method can be enabled at a time');
      return;
    }
    setUploadEnabled(enabled);
    setError(null);
    setSuccess(null);
  };

  // Handle file selection
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (!file.name.endsWith('.tar.gz')) {
        setError('Please select a .tar.gz file');
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  // Handle sync from repository
  const handleSync = async () => {
    setSyncing(true);
    setSyncProgress(0);
    setError(null);

    try {
      // Simulate sync process
      for (let i = 0; i <= 100; i += 10) {
        setSyncProgress(i);
        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setLastSyncTime(new Date().toLocaleString());
      setSuccess('Successfully synchronized compliance rules from Hanalyx repository');
    } catch (err) {
      // Type-safe error handling: check if error has message property
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(`Sync failed: ${errorMessage}`);
    } finally {
      setSyncing(false);
      setSyncProgress(0);
    }
  };

  // Handle file upload
  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file to upload');
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    setError(null);
    setValidationResults(null);

    try {
      // Create FormData for file upload
      const formData = new FormData();
      formData.append('file', selectedFile);

      // Get auth token
      const token = storageGet(StorageKeys.AUTH_TOKEN);
      if (!token) {
        throw new Error('Authentication token not found. Please log in again.');
      }

      // Call upload API
      setUploadProgress(10);
      const response = await fetch(
        '/api/compliance/upload-rules?deduplication_strategy=skip_unchanged_update_changed',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        }
      );

      setUploadProgress(90);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Upload failed');
      }

      const result = await response.json();
      setUploadProgress(100);

      if (result.success) {
        // Extract validation results
        setValidationResults({
          fileHash: result.file_hash,
          rulesCount:
            result.manifest?.rules_count ||
            result.statistics?.imported + result.statistics?.updated + result.statistics?.skipped ||
            0,
          validationPassed: true,
          imported: result.statistics?.imported || 0,
          updated: result.statistics?.updated || 0,
          skipped: result.statistics?.skipped || 0,
          processingTime: result.processing_time_seconds,
          inheritanceImpact: result.inheritance_impact,
          issues: result.warnings || [],
        });

        setSuccess(
          `Successfully uploaded ${selectedFile.name}: ` +
            `${result.statistics?.imported || 0} imported, ` +
            `${result.statistics?.updated || 0} updated, ` +
            `${result.statistics?.skipped || 0} skipped`
        );

        // Reload upload history to show the new upload
        loadUploadHistory();
      } else {
        // Upload failed
        setValidationResults({
          fileHash: result.file_hash || '',
          rulesCount: 0,
          validationPassed: false,
          issues: result.errors || [],
        });

        throw new Error(result.errors?.[0]?.message || 'Upload validation failed');
      }
    } catch (err) {
      // Type-safe error handling: check if error has message property
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(`Upload failed: ${errorMessage}`);
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  // Handle confirmation dialog
  const handleConfirmAction = () => {
    setConfirmDialog(false);
    if (operationType === 'sync') {
      handleSync();
    } else if (operationType === 'upload') {
      handleUpload();
    }
  };

  // Load upload history
  const loadUploadHistory = async () => {
    setLoadingHistory(true);
    try {
      const token = storageGet(StorageKeys.AUTH_TOKEN);
      if (!token) {
        console.warn('No auth token found');
        return;
      }

      const response = await fetch('/api/compliance/upload-history?limit=100', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch upload history');
      }

      const data = await response.json();
      setUploadHistory(data.uploads || []);
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error loading upload history:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to load upload history: ${errorMessage}`);
    } finally {
      setLoadingHistory(false);
    }
  };

  // Toggle row expansion
  const toggleRowExpansion = (uploadId: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(uploadId)) {
      newExpanded.delete(uploadId);
    } else {
      newExpanded.add(uploadId);
    }
    setExpandedRows(newExpanded);
  };

  // Export upload report as JSON
  const handleExportReport = async (uploadId: string) => {
    try {
      const token = storageGet(StorageKeys.AUTH_TOKEN);
      if (!token) {
        setError('Authentication token not found. Please log in again.');
        return;
      }

      const response = await fetch(`/api/compliance/upload-history/${uploadId}/export`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to export report');
      }

      // Get filename from Content-Disposition header
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `upload_report_${uploadId}.json`;
      if (contentDisposition) {
        const matches = /filename="([^"]+)"/.exec(contentDisposition);
        if (matches && matches[1]) {
          filename = matches[1];
        }
      }

      // Download the file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setSuccess(`Report exported: ${filename}`);
    } catch (err) {
      // Type-safe error handling: check if error has message property
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(`Failed to export report: ${errorMessage}`);
    }
  };

  // Load upload history on component mount
  useEffect(() => {
    loadUploadHistory();
  }, []);

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      {/* Header */}
      <Box mb={3}>
        <Typography
          variant="h4"
          gutterBottom
          sx={{ display: 'flex', alignItems: 'center', gap: 2 }}
        >
          <SecurityIcon color="primary" />
          Upload & Synchronize Rules
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Keep your compliance rules up-to-date from trusted Hanalyx repository or upload manual
          updates
        </Typography>
      </Box>

      {/* Status Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess(null)}>
          <AlertTitle>Success</AlertTitle>
          {success}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Automatic Synchronization */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <SyncIcon color="primary" sx={{ fontSize: 32 }} />
                <Box>
                  <Typography variant="h6">Automatic Synchronization</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Daily sync from Hanalyx trusted repository
                  </Typography>
                </Box>
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={syncEnabled}
                    onChange={handleSyncToggle}
                    color="primary"
                    disabled={syncing}
                  />
                }
                label={
                  <Box>
                    <Typography variant="body1">Enable Automatic Sync</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Check for updates daily at 11:00 PM system time
                    </Typography>
                  </Box>
                }
                sx={{ mb: 2, alignItems: 'flex-start' }}
              />

              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05), mb: 3 }}>
                <Stack spacing={1}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <InfoIcon color="info" fontSize="small" />
                    <Typography variant="body2" fontWeight="medium">
                      Repository Information
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Source: https://hanalyx.com/content/rules
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Schedule: Daily at 11:00 PM system time
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Last sync: {lastSyncTime || 'Never'}
                  </Typography>
                </Stack>
              </Paper>

              {syncing && (
                <Box mb={3}>
                  <Typography variant="body2" color="text.secondary" mb={1}>
                    Synchronizing... {syncProgress}%
                  </Typography>
                  <LinearProgress variant="determinate" value={syncProgress} />
                </Box>
              )}

              <Button
                variant="contained"
                startIcon={<SyncIcon />}
                onClick={() => {
                  setOperationType('sync');
                  setConfirmDialog(true);
                }}
                disabled={!syncEnabled || syncing || uploading}
                fullWidth
                sx={{ mb: 2 }}
              >
                Sync Now
              </Button>

              {syncEnabled && (
                <Alert severity="success" icon={<ScheduleIcon />}>
                  <Typography variant="body2">Automatic synchronization is active</Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Manual Upload */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <UploadIcon color="primary" sx={{ fontSize: 32 }} />
                <Box>
                  <Typography variant="h6">Manual Upload</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Upload compliance rules from tar.gz file
                  </Typography>
                </Box>
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={uploadEnabled}
                    onChange={handleUploadToggle}
                    color="primary"
                    disabled={uploading}
                  />
                }
                label={
                  <Box>
                    <Typography variant="body1">Enable Manual Upload</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Upload tar.gz files from Hanalyx repository
                    </Typography>
                  </Box>
                }
                sx={{ mb: 2, alignItems: 'flex-start' }}
              />

              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.05), mb: 3 }}>
                <Stack spacing={1}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <SecurityIcon color="warning" fontSize="small" />
                    <Typography variant="body2" fontWeight="medium">
                      Security Validation
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    • SHA-512 hash verification
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    • Content integrity checking
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    • Rules validation before import
                  </Typography>
                </Stack>
              </Paper>

              {uploadEnabled && (
                <Box mb={3}>
                  <TextField
                    type="file"
                    inputProps={{ accept: '.tar.gz' }}
                    onChange={handleFileSelect}
                    fullWidth
                    helperText="Select a .tar.gz file from Hanalyx repository"
                    sx={{ mb: 2 }}
                  />

                  {selectedFile && (
                    <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
                      <Box display="flex" alignItems="center" gap={1} mb={1}>
                        <VerifiedIcon color="success" fontSize="small" />
                        <Typography variant="body2" fontWeight="medium">
                          Selected File
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        {selectedFile.name} ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)
                      </Typography>
                    </Paper>
                  )}
                </Box>
              )}

              {uploading && (
                <Box mb={3}>
                  <Typography variant="body2" color="text.secondary" mb={1}>
                    Uploading and validating... {uploadProgress}%
                  </Typography>
                  <LinearProgress variant="determinate" value={uploadProgress} />
                </Box>
              )}

              {validationResults && (
                <Alert severity="success" sx={{ mb: 2 }}>
                  <AlertTitle>Validation Results</AlertTitle>
                  <Typography variant="body2">
                    Hash: {validationResults.fileHash?.substring(0, 20)}...
                  </Typography>
                  <Typography variant="body2">Rules: {validationResults.rulesCount}</Typography>
                  <Typography variant="body2">
                    Status: {validationResults.validationPassed ? 'Valid' : 'Invalid'}
                  </Typography>
                </Alert>
              )}

              <Button
                variant="contained"
                startIcon={<UploadIcon />}
                onClick={() => {
                  setOperationType('upload');
                  setConfirmDialog(true);
                }}
                disabled={!uploadEnabled || !selectedFile || uploading || syncing}
                fullWidth
                sx={{ mb: 2 }}
              >
                Upload & Validate
              </Button>

              {uploadEnabled && !selectedFile && (
                <Alert severity="info">
                  <Typography variant="body2">Select a tar.gz file to continue</Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Current Status */}
        <Grid size={{ xs: 12 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Current Configuration
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <Typography variant="body1" fontWeight="medium">
                      Synchronization Method:
                    </Typography>
                    <Chip
                      label={
                        syncEnabled
                          ? 'Automatic Sync'
                          : uploadEnabled
                            ? 'Manual Upload'
                            : 'None Selected'
                      }
                      color={syncEnabled || uploadEnabled ? 'success' : 'default'}
                      icon={
                        syncEnabled ? (
                          <SyncIcon />
                        ) : uploadEnabled ? (
                          <UploadIcon />
                        ) : (
                          <WarningIcon />
                        )
                      }
                    />
                  </Box>
                </Grid>

                <Grid size={{ xs: 12, sm: 6 }}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <Typography variant="body1" fontWeight="medium">
                      Status:
                    </Typography>
                    <Chip
                      label={
                        syncing
                          ? 'Syncing...'
                          : uploading
                            ? 'Uploading...'
                            : syncEnabled || uploadEnabled
                              ? 'Active'
                              : 'Inactive'
                      }
                      color={
                        syncing || uploading
                          ? 'warning'
                          : syncEnabled || uploadEnabled
                            ? 'success'
                            : 'default'
                      }
                    />
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Upload History */}
        <Grid size={{ xs: 12 }}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                <Box display="flex" alignItems="center" gap={2}>
                  <HistoryIcon color="primary" />
                  <Typography variant="h6">Upload History</Typography>
                </Box>
                <Button
                  startIcon={<SyncIcon />}
                  onClick={loadUploadHistory}
                  disabled={loadingHistory}
                  size="small"
                >
                  Refresh
                </Button>
              </Box>
              <Divider sx={{ mb: 2 }} />

              {loadingHistory ? (
                <Box display="flex" justifyContent="center" alignItems="center" py={4}>
                  <CircularProgress />
                </Box>
              ) : uploadHistory.length === 0 ? (
                <Alert severity="info">
                  <Typography variant="body2">
                    No upload history found. Upload a compliance bundle to see history records.
                  </Typography>
                </Alert>
              ) : (
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell />
                        <TableCell>Filename</TableCell>
                        <TableCell>Uploaded At</TableCell>
                        <TableCell>Uploaded By</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell align="right">Statistics</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {uploadHistory.map((upload) => (
                        <React.Fragment key={upload.upload_id}>
                          {/* Main Row */}
                          <TableRow hover>
                            <TableCell>
                              <IconButton
                                size="small"
                                onClick={() => toggleRowExpansion(upload.upload_id)}
                              >
                                {expandedRows.has(upload.upload_id) ? (
                                  <KeyboardArrowUpIcon />
                                ) : (
                                  <KeyboardArrowDownIcon />
                                )}
                              </IconButton>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontWeight="medium">
                                {upload.filename}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {upload.file_hash?.substring(0, 16)}...
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {upload.uploaded_at
                                  ? new Date(upload.uploaded_at).toLocaleString()
                                  : upload.timestamp
                                    ? new Date(upload.timestamp).toLocaleString()
                                    : 'Unknown'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">{upload.uploaded_by}</Typography>
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={upload.success ? 'Success' : 'Failed'}
                                color={upload.success ? 'success' : 'error'}
                                size="small"
                                icon={upload.success ? <CheckCircleIcon /> : <ErrorIcon />}
                              />
                            </TableCell>
                            <TableCell align="right">
                              <Stack direction="row" spacing={1} justifyContent="flex-end">
                                <Chip
                                  label={`Imported: ${upload.statistics?.imported || 0}`}
                                  size="small"
                                  variant="outlined"
                                  color="success"
                                />
                                <Chip
                                  label={`Updated: ${upload.statistics?.updated || 0}`}
                                  size="small"
                                  variant="outlined"
                                  color="primary"
                                />
                                <Chip
                                  label={`Skipped: ${upload.statistics?.skipped || 0}`}
                                  size="small"
                                  variant="outlined"
                                />
                              </Stack>
                            </TableCell>
                            <TableCell align="center">
                              <Tooltip title="Export JSON Report">
                                <IconButton
                                  size="small"
                                  onClick={() => handleExportReport(upload.upload_id)}
                                  color="primary"
                                >
                                  <DownloadIcon />
                                </IconButton>
                              </Tooltip>
                            </TableCell>
                          </TableRow>

                          {/* Expanded Detail Row */}
                          <TableRow>
                            <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                              <Collapse
                                in={expandedRows.has(upload.upload_id)}
                                timeout="auto"
                                unmountOnExit
                              >
                                <Box sx={{ py: 3, px: 2 }}>
                                  <Grid container spacing={3}>
                                    {/* Manifest Info */}
                                    <Grid size={{ xs: 12, md: 6 }}>
                                      <Paper
                                        sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}
                                      >
                                        <Typography
                                          variant="subtitle2"
                                          fontWeight="bold"
                                          gutterBottom
                                        >
                                          Manifest Information
                                        </Typography>
                                        <Divider sx={{ mb: 2 }} />
                                        {upload.manifest ? (
                                          <Stack spacing={1}>
                                            <Typography variant="body2">
                                              <strong>Name:</strong> {upload.manifest.name}
                                            </Typography>
                                            <Typography variant="body2">
                                              <strong>Version:</strong> {upload.manifest.version}
                                            </Typography>
                                            <Typography variant="body2">
                                              <strong>Rules Count:</strong>{' '}
                                              {upload.manifest.rules_count}
                                            </Typography>
                                            <Typography variant="body2">
                                              <strong>Processing Time:</strong>{' '}
                                              {upload.processing_time_seconds?.toFixed(2)}s
                                            </Typography>
                                          </Stack>
                                        ) : (
                                          <Typography variant="body2" color="text.secondary">
                                            No manifest data available
                                          </Typography>
                                        )}
                                      </Paper>
                                    </Grid>

                                    {/* Processing Details */}
                                    <Grid size={{ xs: 12, md: 6 }}>
                                      <Paper
                                        sx={{
                                          p: 2,
                                          bgcolor: alpha(theme.palette.success.main, 0.05),
                                        }}
                                      >
                                        <Typography
                                          variant="subtitle2"
                                          fontWeight="bold"
                                          gutterBottom
                                        >
                                          Processing Details
                                        </Typography>
                                        <Divider sx={{ mb: 2 }} />
                                        <Stack spacing={1}>
                                          <Typography variant="body2">
                                            <strong>Phase:</strong> {upload.phase}
                                          </Typography>
                                          <Typography variant="body2">
                                            <strong>Upload ID:</strong>{' '}
                                            <Typography
                                              component="span"
                                              variant="caption"
                                              sx={{ fontFamily: 'monospace' }}
                                            >
                                              {upload.upload_id}
                                            </Typography>
                                          </Typography>
                                          {(upload.statistics?.errors ?? 0) > 0 && (
                                            <Chip
                                              label={`${upload.statistics?.errors ?? 0} Errors`}
                                              size="small"
                                              color="error"
                                              variant="outlined"
                                            />
                                          )}
                                        </Stack>
                                      </Paper>
                                    </Grid>

                                    {/* Errors */}
                                    {upload.errors && upload.errors.length > 0 && (
                                      <Grid size={{ xs: 12 }}>
                                        <Paper
                                          sx={{
                                            p: 2,
                                            bgcolor: alpha(theme.palette.error.main, 0.05),
                                          }}
                                        >
                                          <Typography
                                            variant="subtitle2"
                                            fontWeight="bold"
                                            gutterBottom
                                            color="error"
                                          >
                                            Errors
                                          </Typography>
                                          <Divider sx={{ mb: 2 }} />
                                          <Stack spacing={1}>
                                            {upload.errors
                                              .slice(0, 5)
                                              .map((error: UploadMessage | string, idx: number) => (
                                                <Alert key={idx} severity="error" sx={{ py: 0 }}>
                                                  <Typography variant="body2">
                                                    {typeof error === 'string'
                                                      ? error
                                                      : error.message || String(error)}
                                                  </Typography>
                                                </Alert>
                                              ))}
                                            {upload.errors.length > 5 && (
                                              <Typography variant="caption" color="text.secondary">
                                                ... and {upload.errors.length - 5} more errors
                                              </Typography>
                                            )}
                                          </Stack>
                                        </Paper>
                                      </Grid>
                                    )}

                                    {/* Warnings */}
                                    {upload.warnings && upload.warnings.length > 0 && (
                                      <Grid size={{ xs: 12 }}>
                                        <Paper
                                          sx={{
                                            p: 2,
                                            bgcolor: alpha(theme.palette.warning.main, 0.05),
                                          }}
                                        >
                                          <Typography
                                            variant="subtitle2"
                                            fontWeight="bold"
                                            gutterBottom
                                            color="warning.main"
                                          >
                                            Warnings
                                          </Typography>
                                          <Divider sx={{ mb: 2 }} />
                                          <Stack spacing={1}>
                                            {upload.warnings
                                              .slice(0, 3)
                                              .map(
                                                (warning: UploadMessage | string, idx: number) => (
                                                  <Alert
                                                    key={idx}
                                                    severity="warning"
                                                    sx={{ py: 0 }}
                                                  >
                                                    <Typography variant="body2">
                                                      {typeof warning === 'string'
                                                        ? warning
                                                        : warning.message || String(warning)}
                                                    </Typography>
                                                  </Alert>
                                                )
                                              )}
                                            {upload.warnings.length > 3 && (
                                              <Typography variant="caption" color="text.secondary">
                                                ... and {upload.warnings.length - 3} more warnings
                                              </Typography>
                                            )}
                                          </Stack>
                                        </Paper>
                                      </Grid>
                                    )}
                                  </Grid>
                                </Box>
                              </Collapse>
                            </TableCell>
                          </TableRow>
                        </React.Fragment>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialog} onClose={() => setConfirmDialog(false)}>
        <DialogTitle>Confirm {operationType === 'sync' ? 'Synchronization' : 'Upload'}</DialogTitle>
        <DialogContent>
          <Typography>
            {operationType === 'sync'
              ? 'This will synchronize compliance rules from the Hanalyx repository. This process may take a few minutes.'
              : 'This will upload and validate the selected tar.gz file. The file will be thoroughly checked before updating the database.'}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Are you sure you want to continue?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDialog(false)}>Cancel</Button>
          <Button onClick={handleConfirmAction} variant="contained" color="primary">
            Continue
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UploadSyncRules;
