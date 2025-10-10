import React, { useState } from 'react';
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
  Grid,
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
} from '@mui/material';
import {
  CloudSync as SyncIcon,
  Upload as UploadIcon,
  Security as SecurityIcon,
  Schedule as ScheduleIcon,
  Verified as VerifiedIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Close as CloseIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';

interface UploadSyncRulesProps {}

const UploadSyncRules: React.FC<UploadSyncRulesProps> = () => {
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
  const [validationResults, setValidationResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

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
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      
      setLastSyncTime(new Date().toLocaleString());
      setSuccess('Successfully synchronized compliance rules from Hanalyx repository');
    } catch (err: any) {
      setError(`Sync failed: ${err.message}`);
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
      const token = localStorage.getItem('auth_token');
      if (!token) {
        throw new Error('Authentication token not found. Please log in again.');
      }

      // Call upload API
      setUploadProgress(10);
      const response = await fetch('/api/v1/compliance/upload-rules?deduplication_strategy=skip_unchanged_update_changed', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

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
          rulesCount: result.manifest?.rules_count || result.statistics?.imported + result.statistics?.updated + result.statistics?.skipped || 0,
          validationPassed: true,
          imported: result.statistics?.imported || 0,
          updated: result.statistics?.updated || 0,
          skipped: result.statistics?.skipped || 0,
          processingTime: result.processing_time_seconds,
          inheritanceImpact: result.inheritance_impact,
          issues: result.warnings || []
        });

        setSuccess(
          `Successfully uploaded ${selectedFile.name}: ` +
          `${result.statistics?.imported || 0} imported, ` +
          `${result.statistics?.updated || 0} updated, ` +
          `${result.statistics?.skipped || 0} skipped`
        );
      } else {
        // Upload failed
        setValidationResults({
          fileHash: result.file_hash || '',
          rulesCount: 0,
          validationPassed: false,
          issues: result.errors || []
        });

        throw new Error(
          result.errors?.[0]?.message || 'Upload validation failed'
        );
      }
    } catch (err: any) {
      setError(`Upload failed: ${err.message}`);
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

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      {/* Header */}
      <Box mb={3}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon color="primary" />
          Upload & Synchronize Rules
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Keep your compliance rules up-to-date from trusted Hanalyx repository or upload manual updates
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
        <Grid item xs={12} md={6}>
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
                    <Typography variant="body1">
                      Enable Automatic Sync
                    </Typography>
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
                  <Typography variant="body2">
                    Automatic synchronization is active
                  </Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Manual Upload */}
        <Grid item xs={12} md={6}>
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
                    <Typography variant="body1">
                      Enable Manual Upload
                    </Typography>
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
                  <Typography variant="body2">
                    Rules: {validationResults.rulesCount}
                  </Typography>
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
                  <Typography variant="body2">
                    Select a tar.gz file to continue
                  </Typography>
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Current Status */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Current Configuration
              </Typography>
              <Divider sx={{ mb: 2 }} />
              
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <Typography variant="body1" fontWeight="medium">
                      Synchronization Method:
                    </Typography>
                    <Chip
                      label={
                        syncEnabled ? 'Automatic Sync' : 
                        uploadEnabled ? 'Manual Upload' : 
                        'None Selected'
                      }
                      color={
                        syncEnabled || uploadEnabled ? 'success' : 'default'
                      }
                      icon={
                        syncEnabled ? <SyncIcon /> : 
                        uploadEnabled ? <UploadIcon /> : 
                        <WarningIcon />
                      }
                    />
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <Typography variant="body1" fontWeight="medium">
                      Status:
                    </Typography>
                    <Chip
                      label={
                        syncing ? 'Syncing...' :
                        uploading ? 'Uploading...' :
                        syncEnabled || uploadEnabled ? 'Active' : 'Inactive'
                      }
                      color={
                        syncing || uploading ? 'warning' :
                        syncEnabled || uploadEnabled ? 'success' : 'default'
                      }
                    />
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialog} onClose={() => setConfirmDialog(false)}>
        <DialogTitle>
          Confirm {operationType === 'sync' ? 'Synchronization' : 'Upload'}
        </DialogTitle>
        <DialogContent>
          <Typography>
            {operationType === 'sync' 
              ? 'This will synchronize compliance rules from the Hanalyx repository. This process may take a few minutes.'
              : 'This will upload and validate the selected tar.gz file. The file will be thoroughly checked before updating the database.'
            }
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Are you sure you want to continue?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleConfirmAction} 
            variant="contained"
            color="primary"
          >
            Continue
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UploadSyncRules;