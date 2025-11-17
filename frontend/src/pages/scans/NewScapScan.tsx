import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Snackbar,
  Grid,
  Stepper,
  Step,
  StepLabel,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  LinearProgress,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Security as SecurityIcon,
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  NetworkCheck as NetworkCheckIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import { ScanService } from '../../services/scanService';
import PreFlightValidationDialog from '../../components/errors/PreFlightValidationDialog';
import ErrorClassificationDisplay, {
  type ClassifiedError,
} from '../../components/errors/ErrorClassificationDisplay';
import { errorService } from '../../services/errorService';
import { SUPPORTED_PLATFORMS, SUPPORTED_FRAMEWORKS } from '../../constants/complianceFrameworks';

interface Host {
  id: string; // Changed to string to handle UUID
  name: string;
  hostname: string;
  operating_system: string;
  status: string;
  platform?: string; // e.g., 'rhel', 'ubuntu'
  platform_version?: string; // e.g., '8', '22.04'
}

const steps = ['Select Host', 'Choose Framework', 'Configure Scan', 'Review & Start'];

const NewScapScan: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);

  // Form data
  const [scanName, setScanName] = useState('');
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState('');
  const [selectedPlatformVersion, setSelectedPlatformVersion] = useState('');
  const [selectedFramework, setSelectedFramework] = useState<
    (typeof SUPPORTED_FRAMEWORKS)[0] | null
  >(null);

  // Data
  const [hosts, setHosts] = useState<Host[]>([]);

  // UI state
  const [_loading, _setLoading] = useState(false); // Setter declared but not currently used - may be used for future loading states
  const [starting, setStarting] = useState(false);
  const [showPreFlightDialog, setShowPreFlightDialog] = useState(false);
  const [scanError, setScanError] = useState<ClassifiedError | null>(null);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'info',
  });

  const showSnackbar = (
    message: string,
    severity: 'success' | 'error' | 'warning' | 'info' = 'info'
  ) => {
    setSnackbar({ open: true, message, severity });
  };

  useEffect(() => {
    fetchHosts();
  }, []);

  useEffect(() => {
    // Generate default scan name when host and framework are selected
    if (selectedHost && selectedFramework && selectedPlatform && selectedPlatformVersion) {
      const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
      setScanName(
        `${selectedHost.name} - ${selectedFramework.name} - ${selectedPlatform} ${selectedPlatformVersion} - ${timestamp}`
      );
    }
  }, [selectedHost, selectedFramework, selectedPlatform, selectedPlatformVersion]);

  const fetchHosts = async () => {
    try {
      const data = await api.get('/api/hosts/');
      // Convert API data to expected format
      const formattedHosts = data.map((host: any) => ({
        id: host.id, // Keep as string UUID
        name: host.display_name || host.hostname,
        hostname: host.hostname,
        operating_system: host.operating_system,
        status: host.status,
      }));
      setHosts(formattedHosts);
    } catch {
      showSnackbar('Failed to load hosts', 'error');
    }
  };

  const handleNext = () => {
    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setActiveStep((prev) => prev - 1);
  };

  const canProceed = () => {
    switch (activeStep) {
      case 0:
        return selectedHost !== null;
      case 1:
        return (
          selectedPlatform !== '' && selectedPlatformVersion !== '' && selectedFramework !== null
        );
      case 2:
        return true; // Configure scan step is optional
      case 3:
        return scanName.trim() !== '';
      default:
        return false;
    }
  };

  const startScan = async () => {
    if (
      !selectedHost ||
      !selectedPlatform ||
      !selectedPlatformVersion ||
      !selectedFramework ||
      !scanName.trim()
    ) {
      showSnackbar('Please complete all required fields', 'error');
      return;
    }

    // Clear any previous error state
    setScanError(null);

    // Show pre-flight validation dialog
    setShowPreFlightDialog(true);
  };

  const handlePreFlightComplete = async () => {
    if (!selectedHost || !selectedPlatform || !selectedPlatformVersion || !selectedFramework)
      return;

    try {
      setStarting(true);
      setShowPreFlightDialog(false);

      // Use the new MongoDB scan API
      const result = await ScanService.startMongoDBScan(
        selectedHost.id,
        selectedHost.hostname,
        selectedPlatform,
        selectedPlatformVersion,
        selectedFramework.id
      );

      showSnackbar('Scan started successfully!', 'success');

      // Navigate to scan detail page after a short delay
      setTimeout(() => {
        navigate(`/scans/${result.scan_id}`);
      }, 1500);
    } catch (error: any) {
      console.error('Scan creation failed:', error);

      // Try to classify the error using our error service
      const classification = errorService.getErrorClassification(error);
      if (classification) {
        setScanError(classification);
      } else {
        // Fallback to generic error
        setScanError(errorService.classifyGenericError(error));
      }
    } finally {
      setStarting(false);
    }
  };

  const handleErrorRetry = async () => {
    setScanError(null);
    // Retry the scan creation
    await handlePreFlightComplete();
  };

  const handleApplyFix = async (fixId: string) => {
    if (!selectedHost) return;

    try {
      await errorService.applyAutomatedFix(selectedHost.id, fixId);
      showSnackbar('Fix applied successfully', 'success');
      setScanError(null);
    } catch (error: any) {
      showSnackbar(errorService.getUserFriendlyError(error), 'error');
    }
  };

  const getValidationRequest = () => {
    if (!selectedHost || !selectedPlatform || !selectedPlatformVersion || !selectedFramework)
      return null;

    return {
      host_id: selectedHost.id,
      platform: selectedPlatform,
      platform_version: selectedPlatformVersion,
      framework: selectedFramework.id,
    };
  };

  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Select Target Host
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Choose the host you want to scan for compliance.
            </Typography>

            <Grid container spacing={2}>
              {hosts.map((host) => (
                <Grid item xs={12} md={6} key={host.id}>
                  <Card
                    sx={{
                      cursor: 'pointer',
                      border: selectedHost?.id === host.id ? 2 : 1,
                      borderColor: selectedHost?.id === host.id ? 'primary.main' : 'divider',
                      '&:hover': {
                        borderColor: 'primary.main',
                        boxShadow: 1,
                      },
                    }}
                    onClick={() => setSelectedHost(host)}
                  >
                    <CardContent>
                      <Box display="flex" alignItems="center" gap={2}>
                        <ComputerIcon color={host.status === 'online' ? 'success' : 'disabled'} />
                        <Box flex={1}>
                          <Typography variant="subtitle1" fontWeight="medium">
                            {host.name}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {host.hostname}
                          </Typography>
                          <Typography variant="caption" display="block">
                            {host.operating_system}
                          </Typography>
                        </Box>
                        <Chip
                          label={host.status}
                          color={host.status === 'online' ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            {hosts.length === 0 && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                No hosts available. Please add hosts before creating scans.
              </Alert>
            )}
          </Box>
        );

      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Choose Framework & Platform
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Select the compliance framework and platform configuration for the scan.
            </Typography>

            {/* Platform Selection */}
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Platform
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Platform</InputLabel>
                <Select
                  value={selectedPlatform}
                  label="Platform"
                  onChange={(e) => {
                    setSelectedPlatform(e.target.value);
                    setSelectedPlatformVersion(''); // Reset version when platform changes
                  }}
                >
                  {SUPPORTED_PLATFORMS.map((platform) => (
                    <MenuItem key={platform.id} value={platform.id}>
                      {platform.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {selectedPlatform && (
                <FormControl fullWidth>
                  <InputLabel>Platform Version</InputLabel>
                  <Select
                    value={selectedPlatformVersion}
                    label="Platform Version"
                    onChange={(e) => setSelectedPlatformVersion(e.target.value)}
                  >
                    {SUPPORTED_PLATFORMS.find((p) => p.id === selectedPlatform)?.versions.map(
                      (version) => (
                        <MenuItem key={version} value={version}>
                          {version}
                        </MenuItem>
                      )
                    )}
                  </Select>
                </FormControl>
              )}
            </Box>

            {/* Framework Selection */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Compliance Framework
              </Typography>
              <Grid container spacing={2}>
                {SUPPORTED_FRAMEWORKS.map((framework) => (
                  <Grid item xs={12} sm={6} key={framework.id}>
                    <Card
                      sx={{
                        cursor: 'pointer',
                        border: selectedFramework?.id === framework.id ? 2 : 1,
                        borderColor:
                          selectedFramework?.id === framework.id ? 'primary.main' : 'divider',
                        '&:hover': {
                          borderColor: 'primary.main',
                          boxShadow: 1,
                        },
                      }}
                      onClick={() => setSelectedFramework(framework)}
                    >
                      <CardContent>
                        <Box display="flex" alignItems="center" gap={2}>
                          <SecurityIcon color="primary" />
                          <Box flex={1}>
                            <Typography variant="subtitle1" fontWeight="medium">
                              {framework.name}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {framework.description}
                            </Typography>
                          </Box>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Box>
        );

      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Configure Scan (Optional)
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Additional scan configuration options will be available in future updates. For now,
              MongoDB scans will use all available rules for the selected framework and platform.
            </Typography>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Scan Configuration Summary
              </Typography>
              <Typography variant="body2">
                Platform: {SUPPORTED_PLATFORMS.find((p) => p.id === selectedPlatform)?.name}{' '}
                {selectedPlatformVersion}
                <br />
                Framework: {selectedFramework?.name}
                <br />
                Scan Type: Full compliance scan (all applicable rules)
              </Typography>
            </Alert>
          </Box>
        );

      case 3:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review & Start Scan
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Review your scan configuration and provide a name for the scan.
            </Typography>

            <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Scan Configuration
              </Typography>
              <List dense>
                <ListItem disablePadding>
                  <ListItemIcon>
                    <ComputerIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Target Host"
                    secondary={`${selectedHost?.name} (${selectedHost?.hostname})`}
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemIcon>
                    <SecurityIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Platform"
                    secondary={`${SUPPORTED_PLATFORMS.find((p) => p.id === selectedPlatform)?.name} ${selectedPlatformVersion}`}
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemIcon>
                    <CheckCircleIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Compliance Framework"
                    secondary={selectedFramework?.name}
                  />
                </ListItem>
              </List>
            </Paper>

            <TextField
              fullWidth
              label="Scan Name"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              required
              helperText="Provide a descriptive name for this scan"
              sx={{ mb: 2 }}
            />

            {starting && (
              <Box sx={{ mt: 2 }}>
                <LinearProgress />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Starting scan...
                </Typography>
              </Box>
            )}
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        New SCAP Scan
      </Typography>

      <Paper sx={{ p: 3, mt: 3 }}>
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        <Box sx={{ minHeight: 400 }}>{renderStepContent()}</Box>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
          <Button onClick={handleBack} disabled={activeStep === 0}>
            Back
          </Button>

          <Box>
            {activeStep === steps.length - 1 ? (
              <Button
                variant="contained"
                onClick={startScan}
                disabled={!canProceed() || starting}
                startIcon={starting ? <NetworkCheckIcon /> : <PlayArrowIcon />}
                data-testid="start-scan-button"
              >
                {starting ? 'Starting...' : 'Validate & Start Scan'}
              </Button>
            ) : (
              <Button variant="contained" onClick={handleNext} disabled={!canProceed()}>
                Next
              </Button>
            )}
          </Box>
        </Box>
      </Paper>

      {/* Error Display */}
      {scanError && (
        <Box sx={{ mt: 3 }}>
          <ErrorClassificationDisplay
            error={scanError}
            onRetry={handleErrorRetry}
            onApplyFix={handleApplyFix}
            showTechnicalDetails={true}
            data-testid="scan-creation-error"
          />
        </Box>
      )}

      {/* Pre-Flight Validation Dialog */}
      <PreFlightValidationDialog
        open={showPreFlightDialog}
        onClose={() => setShowPreFlightDialog(false)}
        onProceed={handlePreFlightComplete}
        validationRequest={getValidationRequest()}
        title="Pre-Scan Validation"
        data-testid="scan-preflight-validation"
      />

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default NewScapScan;
