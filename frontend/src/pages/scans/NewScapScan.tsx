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
  Divider,
  LinearProgress,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Security as SecurityIcon,
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  NetworkCheck as NetworkCheckIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import PreFlightValidationDialog from '../../components/errors/PreFlightValidationDialog';
import ErrorClassificationDisplay, {
  ClassifiedError,
} from '../../components/errors/ErrorClassificationDisplay';
import { errorService } from '../../services/errorService';

interface Host {
  id: string; // Changed to string to handle UUID
  name: string;
  hostname: string;
  operating_system: string;
  status: string;
}

interface ScapContent {
  id: number;
  name: string;
  filename: string;
  content_type: string;
  profiles: Profile[];
}

interface Profile {
  id: string;
  title: string;
  description: string;
}

const steps = ['Select Host', 'Choose Content', 'Configure Scan', 'Review & Start'];

const NewScapScan: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);

  // Form data
  const [scanName, setScanName] = useState('');
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [selectedContent, setSelectedContent] = useState<ScapContent | null>(null);
  const [selectedProfile, setSelectedProfile] = useState<Profile | null>(null);

  // Data
  const [hosts, setHosts] = useState<Host[]>([]);
  const [scapContent, setScapContent] = useState<ScapContent[]>([]);

  // UI state
  const [loading, setLoading] = useState(false);
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
    fetchScapContent();
  }, []);

  useEffect(() => {
    // Generate default scan name when host and content are selected
    if (selectedHost && selectedContent && selectedProfile) {
      const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
      setScanName(`${selectedHost.name} - ${selectedProfile.title} - ${timestamp}`);
    }
  }, [selectedHost, selectedContent, selectedProfile]);

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
    } catch (error) {
      showSnackbar('Failed to load hosts', 'error');
    }
  };

  const fetchScapContent = async () => {
    try {
      const data = await api.get('/api/scap-content/');
      setScapContent(data.scap_content || []);
    } catch (error) {
      showSnackbar('Failed to load SCAP content', 'error');
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
        return selectedContent !== null;
      case 2:
        return selectedProfile !== null;
      case 3:
        return scanName.trim() !== '';
      default:
        return false;
    }
  };

  const startScan = async () => {
    if (!selectedHost || !selectedContent || !selectedProfile || !scanName.trim()) {
      showSnackbar('Please complete all required fields', 'error');
      return;
    }

    // Clear any previous error state
    setScanError(null);

    // Show pre-flight validation dialog
    setShowPreFlightDialog(true);
  };

  const handlePreFlightComplete = async () => {
    if (!selectedHost || !selectedContent || !selectedProfile) return;

    try {
      setStarting(true);
      setShowPreFlightDialog(false);

      const scanRequest = {
        name: scanName.trim(),
        host_id: selectedHost.id,
        content_id: selectedContent.id,
        profile_id: selectedProfile.id,
        scan_options: {},
      };

      const result = await api.post('/api/scans/', scanRequest);
      showSnackbar('Scan started successfully!', 'success');

      // Navigate to scan detail page after a short delay
      setTimeout(() => {
        navigate(`/scans/${result.id}`);
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
    if (!selectedHost || !selectedContent || !selectedProfile) return null;

    return {
      host_id: selectedHost.id,
      content_id: selectedContent.id,
      profile_id: selectedProfile.id,
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
              Choose Content
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Select the SCAP content to use for compliance checking.
            </Typography>

            <Grid container spacing={2}>
              {scapContent.map((content) => (
                <Grid item xs={12} key={content.id}>
                  <Card
                    sx={{
                      cursor: 'pointer',
                      border: selectedContent?.id === content.id ? 2 : 1,
                      borderColor: selectedContent?.id === content.id ? 'primary.main' : 'divider',
                      '&:hover': {
                        borderColor: 'primary.main',
                        boxShadow: 1,
                      },
                    }}
                    onClick={() => setSelectedContent(content)}
                  >
                    <CardContent>
                      <Box display="flex" alignItems="center" gap={2}>
                        <SecurityIcon color="primary" />
                        <Box flex={1}>
                          <Typography variant="subtitle1" fontWeight="medium">
                            {content.name}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {content.filename}
                          </Typography>
                          <Box display="flex" gap={1} mt={1}>
                            <Chip
                              label={content.content_type.toUpperCase()}
                              size="small"
                              color="primary"
                            />
                            <Chip
                              label={`${content.profiles.length} profiles`}
                              size="small"
                              variant="outlined"
                            />
                          </Box>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            {scapContent.length === 0 && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                No SCAP content available. Please upload SCAP content before creating scans.
              </Alert>
            )}
          </Box>
        );

      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Configure Scan
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Select the compliance profile to apply during the scan.
            </Typography>

            {selectedContent?.profiles.map((profile) => (
              <Card
                key={profile.id}
                sx={{
                  mb: 2,
                  cursor: 'pointer',
                  border: selectedProfile?.id === profile.id ? 2 : 1,
                  borderColor: selectedProfile?.id === profile.id ? 'primary.main' : 'divider',
                  '&:hover': {
                    borderColor: 'primary.main',
                    boxShadow: 1,
                  },
                }}
                onClick={() => setSelectedProfile(profile)}
              >
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="medium">
                    {profile.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {profile.description}
                  </Typography>
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                    Profile ID: {profile.id}
                  </Typography>
                </CardContent>
              </Card>
            ))}
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
                  <ListItemText primary="Content" secondary={selectedContent?.name} />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemIcon>
                    <CheckCircleIcon />
                  </ListItemIcon>
                  <ListItemText primary="Compliance Profile" secondary={selectedProfile?.title} />
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
