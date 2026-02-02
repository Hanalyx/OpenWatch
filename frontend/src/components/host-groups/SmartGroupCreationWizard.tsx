import React, { useState, useEffect } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Alert,
  CircularProgress,
  Autocomplete,
  Card,
  CardContent,
  Switch,
  FormHelperText,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CheckCircle as SuccessIcon,
  Group as GroupIcon,
  Add as AddIcon,
  SmartToy as SmartIcon,
} from '@mui/icons-material';
import {
  OS_FAMILY_OPTIONS,
  ARCHITECTURE_OPTIONS,
  COMPLIANCE_FRAMEWORK_OPTIONS,
  SCAN_SCHEDULE_OPTIONS,
} from '../../constants/formOptions';

interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  operating_system?: string;
  os_family?: string;
  os_version?: string;
  architecture?: string;
}

interface Profile {
  id: string;
  title: string;
  description: string;
}

interface SCAPContent {
  id: number;
  name: string;
  os_family?: string;
  os_version?: string;
  compliance_framework?: string;
  profiles: Profile[] | string[];
}

/**
 * Group validation result from backend analysis
 * Provides compatibility analysis and recommendations for smart group creation
 */
interface GroupValidation {
  compatible: Host[];
  incompatible: Host[];
  warnings: string[];
  // Suggestions from validation - recommendations for group configuration
  suggestions: Record<string, string | number | boolean | string[]>;
  summary: {
    total_hosts: number;
    compatible_count: number;
    incompatible_count: number;
    compatibility_score: number;
  };
}

interface SmartGroupCreationWizardProps {
  open: boolean;
  onClose: () => void;
  onGroupCreated: () => void;
}

const steps = ['Select Hosts', 'Configure Group', 'Validation & Review', 'Create Group'];

const SmartGroupCreationWizard: React.FC<SmartGroupCreationWizardProps> = ({
  open,
  onClose,
  onGroupCreated,
}) => {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [hostAssignmentLoading, setHostAssignmentLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdGroupId, setCreatedGroupId] = useState<string | null>(null);

  // Step 1: Host Selection
  const [hosts, setHosts] = useState<Host[]>([]);
  const [selectedHosts, setSelectedHosts] = useState<Host[]>([]);

  // Step 2: Group Configuration
  const [groupName, setGroupName] = useState('');
  const [description, setDescription] = useState('');
  const [osFamily, setOsFamily] = useState('');
  const [osVersionPattern, setOsVersionPattern] = useState('');
  const [architecture, setArchitecture] = useState('');
  const [scapContent, setScapContent] = useState<SCAPContent | null>(null);
  const [defaultProfile, setDefaultProfile] = useState('');
  const [complianceFramework, setComplianceFramework] = useState('');
  const [autoScanEnabled, setAutoScanEnabled] = useState(false);
  const [scanSchedule, setScanSchedule] = useState('');
  const [useSmartConfiguration, setUseSmartConfiguration] = useState(true);

  // Step 3: Validation Results
  const [validation, setValidation] = useState<GroupValidation | null>(null);

  // Available data
  const [availableScapContent, setAvailableScapContent] = useState<SCAPContent[]>([]);
  const [scapContentLoading, setScapContentLoading] = useState(false);
  const [scapContentError, setScapContentError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      fetchHosts();
      fetchScapContent();
      resetWizard();
    }
  }, [open]);

  const resetWizard = () => {
    setActiveStep(0);
    setSelectedHosts([]);
    setGroupName('');
    setDescription('');
    setOsFamily('');
    setOsVersionPattern('');
    setArchitecture('');
    setScapContent(null);
    setDefaultProfile('');
    setComplianceFramework('');
    setAutoScanEnabled(false);
    setScanSchedule('');
    setUseSmartConfiguration(true);
    setValidation(null);
    setError(null);
    setScapContentError(null);
    setCreatedGroupId(null);
    setHostAssignmentLoading(false);
  };

  const fetchHosts = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/hosts/', {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch hosts');
      }

      const data = await response.json();
      const hostList = Array.isArray(data.hosts) ? data.hosts : Array.isArray(data) ? data : [];
      setHosts(hostList);
    } catch (err) {
      console.error('Error fetching hosts:', err);
      setError(err instanceof Error ? err.message : 'Failed to load hosts');
    } finally {
      setLoading(false);
    }
  };

  const fetchScapContent = async () => {
    try {
      setScapContentLoading(true);
      setScapContentError(null);

      // MongoDB compliance rules endpoint - returns bundles that can be used for scanning
      const response = await fetch('/api/compliance-rules/?view_mode=bundles', {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch SCAP content: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      // SCAP Content API response received successfully

      // MongoDB returns bundles in 'bundles' field
      let contentList: SCAPContent[] = [];
      if (Array.isArray(data.bundles)) {
        contentList = data.bundles;
      } else if (Array.isArray(data)) {
        // Fallback for array response
        contentList = data;
      }

      // SCAP content bundles parsed and loaded successfully
      setAvailableScapContent(contentList);
    } catch (err) {
      console.error('Error fetching SCAP content:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to load SCAP content';
      setScapContentError(errorMessage);
      setError(`SCAP Content loading failed: ${errorMessage}`);
    } finally {
      setScapContentLoading(false);
    }
  };

  const handleHostSelection = (host: Host, selected: boolean) => {
    if (selected) {
      setSelectedHosts([...selectedHosts, host]);
    } else {
      setSelectedHosts(selectedHosts.filter((h) => h.id !== host.id));
    }
  };

  const analyzeSelectedHosts = async () => {
    if (selectedHosts.length === 0 || !useSmartConfiguration) return;

    try {
      setLoading(true);

      const response = await fetch('/api/host-groups/smart-create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_ids: selectedHosts.map((h) => h.id),
          group_name: groupName || 'Smart Group',
          auto_configure: false, // Just get analysis
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze hosts');
      }

      const analysis = await response.json();

      // Apply smart configuration
      if (analysis.analysis?.recommendations) {
        const rec = analysis.analysis.recommendations;

        // Set OS family if it matches one of our predefined options
        if (rec.os_family) {
          const osOption = OS_FAMILY_OPTIONS.find(
            (opt) =>
              opt.value === rec.os_family.toLowerCase() ||
              opt.label.toLowerCase().includes(rec.os_family.toLowerCase())
          );
          if (osOption) {
            setOsFamily(osOption.value);
          }
        }

        if (rec.os_version_pattern) setOsVersionPattern(rec.os_version_pattern);

        // Set architecture if it matches one of our predefined options
        if (rec.architecture) {
          const archOption = ARCHITECTURE_OPTIONS.find(
            (opt) => opt.value === rec.architecture.toLowerCase()
          );
          if (archOption) {
            setArchitecture(archOption.value);
          }
        }

        if (rec.scap_content) {
          const content = availableScapContent.find((c) => c.id === rec.scap_content.id);
          if (content) {
            setScapContent(content);

            // Set compliance framework from content or recommendation
            const framework = rec.scap_content.compliance_framework || content.compliance_framework;
            if (framework) {
              const frameworkOption = COMPLIANCE_FRAMEWORK_OPTIONS.find(
                (opt) =>
                  opt.value === framework ||
                  opt.label.toLowerCase().includes(framework.toLowerCase())
              );
              if (frameworkOption) {
                setComplianceFramework(frameworkOption.value);
              }
            }
          }
        }
      }
    } catch (err) {
      // Host analysis failed - using default configuration
      console.error('Error analyzing hosts:', err);
    } finally {
      setLoading(false);
    }
  };

  const validateGroupConfiguration = async () => {
    if (selectedHosts.length === 0) return;

    try {
      setLoading(true);
      setError(null);

      // Create a temporary group configuration for validation
      const groupConfig = {
        name: groupName,
        description,
        os_family: osFamily,
        os_version_pattern: osVersionPattern,
        architecture,
        scap_content_id: scapContent?.id,
        default_profile_id: defaultProfile,
        compliance_framework: complianceFramework,
        auto_scan_enabled: autoScanEnabled,
        scan_schedule: scanSchedule,
      };

      // First create the group
      const createResponse = await fetch('/api/host-groups/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify(groupConfig),
      });

      if (!createResponse.ok) {
        throw new Error('Failed to create group for validation');
      }

      const tempGroup = await createResponse.json();

      // Then validate hosts against the group
      const validateResponse = await fetch(`/api/host-groups/${tempGroup.id}/validate-hosts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_ids: selectedHosts.map((h) => h.id),
        }),
      });

      if (validateResponse.ok) {
        const validationData = await validateResponse.json();
        setValidation(validationData);
      }

      // Clean up temporary group
      await fetch(`/api/host-groups/${tempGroup.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });
    } catch (err) {
      // Group configuration validation failed
      console.error('Error validating group:', err);
      setError(err instanceof Error ? err.message : 'Failed to validate group configuration');
    } finally {
      setLoading(false);
    }
  };

  const createGroup = async () => {
    try {
      setLoading(true);
      setError(null);

      const groupConfig = {
        name: groupName,
        description,
        os_family: osFamily,
        os_version_pattern: osVersionPattern,
        architecture,
        scap_content_id: scapContent?.id,
        default_profile_id: defaultProfile,
        compliance_framework: complianceFramework,
        auto_scan_enabled: autoScanEnabled,
        scan_schedule: scanSchedule,
      };

      // Creating host group with validated configuration

      const createResponse = await fetch('/api/host-groups/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify(groupConfig),
      });

      if (!createResponse.ok) {
        const errorData = await createResponse.json().catch(() => null);
        const errorMessage =
          errorData?.detail || `Failed to create group (${createResponse.status})`;
        throw new Error(errorMessage);
      }

      const group = await createResponse.json();
      // Host group created successfully
      setCreatedGroupId(group.id);

      // Switch to host assignment loading state
      setLoading(false);
      setHostAssignmentLoading(true);

      // Assign hosts to the group
      await assignHostsToGroup(group.id);
    } catch (err) {
      // Group creation failed
      console.error('Error creating group:', err);
      setError(err instanceof Error ? err.message : 'Failed to create group');
    } finally {
      setLoading(false);
      setHostAssignmentLoading(false);
    }
  };

  const assignHostsToGroup = async (groupId: string) => {
    try {
      const hostIds = selectedHosts.map((h) => h.id);
      // Assigning selected hosts to the newly created group

      const assignResponse = await fetch(`/api/host-groups/${groupId}/hosts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_ids: hostIds,
        }),
      });

      if (!assignResponse.ok) {
        const errorData = await assignResponse.json().catch(() => null);
        const errorMessage =
          errorData?.detail || `Failed to assign hosts to group (${assignResponse.status})`;
        // Host assignment to group failed - group created but hosts not added

        // If group was created but host assignment failed, provide recovery options
        setError(`Group was created successfully, but failed to assign hosts: ${errorMessage}`);
        return;
      }

      // All hosts successfully assigned to the group
      onGroupCreated();
      onClose();
    } catch (err) {
      console.error('Error assigning hosts:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to assign hosts';
      setError(`Group was created successfully, but failed to assign hosts: ${errorMessage}`);
    }
  };

  const retryHostAssignment = async () => {
    if (!createdGroupId) return;

    setError(null);
    setHostAssignmentLoading(true);

    try {
      await assignHostsToGroup(createdGroupId);
    } finally {
      setHostAssignmentLoading(false);
    }
  };

  const handleNext = async () => {
    // Validate current step before proceeding
    const validation = validateCurrentStep();
    if (!validation.valid) {
      setError(validation.message);
      return;
    }

    // Clear any previous errors
    setError(null);

    if (activeStep === 1) {
      await analyzeSelectedHosts();
    } else if (activeStep === 2) {
      await validateGroupConfiguration();
    } else if (activeStep === 3) {
      await createGroup();
      return;
    }

    setActiveStep(activeStep + 1);
  };

  const handleBack = () => {
    setActiveStep(activeStep - 1);
  };

  const validateCurrentStep = () => {
    switch (activeStep) {
      case 0:
        return {
          valid: selectedHosts.length > 0,
          message: selectedHosts.length === 0 ? 'Please select at least one host' : null,
        };
      case 1: {
        const errors = [];
        if (!groupName.trim()) errors.push('Group name is required');
        if (groupName.trim().length < 3) errors.push('Group name must be at least 3 characters');
        if (scapContent && !defaultProfile)
          errors.push('Default profile is required when SCAP content is selected');

        return {
          valid: errors.length === 0,
          message: errors.length > 0 ? errors[0] : null,
        };
      }
      case 2:
        return { valid: true, message: null }; // Can always review
      case 3:
        return { valid: true, message: null };
      default:
        return { valid: false, message: 'Invalid step' };
    }
  };

  const canProceed = () => {
    return validateCurrentStep().valid;
  };

  const renderHostSelection = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Select Hosts for Group
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Choose the hosts you want to include in this compliance group
      </Typography>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
          <CircularProgress />
        </Box>
      ) : (
        <List sx={{ maxHeight: 400, overflow: 'auto' }}>
          {hosts.map((host) => {
            const isSelected = selectedHosts.some((h) => h.id === host.id);

            return (
              <ListItem key={host.id}>
                <ListItemIcon>
                  <Checkbox
                    checked={isSelected}
                    onChange={(e) => handleHostSelection(host, e.target.checked)}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={host.hostname}
                  secondary={
                    <Box component="span" sx={{ display: 'block' }}>
                      <Typography variant="caption" display="block" component="span">
                        {host.ip_address}
                      </Typography>
                      {host.operating_system && (
                        <Chip
                          label={host.operating_system}
                          size="small"
                          sx={{ mt: 0.5, display: 'inline-block' }}
                        />
                      )}
                    </Box>
                  }
                />
              </ListItem>
            );
          })}
        </List>
      )}

      <Box sx={{ mt: 2, p: 2, bgcolor: 'background.paper', borderRadius: 1 }}>
        <Typography variant="subtitle2">
          Selected: {selectedHosts.length} host{selectedHosts.length !== 1 ? 's' : ''}
        </Typography>
      </Box>
    </Box>
  );

  const renderGroupConfiguration = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Configure Group Settings
      </Typography>

      <Box sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Switch
              checked={useSmartConfiguration}
              onChange={(e) => setUseSmartConfiguration(e.target.checked)}
            />
          }
          label="Use smart configuration (analyze selected hosts)"
        />
      </Box>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Group Name"
            value={groupName}
            onChange={(e) => setGroupName(e.target.value)}
            fullWidth
            required
            helperText="A descriptive name for this compliance group"
          />
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            multiline
            rows={2}
            helperText="Optional description of the group's purpose"
          />
        </Grid>

        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControl fullWidth>
            <InputLabel>OS Family</InputLabel>
            <Select
              value={osFamily}
              onChange={(e) => setOsFamily(e.target.value)}
              label="OS Family"
            >
              <MenuItem value="">
                <em>Select OS Family</em>
              </MenuItem>
              {OS_FAMILY_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Choose the operating system family</FormHelperText>
          </FormControl>
        </Grid>

        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            label="OS Version Pattern"
            value={osVersionPattern}
            onChange={(e) => setOsVersionPattern(e.target.value)}
            fullWidth
            helperText="e.g., 8.*, 22.04, 2019"
            placeholder="Enter version pattern"
          />
        </Grid>

        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControl fullWidth>
            <InputLabel>Architecture</InputLabel>
            <Select
              value={architecture}
              onChange={(e) => setArchitecture(e.target.value)}
              label="Architecture"
            >
              <MenuItem value="">
                <em>Select Architecture</em>
              </MenuItem>
              {ARCHITECTURE_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Choose the system architecture</FormHelperText>
          </FormControl>
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          <Autocomplete
            options={availableScapContent}
            getOptionLabel={(option) => option.name}
            value={scapContent}
            onChange={(_, newValue) => {
              setScapContent(newValue);
              // Reset default profile when content changes
              setDefaultProfile('');
            }}
            loading={scapContentLoading}
            renderInput={(params) => (
              <TextField
                {...params}
                label="SCAP Content"
                helperText={
                  scapContentError
                    ? `Error: ${scapContentError}`
                    : scapContentLoading
                      ? 'Loading content...'
                      : availableScapContent.length === 0
                        ? 'No content available - upload content first'
                        : 'Choose compliance content for scanning'
                }
                error={!!scapContentError}
                InputProps={{
                  ...params.InputProps,
                  endAdornment: (
                    <>
                      {scapContentLoading ? <CircularProgress color="inherit" size={20} /> : null}
                      {params.InputProps.endAdornment}
                    </>
                  ),
                }}
              />
            )}
            renderOption={(props, option) => (
              <Box component="li" {...props}>
                <Box>
                  <Typography variant="body2" fontWeight="medium">
                    {option.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {option.os_family?.toUpperCase()} {option.os_version} •{' '}
                    {option.compliance_framework}
                  </Typography>
                </Box>
              </Box>
            )}
            noOptionsText={
              scapContentLoading
                ? 'Loading...'
                : scapContentError
                  ? 'Failed to load content'
                  : 'No SCAP content available - upload content first'
            }
          />
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          {scapContent && scapContent.profiles && scapContent.profiles.length > 0 ? (
            <FormControl fullWidth>
              <InputLabel>Default Profile</InputLabel>
              <Select
                value={defaultProfile}
                onChange={(e) => setDefaultProfile(e.target.value)}
                label="Default Profile"
              >
                <MenuItem value="">
                  <em>Select Profile</em>
                </MenuItem>
                {scapContent.profiles.map((profile, index) => {
                  // Handle both object and string profiles
                  const profileId = typeof profile === 'object' ? profile.id : profile;
                  const profileTitle = typeof profile === 'object' ? profile.title : profile;
                  const profileDescription = typeof profile === 'object' ? profile.description : '';

                  return (
                    <MenuItem key={profileId || index} value={profileId}>
                      <Box>
                        <Typography variant="body2">{profileTitle}</Typography>
                        {profileDescription && (
                          <Typography variant="caption" color="text.secondary">
                            {profileDescription}
                          </Typography>
                        )}
                      </Box>
                    </MenuItem>
                  );
                })}
              </Select>
              <FormHelperText>Choose the default scanning profile</FormHelperText>
            </FormControl>
          ) : (
            <TextField
              label="Default Profile"
              value={defaultProfile}
              onChange={(e) => setDefaultProfile(e.target.value)}
              fullWidth
              disabled={!scapContent}
              helperText={
                scapContent
                  ? 'No profiles available in selected content'
                  : 'Select SCAP content first'
              }
              placeholder="Enter profile ID"
            />
          )}
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControl fullWidth>
            <InputLabel>Compliance Framework</InputLabel>
            <Select
              value={complianceFramework}
              onChange={(e) => setComplianceFramework(e.target.value)}
              label="Compliance Framework"
            >
              <MenuItem value="">
                <em>Select Framework</em>
              </MenuItem>
              {COMPLIANCE_FRAMEWORK_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  <Box>
                    <Typography variant="body2">{option.label}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {option.description}
                    </Typography>
                  </Box>
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Choose the compliance standard</FormHelperText>
          </FormControl>
        </Grid>

        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={autoScanEnabled}
                onChange={(e) => setAutoScanEnabled(e.target.checked)}
              />
            }
            label="Enable automatic scanning"
          />

          {autoScanEnabled && (
            <FormControl fullWidth size="small" sx={{ mt: 1 }}>
              <InputLabel>Scan Schedule</InputLabel>
              <Select
                value={scanSchedule}
                onChange={(e) => setScanSchedule(e.target.value)}
                label="Scan Schedule"
              >
                {SCAN_SCHEDULE_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    <Box>
                      <Typography variant="body2">{option.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {option.description}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {scanSchedule === 'custom'
                  ? 'Enter custom cron expression below'
                  : 'Choose when to run automatic scans'}
              </FormHelperText>
            </FormControl>
          )}

          {autoScanEnabled && scanSchedule === 'custom' && (
            <TextField
              label="Custom Cron Expression"
              value={scanSchedule === 'custom' ? '' : scanSchedule}
              onChange={(e) => setScanSchedule(e.target.value)}
              fullWidth
              size="small"
              sx={{ mt: 1 }}
              helperText="e.g., 0 2 * * * (daily at 2 AM)"
              placeholder="0 2 * * *"
            />
          )}
        </Grid>
      </Grid>
    </Box>
  );

  const renderValidationResults = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Validation Results
      </Typography>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
          <CircularProgress />
        </Box>
      ) : validation ? (
        <Box>
          {/* Summary */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Grid container spacing={2}>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="primary">
                      {validation.summary.total_hosts}
                    </Typography>
                    <Typography variant="caption">Total Hosts</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="success.main">
                      {validation.summary.compatible_count}
                    </Typography>
                    <Typography variant="caption">Compatible</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="error.main">
                      {validation.summary.incompatible_count}
                    </Typography>
                    <Typography variant="caption">Incompatible</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" color="info.main">
                      {validation.summary.compatibility_score.toFixed(1)}%
                    </Typography>
                    <Typography variant="caption">Compatibility</Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Warnings */}
          {validation.warnings.length > 0 && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Warnings:
              </Typography>
              <ul>
                {validation.warnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </Alert>
          )}

          {/* Incompatible Hosts */}
          {validation.incompatible.length > 0 && (
            <Alert severity="error" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Incompatible Hosts ({validation.incompatible.length}):
              </Typography>
              <Box component="div" sx={{ mt: 1 }}>
                {validation.incompatible.slice(0, 3).map((host) => (
                  <Chip
                    key={host.id}
                    label={host.hostname}
                    size="small"
                    color="error"
                    sx={{ mr: 1, mb: 1 }}
                  />
                ))}
                {validation.incompatible.length > 3 && (
                  <Box component="span" sx={{ display: 'block', mt: 1 }}>
                    <Typography variant="caption" color="text.secondary" component="span">
                      ... and {validation.incompatible.length - 3} more
                    </Typography>
                  </Box>
                )}
              </Box>
            </Alert>
          )}

          {/* Compatible Hosts */}
          <Alert severity="success">
            <Typography variant="subtitle2" gutterBottom>
              Compatible Hosts ({validation.compatible.length}):
            </Typography>
            <Box component="div" sx={{ mt: 1 }}>
              {validation.compatible.slice(0, 5).map((host) => (
                <Chip
                  key={host.id}
                  label={host.hostname}
                  size="small"
                  color="success"
                  sx={{ mr: 1, mb: 1 }}
                />
              ))}
              {validation.compatible.length > 5 && (
                <Box component="span" sx={{ display: 'block', mt: 1 }}>
                  <Typography variant="caption" color="text.secondary" component="span">
                    ... and {validation.compatible.length - 5} more
                  </Typography>
                </Box>
              )}
            </Box>
          </Alert>
        </Box>
      ) : (
        <Typography color="text.secondary">
          Click Next to validate the group configuration
        </Typography>
      )}
    </Box>
  );

  const renderCreateGroup = () => (
    <Box sx={{ textAlign: 'center', py: 4 }}>
      {!createdGroupId ? (
        <>
          <GroupIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            Ready to Create Group
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Group {groupName} will be created with {selectedHosts.length} hosts
          </Typography>

          {validation && validation.summary.incompatible_count > 0 && (
            <Alert severity="info" sx={{ mb: 2 }}>
              {validation.summary.compatible_count} compatible hosts will be assigned. Incompatible
              hosts will be skipped.
            </Alert>
          )}
        </>
      ) : (
        <>
          <SuccessIcon sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            Group Created Successfully
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
            Group {groupName} has been created.
          </Typography>

          {hostAssignmentLoading ? (
            <Box sx={{ mb: 2 }}>
              <CircularProgress size={24} sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Assigning hosts to group...
              </Typography>
            </Box>
          ) : error && error.includes('Group was created successfully') ? (
            <Box sx={{ mb: 2 }}>
              <Alert severity="warning" sx={{ mb: 2 }}>
                {error}
              </Alert>
              <Button
                variant="contained"
                onClick={retryHostAssignment}
                startIcon={<AddIcon />}
                disabled={hostAssignmentLoading}
              >
                Retry Host Assignment
              </Button>
              <Button
                variant="outlined"
                onClick={() => {
                  onGroupCreated();
                  onClose();
                }}
                sx={{ ml: 1 }}
              >
                Continue Without Hosts
              </Button>
            </Box>
          ) : null}
        </>
      )}
    </Box>
  );

  const getStepContent = () => {
    switch (activeStep) {
      case 0:
        return renderHostSelection();
      case 1:
        return renderGroupConfiguration();
      case 2:
        return renderValidationResults();
      case 3:
        return renderCreateGroup();
      default:
        return null;
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{ sx: { minHeight: '70vh' } }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SmartIcon color="primary" />
          <Typography variant="h6">Smart Group Creation Wizard</Typography>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Stepper activeStep={activeStep} orientation="vertical">
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
              <StepContent>{index === activeStep && getStepContent()}</StepContent>
            </Step>
          ))}
        </Stepper>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>

        <Button
          onClick={handleBack}
          disabled={activeStep === 0 || loading || hostAssignmentLoading}
        >
          Back
        </Button>

        {/* Show Create Group button only if group hasn't been created yet */}
        {activeStep === steps.length - 1 && !createdGroupId && (
          <Button variant="contained" onClick={handleNext} disabled={!canProceed() || loading}>
            {loading ? <CircularProgress size={20} /> : 'Create Group'}
          </Button>
        )}

        {/* Show Next button for other steps */}
        {activeStep < steps.length - 1 && (
          <Button variant="contained" onClick={handleNext} disabled={!canProceed() || loading}>
            {loading ? <CircularProgress size={20} /> : 'Next'}
          </Button>
        )}

        {/* Show Done button when group is created and assignment is complete */}
        {createdGroupId && !hostAssignmentLoading && !error && (
          <Button
            variant="contained"
            color="success"
            onClick={() => {
              onGroupCreated();
              onClose();
            }}
          >
            Done
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default SmartGroupCreationWizard;
