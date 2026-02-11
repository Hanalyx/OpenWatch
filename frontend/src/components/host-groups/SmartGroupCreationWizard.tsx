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
  Card,
  CardContent,
  FormHelperText,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CheckCircle as SuccessIcon,
  Group as GroupIcon,
  Add as AddIcon,
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

const steps = ['Select Hosts', 'Configure Group', 'Review & Create'];

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
  const [complianceFramework, setComplianceFramework] = useState('');
  const [autoScanEnabled, setAutoScanEnabled] = useState(false);
  const [scanSchedule, setScanSchedule] = useState('');

  // Step 3: Validation Results
  const [validation, setValidation] = useState<GroupValidation | null>(null);

  useEffect(() => {
    if (open) {
      fetchHosts();
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
    setComplianceFramework('');
    setAutoScanEnabled(false);
    setScanSchedule('');
    setValidation(null);
    setError(null);
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

  const handleHostSelection = (host: Host, selected: boolean) => {
    if (selected) {
      setSelectedHosts([...selectedHosts, host]);
    } else {
      setSelectedHosts(selectedHosts.filter((h) => h.id !== host.id));
    }
  };

  const analyzeSelectedHosts = async () => {
    if (selectedHosts.length === 0) return;

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
          group_name: groupName || 'New Group',
          auto_configure: false, // Just get analysis
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze hosts');
      }

      const analysis = await response.json();

      // Apply smart configuration from analysis
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

        // Set compliance framework if recommended
        if (rec.compliance_framework) {
          const frameworkOption = COMPLIANCE_FRAMEWORK_OPTIONS.find(
            (opt) =>
              opt.value === rec.compliance_framework ||
              opt.label.toLowerCase().includes(rec.compliance_framework.toLowerCase())
          );
          if (frameworkOption) {
            setComplianceFramework(frameworkOption.value);
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
    const stepValidation = validateCurrentStep();
    if (!stepValidation.valid) {
      setError(stepValidation.message);
      return;
    }

    // Clear any previous errors
    setError(null);

    if (activeStep === 0) {
      // Moving from host selection to configuration - analyze hosts
      await analyzeSelectedHosts();
    } else if (activeStep === 1) {
      // Moving from configuration to review - validate configuration
      await validateGroupConfiguration();
    } else if (activeStep === 2) {
      // Final step - create group
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

        return {
          valid: errors.length === 0,
          message: errors.length > 0 ? errors[0] : null,
        };
      }
      case 2:
        return { valid: true, message: null }; // Review step - can always proceed
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
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Configure basic information and optional filtering criteria for this group
      </Typography>

      <Grid container spacing={3}>
        {/* Basic Info */}
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

        {/* Platform Filtering (Optional) */}
        <Grid size={12}>
          <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 1, mb: 1 }}>
            Platform Filtering (Optional)
          </Typography>
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
                <em>Any</em>
              </MenuItem>
              {OS_FAMILY_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Filter by operating system</FormHelperText>
          </FormControl>
        </Grid>

        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            label="OS Version Pattern"
            value={osVersionPattern}
            onChange={(e) => setOsVersionPattern(e.target.value)}
            fullWidth
            helperText="e.g., 9.*, 22.04"
            placeholder="Any version"
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
                <em>Any</em>
              </MenuItem>
              {ARCHITECTURE_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Filter by CPU architecture</FormHelperText>
          </FormControl>
        </Grid>

        {/* Compliance Settings */}
        <Grid size={12}>
          <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 1, mb: 1 }}>
            Compliance Settings
          </Typography>
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
                <em>Default (CIS)</em>
              </MenuItem>
              {COMPLIANCE_FRAMEWORK_OPTIONS.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>Framework used for compliance scanning</FormHelperText>
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
            label="Enable scheduled scanning"
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
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>When to run automatic scans</FormHelperText>
            </FormControl>
          )}
        </Grid>
      </Grid>
    </Box>
  );

  const renderReviewAndCreate = () => (
    <Box>
      {!createdGroupId ? (
        <>
          <Typography variant="h6" gutterBottom>
            Review & Create Group
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Review your configuration before creating the group
          </Typography>

          {/* Summary Card */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Grid container spacing={2}>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="overline" color="text.secondary">
                    Group Name
                  </Typography>
                  <Typography variant="body1">{groupName}</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="overline" color="text.secondary">
                    Hosts
                  </Typography>
                  <Typography variant="body1">{selectedHosts.length} selected</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="overline" color="text.secondary">
                    Framework
                  </Typography>
                  <Typography variant="body1">{complianceFramework || 'Default (CIS)'}</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="overline" color="text.secondary">
                    Auto-Scan
                  </Typography>
                  <Typography variant="body1">
                    {autoScanEnabled ? 'Enabled' : 'Disabled'}
                  </Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Validation Results */}
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
              <CircularProgress />
              <Typography sx={{ ml: 2 }}>Validating configuration...</Typography>
            </Box>
          ) : validation ? (
            <Box>
              {/* Warnings */}
              {validation.warnings.length > 0 && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Warnings:
                  </Typography>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {validation.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                </Alert>
              )}

              {/* Incompatible Hosts */}
              {validation.incompatible.length > 0 && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    {validation.summary.incompatible_count} host(s) may have compatibility issues:
                  </Typography>
                  <Box component="div" sx={{ mt: 1 }}>
                    {validation.incompatible.slice(0, 3).map((host) => (
                      <Chip
                        key={host.id}
                        label={host.hostname}
                        size="small"
                        sx={{ mr: 1, mb: 1 }}
                      />
                    ))}
                    {validation.incompatible.length > 3 && (
                      <Typography variant="caption" color="text.secondary">
                        ... and {validation.incompatible.length - 3} more
                      </Typography>
                    )}
                  </Box>
                </Alert>
              )}

              {/* Ready to create */}
              <Alert severity="success" icon={<GroupIcon />}>
                Ready to create group <strong>{groupName}</strong> with{' '}
                {validation.summary.compatible_count} compatible host(s)
              </Alert>
            </Box>
          ) : (
            <Alert severity="info">
              Configuration will be validated when you click Create Group
            </Alert>
          )}
        </>
      ) : (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <SuccessIcon sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            Group Created Successfully
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
            Group <strong>{groupName}</strong> has been created.
          </Typography>

          {hostAssignmentLoading ? (
            <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
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
        </Box>
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
        return renderReviewAndCreate();
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
      PaperProps={{ sx: { minHeight: '60vh' } }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GroupIcon color="primary" />
          <Typography variant="h6">Create Host Group</Typography>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && !error.includes('Group was created successfully') && (
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
        <Button onClick={onClose} disabled={loading || hostAssignmentLoading}>
          Cancel
        </Button>

        <Button
          onClick={handleBack}
          disabled={activeStep === 0 || loading || hostAssignmentLoading || !!createdGroupId}
        >
          Back
        </Button>

        {/* Show Create Group button on final step if group hasn't been created yet */}
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
        {createdGroupId &&
          !hostAssignmentLoading &&
          !error?.includes('Group was created successfully') && (
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
