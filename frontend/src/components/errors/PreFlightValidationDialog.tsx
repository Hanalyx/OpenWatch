import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  AlertTitle,
  Divider,
  Paper,
  CircularProgress,
  Collapse,
  IconButton,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  Extension as ExtensionIcon,
  PlayArrow as PlayArrowIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';
import ErrorClassificationDisplay, { type ClassifiedError } from './ErrorClassificationDisplay';
import type { SystemInfo } from '../../services/errorService';

export interface ValidationRequest {
  host_id: string;
  // Legacy SCAP content scanning fields
  content_id?: number;
  profile_id?: string;
  // MongoDB scanning fields
  platform?: string;
  platform_version?: string;
  framework?: string;
}

export interface ValidationResult {
  can_proceed: boolean;
  errors: ClassifiedError[];
  warnings: ClassifiedError[];
  pre_flight_duration: number;
  // System information collected during validation - see errorService.ts for structure
  system_info: SystemInfo;
  validation_checks: Record<string, boolean>;
}

interface ValidationStep {
  id: string;
  label: string;
  icon: React.ReactNode;
  status: 'pending' | 'running' | 'success' | 'warning' | 'error';
  duration?: number;
  details?: string;
}

interface PreFlightValidationDialogProps {
  open: boolean;
  onClose: () => void;
  onProceed: () => void;
  validationRequest: ValidationRequest | null;
  title?: string;
  'data-testid'?: string;
}

const getStepIcon = (status: string, icon: React.ReactNode) => {
  switch (status) {
    case 'success':
      return <CheckCircleIcon color="success" />;
    case 'error':
      return <ErrorIcon color="error" />;
    case 'warning':
      return <WarningIcon color="warning" />;
    case 'running':
      return <CircularProgress size={20} />;
    default:
      return icon;
  }
};

/**
 * Get MUI Chip color for validation step status
 * Maps step status to Material-UI color palette values
 */
const getStepColor = (status: string): 'success' | 'error' | 'warning' | 'primary' | 'default' => {
  switch (status) {
    case 'success':
      return 'success';
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'running':
      return 'primary';
    default:
      return 'default';
  }
};

/**
 * Mapping from frontend step IDs to backend validation_checks keys
 * Frontend groups related checks into logical categories for better UX
 */
const STEP_TO_CHECKS_MAP: Record<string, string[]> = {
  network_connectivity: ['network_connectivity'],
  authentication: [], // SSH auth is implicit - if we get results, auth worked
  privileges: ['sudo_access', 'selinux_status'],
  resources: ['disk_space', 'memory_availability'],
  dependencies: ['oscap_installation', 'operating_system', 'component_detection'],
};

/**
 * Mapping from error categories to frontend step IDs
 */
const CATEGORY_TO_STEP_MAP: Record<string, string> = {
  network: 'network_connectivity',
  authentication: 'authentication',
  privilege: 'privileges',
  resource: 'resources',
  dependency: 'dependencies',
  configuration: 'dependencies',
  execution: 'dependencies',
};

export const PreFlightValidationDialog: React.FC<PreFlightValidationDialogProps> = ({
  open,
  onClose,
  onProceed,
  validationRequest,
  title = 'Pre-Flight Validation',
  'data-testid': testId = 'preflight-validation-dialog',
}) => {
  const [validationSteps, setValidationSteps] = useState<ValidationStep[]>([
    {
      id: 'network_connectivity',
      label: 'Network Connectivity',
      icon: <NetworkIcon />,
      status: 'pending',
    },
    {
      id: 'authentication',
      label: 'SSH Authentication',
      icon: <SecurityIcon />,
      status: 'pending',
    },
    {
      id: 'privileges',
      label: 'System Privileges',
      icon: <SecurityIcon />,
      status: 'pending',
    },
    {
      id: 'resources',
      label: 'System Resources',
      icon: <StorageIcon />,
      status: 'pending',
    },
    {
      id: 'dependencies',
      label: 'OpenSCAP Dependencies',
      icon: <ExtensionIcon />,
      status: 'pending',
    },
  ]);

  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1);
  const [showErrors, setShowErrors] = useState(true);
  const [showWarnings, setShowWarnings] = useState(false);
  const [showSystemInfo, setShowSystemInfo] = useState(false);

  // Start validation when dialog opens with valid request
  // ESLint disable: startValidation function is not memoized to avoid complex dependency chain
  useEffect(() => {
    if (open && validationRequest) {
      startValidation();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, validationRequest]);

  const updateStepStatus = (
    stepId: string,
    status: ValidationStep['status'],
    duration?: number,
    details?: string
  ) => {
    setValidationSteps((prev) =>
      prev.map((step) => (step.id === stepId ? { ...step, status, duration, details } : step))
    );
  };

  const startValidation = async () => {
    if (!validationRequest) return;

    setIsValidating(true);
    setValidationResult(null);
    setCurrentStep(0);

    // Reset all steps to pending
    setValidationSteps((prev) => prev.map((step) => ({ ...step, status: 'pending' as const })));

    try {
      // Simulate step-by-step validation for better UX
      const steps = validationSteps.map((s) => s.id);

      for (let i = 0; i < steps.length; i++) {
        setCurrentStep(i);
        updateStepStatus(steps[i], 'running');

        // Add small delay for visual feedback
        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      // Perform actual validation
      const result = await api.post<ValidationResult>('/api/scans/validate', validationRequest);

      // Update steps based on validation results
      // Use the mapping to convert backend check keys to frontend step IDs
      const frontendSteps = [
        'network_connectivity',
        'authentication',
        'privileges',
        'resources',
        'dependencies',
      ];

      frontendSteps.forEach((stepId) => {
        const relatedChecks = STEP_TO_CHECKS_MAP[stepId] || [];

        // Find errors and warnings for this step based on category mapping
        const stepErrors = result.errors.filter(
          (e) => CATEGORY_TO_STEP_MAP[e.category.toLowerCase()] === stepId
        );
        const stepWarnings = result.warnings.filter(
          (w) => CATEGORY_TO_STEP_MAP[w.category.toLowerCase()] === stepId
        );

        // Determine step status based on related backend checks
        let status: ValidationStep['status'] = 'success';
        let details: string | undefined;

        if (stepErrors.length > 0) {
          status = 'error';
          details = stepErrors[0].message;
        } else if (stepWarnings.length > 0) {
          status = 'warning';
          details = stepWarnings[0].message;
        } else if (relatedChecks.length > 0) {
          // Check if any related backend checks failed
          const anyFailed = relatedChecks.some(
            (checkKey) => result.validation_checks[checkKey] === false
          );
          if (anyFailed) {
            status = 'warning';
          }
        } else if (stepId === 'authentication') {
          // Authentication is implicit - if we got results, auth worked
          status = 'success';
        }

        updateStepStatus(stepId, status, undefined, details);
      });

      setValidationResult(result);
    } catch (error) {
      // Handle validation errors with proper type checking
      console.error('Validation failed:', error);

      // Extract error message from different error formats
      const errorMessage =
        (error as { response?: { data?: { detail?: string } } }).response?.data?.detail ||
        (error instanceof Error ? error.message : null) ||
        'Validation failed';

      // Mark current step as failed
      if (currentStep >= 0 && currentStep < validationSteps.length) {
        updateStepStatus(validationSteps[currentStep].id, 'error', undefined, errorMessage);
      }

      // Create a fallback validation result
      setValidationResult({
        can_proceed: false,
        errors: [
          {
            error_code: 'VAL_001',
            category: 'execution',
            severity: 'error',
            message: 'Pre-flight validation failed',
            user_guidance:
              error.response?.data?.detail ||
              error.message ||
              'An error occurred during validation',
            technical_details: { error: error.message },
            automated_fixes: [],
            can_retry: true,
            retry_after: 30,
          },
        ],
        warnings: [],
        pre_flight_duration: 0,
        system_info: {},
        validation_checks: {},
      });
    } finally {
      setIsValidating(false);
      setCurrentStep(-1);
    }
  };

  const handleApplyFix = async (fixId: string) => {
    // This would integrate with the automated fix API
    // TODO: Implement automated fix application for fix ID: ${fixId}
    void fixId; // Suppress unused parameter warning
  };

  const handleClose = () => {
    if (!isValidating) {
      onClose();
    }
  };

  const canProceed = validationResult?.can_proceed || false;
  const hasErrors = (validationResult?.errors.length || 0) > 0;
  const hasWarnings = (validationResult?.warnings.length || 0) > 0;

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth data-testid={testId}>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={2}>
          <NetworkIcon />
          {title}
          {isValidating && (
            <Chip
              icon={<CircularProgress size={16} />}
              label="Validating..."
              color="primary"
              size="small"
            />
          )}
        </Box>
      </DialogTitle>

      <DialogContent>
        {/* Validation Steps */}
        <Paper variant="outlined" sx={{ mb: 3 }}>
          <List>
            {validationSteps.map((step, index) => (
              <React.Fragment key={step.id}>
                <ListItem>
                  <ListItemIcon>{getStepIcon(step.status, step.icon)}</ListItemIcon>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={2}>
                        <Typography variant="body1">{step.label}</Typography>
                        <Chip
                          label={step.status.charAt(0).toUpperCase() + step.status.slice(1)}
                          color={getStepColor(step.status)}
                          size="small"
                          variant="outlined"
                        />
                        {step.duration && (
                          <Typography variant="caption" color="text.secondary">
                            ({step.duration.toFixed(2)}s)
                          </Typography>
                        )}
                      </Box>
                    }
                    secondary={step.details}
                  />
                </ListItem>
                {index < validationSteps.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        </Paper>

        {/* Validation Results Summary */}
        {validationResult && !isValidating && (
          <Box mb={3}>
            <Typography variant="h6" gutterBottom>
              Validation Results
            </Typography>

            <Box display="flex" gap={2} mb={2}>
              <Chip
                icon={canProceed ? <CheckCircleIcon /> : <ErrorIcon />}
                label={canProceed ? 'Ready to Proceed' : 'Issues Found'}
                color={canProceed ? 'success' : 'error'}
              />
              <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
                Completed in {validationResult.pre_flight_duration.toFixed(2)}s
              </Typography>
            </Box>

            {!canProceed && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                <AlertTitle>Validation Issues Detected</AlertTitle>
                Please resolve the issues below before proceeding with the scan.
              </Alert>
            )}
          </Box>
        )}

        {/* Errors Section */}
        {hasErrors && (
          <Box mb={3}>
            <Box display="flex" alignItems="center" gap={1} mb={2}>
              <Typography variant="h6" color="error">
                Errors ({validationResult!.errors.length})
              </Typography>
              <IconButton
                size="small"
                onClick={() => setShowErrors(!showErrors)}
                data-testid="toggle-errors"
              >
                {showErrors ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            </Box>
            <Collapse in={showErrors}>
              <Box>
                {validationResult!.errors.map((error, index) => (
                  <ErrorClassificationDisplay
                    key={`error-${index}`}
                    error={error}
                    onRetry={startValidation}
                    onApplyFix={handleApplyFix}
                    data-testid={`validation-error-${index}`}
                  />
                ))}
              </Box>
            </Collapse>
          </Box>
        )}

        {/* Warnings Section */}
        {hasWarnings && (
          <Box mb={3}>
            <Box display="flex" alignItems="center" gap={1} mb={2}>
              <Typography variant="h6" color="warning.main">
                Warnings ({validationResult!.warnings.length})
              </Typography>
              <IconButton
                size="small"
                onClick={() => setShowWarnings(!showWarnings)}
                data-testid="toggle-warnings"
              >
                {showWarnings ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            </Box>
            <Collapse in={showWarnings}>
              <Box>
                {validationResult!.warnings.map((warning, index) => (
                  <ErrorClassificationDisplay
                    key={`warning-${index}`}
                    error={warning}
                    onRetry={startValidation}
                    onApplyFix={handleApplyFix}
                    compact
                    data-testid={`validation-warning-${index}`}
                  />
                ))}
              </Box>
            </Collapse>
          </Box>
        )}

        {/* System Information */}
        {validationResult && Object.keys(validationResult.system_info).length > 0 && (
          <Box>
            <Box display="flex" alignItems="center" gap={1} mb={2}>
              <Typography variant="h6">System Information</Typography>
              <IconButton
                size="small"
                onClick={() => setShowSystemInfo(!showSystemInfo)}
                data-testid="toggle-system-info"
              >
                {showSystemInfo ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            </Box>
            <Collapse in={showSystemInfo}>
              <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
                <pre
                  style={{
                    fontSize: '0.875rem',
                    margin: 0,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {validationResult.system_info.system_details || 'No system details available'}
                </pre>
              </Paper>
            </Collapse>
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose} disabled={isValidating} data-testid="cancel-validation">
          Cancel
        </Button>

        {validationResult && !canProceed && (
          <Button
            onClick={startValidation}
            startIcon={<RefreshIcon />}
            disabled={isValidating}
            data-testid="retry-validation"
          >
            Retry Validation
          </Button>
        )}

        <Button
          onClick={onProceed}
          variant="contained"
          disabled={!canProceed || isValidating}
          startIcon={<PlayArrowIcon />}
          data-testid="proceed-with-scan"
        >
          {canProceed ? 'Start Scan' : 'Resolve Issues First'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PreFlightValidationDialog;
