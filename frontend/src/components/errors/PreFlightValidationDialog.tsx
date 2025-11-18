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

const getStepColor = (status: string) => {
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

  useEffect(() => {
    if (open && validationRequest) {
      startValidation();
    }
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
      Object.entries(result.validation_checks).forEach(([stepId, success]) => {
        // Check for specific errors/warnings for this step
        const stepErrors = result.errors.filter(
          (e) =>
            e.error_code.toLowerCase().includes(stepId.toLowerCase()) ||
            e.category.toLowerCase().includes(stepId.split('_')[0])
        );
        const stepWarnings = result.warnings.filter(
          (w) =>
            w.error_code.toLowerCase().includes(stepId.toLowerCase()) ||
            w.category.toLowerCase().includes(stepId.split('_')[0])
        );

        let status: ValidationStep['status'] = 'success';
        if (stepErrors.length > 0) {
          status = 'error';
        } else if (stepWarnings.length > 0) {
          status = 'warning';
        } else if (!success) {
          status = 'warning';
        }

        updateStepStatus(
          stepId,
          status,
          undefined,
          stepErrors.length > 0
            ? stepErrors[0].message
            : stepWarnings.length > 0
              ? stepWarnings[0].message
              : undefined
        );
      });

      setValidationResult(result);
    } catch (error: any) {
      console.error('Validation failed:', error);

      // Mark current step as failed
      if (currentStep >= 0 && currentStep < validationSteps.length) {
        updateStepStatus(
          validationSteps[currentStep].id,
          'error',
          undefined,
          error.response?.data?.detail || error.message || 'Validation failed'
        );
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
    console.log('Applying fix:', fixId);
    // TODO: Implement fix application
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
                          color={getStepColor(step.status) as any}
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
