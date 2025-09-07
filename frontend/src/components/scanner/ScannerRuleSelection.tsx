import React, { useState, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Checkbox,
  IconButton,
  Chip,
  Stack,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  LinearProgress,
  Divider,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Close as CloseIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Computer as ComputerIcon,
  Schedule as ScheduleIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import { Rule } from '../../store/slices/ruleSlice';

interface ScannerRuleSelectionProps {
  open: boolean;
  onClose: () => void;
  selectedRules: Rule[];
  onRuleToggle: (rule: Rule) => void;
  onStartScan: (config: ScanConfiguration) => Promise<void>;
}

interface ScanConfiguration {
  targetHosts: string[];
  scanProfile: 'quick' | 'standard' | 'comprehensive';
  outputFormats: string[];
  scanName: string;
  description?: string;
  schedule?: {
    type: 'immediate' | 'scheduled';
    datetime?: string;
    recurring?: boolean;
  };
}

interface ScanProgress {
  scanId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  currentRule?: string;
  completedRules: number;
  totalRules: number;
  startTime: string;
  estimatedEndTime?: string;
  errors: string[];
}

const ScannerRuleSelection: React.FC<ScannerRuleSelectionProps> = ({
  open,
  onClose,
  selectedRules,
  onRuleToggle,
  onStartScan,
}) => {
  const theme = useTheme();
  const [activeStep, setActiveStep] = useState(0);
  const [scanConfig, setScanConfig] = useState<ScanConfiguration>({
    targetHosts: ['localhost'],
    scanProfile: 'standard',
    outputFormats: ['html', 'xml'],
    scanName: `Scan - ${new Date().toISOString().split('T')[0]}`,
    description: '',
    schedule: {
      type: 'immediate',
    },
  });
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);

  // Handle scan configuration changes
  const updateScanConfig = useCallback((updates: Partial<ScanConfiguration>) => {
    setScanConfig(prev => ({ ...prev, ...updates }));
  }, []);

  // Handle host input changes
  const handleHostsChange = useCallback((hostsString: string) => {
    const hosts = hostsString.split(',').map(h => h.trim()).filter(h => h);
    updateScanConfig({ targetHosts: hosts });
  }, [updateScanConfig]);

  // Start scan process
  const handleStartScan = useCallback(async () => {
    if (selectedRules.length === 0) {
      return;
    }

    setIsScanning(true);
    
    // Initialize scan progress
    const newScanProgress: ScanProgress = {
      scanId: `scan-${Date.now()}`,
      status: 'pending',
      progress: 0,
      completedRules: 0,
      totalRules: selectedRules.length,
      startTime: new Date().toISOString(),
      errors: [],
    };
    setScanProgress(newScanProgress);

    try {
      // Start the scan
      await onStartScan(scanConfig);
      
      // Simulate scan progress (in real implementation, this would be WebSocket or polling)
      simulateScanProgress();
      
    } catch (error) {
      setScanProgress(prev => prev ? {
        ...prev,
        status: 'failed',
        errors: [...prev.errors, error instanceof Error ? error.message : 'Scan failed']
      } : null);
    }
  }, [selectedRules, scanConfig, onStartScan]);

  // Simulate scan progress for demo
  const simulateScanProgress = useCallback(() => {
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15 + 5; // Progress by 5-20% each step
      
      if (progress >= 100) {
        progress = 100;
        setScanProgress(prev => prev ? {
          ...prev,
          status: 'completed',
          progress: 100,
          completedRules: prev.totalRules,
          estimatedEndTime: new Date().toISOString(),
        } : null);
        setIsScanning(false);
        clearInterval(interval);
      } else {
        setScanProgress(prev => prev ? {
          ...prev,
          status: 'running',
          progress,
          completedRules: Math.floor((progress / 100) * prev.totalRules),
          currentRule: selectedRules[Math.floor((progress / 100) * selectedRules.length)]?.metadata.name,
          estimatedEndTime: new Date(Date.now() + (100 - progress) * 1000).toISOString(),
        } : null);
      }
    }, 1500);
  }, [selectedRules]);

  // Get severity statistics
  const getSeverityStats = () => {
    const stats = { high: 0, medium: 0, low: 0, info: 0 };
    selectedRules.forEach(rule => {
      if (rule.severity in stats) {
        stats[rule.severity as keyof typeof stats]++;
      }
    });
    return stats;
  };

  // Render rule selection step
  const renderRuleSelection = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Selected Rules ({selectedRules.length})
      </Typography>
      
      {selectedRules.length === 0 ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          No rules selected. Please go back to the Rules Explorer and select rules to scan.
        </Alert>
      ) : (
        <Box>
          {/* Severity Statistics */}
          <Paper sx={{ p: 2, mb: 2, backgroundColor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom>
              Severity Distribution
            </Typography>
            <Stack direction="row" spacing={1}>
              {Object.entries(getSeverityStats()).map(([severity, count]) => (
                count > 0 && (
                  <Chip
                    key={severity}
                    label={`${severity.toUpperCase()}: ${count}`}
                    size="small"
                    color={
                      severity === 'high' ? 'error' :
                      severity === 'medium' ? 'warning' :
                      severity === 'low' ? 'info' : 'default'
                    }
                  />
                )
              ))}
            </Stack>
          </Paper>

          {/* Rule List */}
          <List sx={{ maxHeight: 300, overflow: 'auto' }}>
            {selectedRules.map(rule => (
              <ListItem
                key={rule.rule_id}
                secondaryAction={
                  <IconButton
                    edge="end"
                    onClick={() => onRuleToggle(rule)}
                    size="small"
                  >
                    <CloseIcon />
                  </IconButton>
                }
              >
                <ListItemIcon>
                  <Checkbox
                    checked={true}
                    onChange={() => onRuleToggle(rule)}
                    color="primary"
                  />
                </ListItemIcon>
                <ListItemText
                  primary={rule.metadata.name}
                  secondary={
                    <Box display="flex" alignItems="center" gap={1} mt={0.5}>
                      <Chip
                        label={rule.severity}
                        size="small"
                        color={
                          rule.severity === 'high' ? 'error' :
                          rule.severity === 'medium' ? 'warning' :
                          rule.severity === 'low' ? 'info' : 'default'
                        }
                      />
                      <Chip label={rule.category} size="small" variant="outlined" />
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      )}
    </Box>
  );

  // Render scan configuration step
  const renderScanConfiguration = () => (
    <Stack spacing={3}>
      <Typography variant="h6" gutterBottom>
        Scan Configuration
      </Typography>

      {/* Basic Configuration */}
      <Paper sx={{ p: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          Basic Settings
        </Typography>
        <Stack spacing={2}>
          <TextField
            label="Scan Name"
            value={scanConfig.scanName}
            onChange={(e) => updateScanConfig({ scanName: e.target.value })}
            fullWidth
          />
          
          <TextField
            label="Description (Optional)"
            value={scanConfig.description}
            onChange={(e) => updateScanConfig({ description: e.target.value })}
            multiline
            rows={2}
            fullWidth
          />
          
          <TextField
            label="Target Hosts (comma-separated)"
            value={scanConfig.targetHosts.join(', ')}
            onChange={(e) => handleHostsChange(e.target.value)}
            placeholder="localhost, server1.example.com, 192.168.1.100"
            fullWidth
          />
        </Stack>
      </Paper>

      {/* Scan Profile */}
      <Paper sx={{ p: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          Scan Profile
        </Typography>
        <FormControl fullWidth>
          <Select
            value={scanConfig.scanProfile}
            onChange={(e) => updateScanConfig({ scanProfile: e.target.value as any })}
          >
            <MenuItem value="quick">
              <Box>
                <Typography variant="body2" fontWeight="medium">Quick Scan</Typography>
                <Typography variant="caption" color="text.secondary">
                  Basic security checks, faster execution
                </Typography>
              </Box>
            </MenuItem>
            <MenuItem value="standard">
              <Box>
                <Typography variant="body2" fontWeight="medium">Standard Scan</Typography>
                <Typography variant="caption" color="text.secondary">
                  Comprehensive security assessment, balanced speed and coverage
                </Typography>
              </Box>
            </MenuItem>
            <MenuItem value="comprehensive">
              <Box>
                <Typography variant="body2" fontWeight="medium">Comprehensive Scan</Typography>
                <Typography variant="caption" color="text.secondary">
                  In-depth analysis, longer execution time
                </Typography>
              </Box>
            </MenuItem>
          </Select>
        </FormControl>
      </Paper>

      {/* Output Formats */}
      <Paper sx={{ p: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          Output Formats
        </Typography>
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          {['html', 'xml', 'json', 'pdf'].map(format => (
            <Chip
              key={format}
              label={format.toUpperCase()}
              variant={scanConfig.outputFormats.includes(format) ? 'filled' : 'outlined'}
              onClick={() => {
                const formats = scanConfig.outputFormats.includes(format)
                  ? scanConfig.outputFormats.filter(f => f !== format)
                  : [...scanConfig.outputFormats, format];
                updateScanConfig({ outputFormats: formats });
              }}
              color="primary"
            />
          ))}
        </Stack>
      </Paper>
    </Stack>
  );

  // Render scan execution step
  const renderScanExecution = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan Execution
      </Typography>

      {!scanProgress ? (
        <Box textAlign="center" py={4}>
          <ComputerIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="body1" gutterBottom>
            Ready to start scanning {selectedRules.length} rules on {scanConfig.targetHosts.length} host(s)
          </Typography>
          <Button
            variant="contained"
            size="large"
            startIcon={<PlayIcon />}
            onClick={handleStartScan}
            disabled={selectedRules.length === 0}
          >
            Start Scan
          </Button>
        </Box>
      ) : (
        <Stack spacing={3}>
          {/* Progress Overview */}
          <Paper sx={{ p: 2 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="subtitle2">
                Scan Progress - {scanProgress.scanId}
              </Typography>
              <Chip
                label={scanProgress.status}
                color={
                  scanProgress.status === 'completed' ? 'success' :
                  scanProgress.status === 'failed' ? 'error' :
                  scanProgress.status === 'running' ? 'primary' : 'default'
                }
              />
            </Box>
            
            <LinearProgress
              variant="determinate"
              value={scanProgress.progress}
              sx={{ mb: 2, height: 8, borderRadius: 4 }}
              color={
                scanProgress.status === 'completed' ? 'success' :
                scanProgress.status === 'failed' ? 'error' : 'primary'
              }
            />
            
            <Box display="flex" justifyContent="space-between" alignItems="center">
              <Typography variant="body2" color="text.secondary">
                {scanProgress.completedRules} / {scanProgress.totalRules} rules completed
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {scanProgress.progress.toFixed(1)}%
              </Typography>
            </Box>
          </Paper>

          {/* Current Status */}
          {scanProgress.status === 'running' && scanProgress.currentRule && (
            <Alert severity="info" icon={<RefreshIcon />}>
              Currently scanning: {scanProgress.currentRule}
            </Alert>
          )}

          {/* Completion Status */}
          {scanProgress.status === 'completed' && (
            <Alert severity="success" icon={<CheckIcon />}>
              Scan completed successfully! Results are available in the specified output formats.
            </Alert>
          )}

          {/* Error Status */}
          {scanProgress.status === 'failed' && (
            <Alert severity="error" icon={<ErrorIcon />}>
              Scan failed. Check the logs for more details.
            </Alert>
          )}

          {/* Timing Information */}
          <Paper sx={{ p: 2, backgroundColor: alpha(theme.palette.info.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom>
              Timing Information
            </Typography>
            <Stack spacing={1}>
              <Typography variant="body2">
                Started: {new Date(scanProgress.startTime).toLocaleString()}
              </Typography>
              {scanProgress.estimatedEndTime && (
                <Typography variant="body2">
                  {scanProgress.status === 'completed' ? 'Completed' : 'Estimated completion'}: {' '}
                  {new Date(scanProgress.estimatedEndTime).toLocaleString()}
                </Typography>
              )}
            </Stack>
          </Paper>
        </Stack>
      )}
    </Box>
  );

  const steps = [
    {
      label: 'Rule Selection',
      content: renderRuleSelection(),
      completed: selectedRules.length > 0,
    },
    {
      label: 'Configuration',
      content: renderScanConfiguration(),
      completed: scanConfig.scanName && scanConfig.targetHosts.length > 0,
    },
    {
      label: 'Execution',
      content: renderScanExecution(),
      completed: scanProgress?.status === 'completed',
    },
  ];

  const handleNext = () => {
    setActiveStep(prev => Math.min(prev + 1, steps.length - 1));
  };

  const handleBack = () => {
    setActiveStep(prev => Math.max(prev - 1, 0));
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          minHeight: '70vh',
          maxHeight: '90vh',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={1}>
            <AssessmentIcon color="primary" />
            <Typography variant="h6">
              Scanner - Rule Selection & Configuration
            </Typography>
          </Box>
          <IconButton onClick={onClose} disabled={isScanning}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <Divider />

      <DialogContent sx={{ p: 0 }}>
        <Stepper activeStep={activeStep} orientation="vertical">
          {steps.map((step, index) => (
            <Step key={step.label} completed={step.completed || false}>
              <StepLabel>{step.label}</StepLabel>
              <StepContent>
                <Box sx={{ p: 2 }}>
                  {step.content}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </DialogContent>

      <DialogActions sx={{ p: 2, justifyContent: 'space-between' }}>
        <Box>
          {activeStep > 0 && (
            <Button onClick={handleBack} disabled={isScanning}>
              Back
            </Button>
          )}
        </Box>
        
        <Box display="flex" gap={1}>
          <Button onClick={onClose} disabled={isScanning}>
            {scanProgress?.status === 'completed' ? 'Close' : 'Cancel'}
          </Button>
          
          {activeStep < steps.length - 1 && (
            <Button
              variant="contained"
              onClick={handleNext}
              disabled={!steps[activeStep].completed || isScanning}
            >
              Next
            </Button>
          )}
        </Box>
      </DialogActions>
    </Dialog>
  );
};

export default ScannerRuleSelection;