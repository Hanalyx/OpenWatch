import React, { useState } from 'react';
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Typography,
  CircularProgress,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Build as BuildIcon,
  PlayArrow as PlayArrowIcon,
  Refresh as RefreshIcon,
  OpenInNew as OpenInNewIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Extension as ExtensionIcon,
} from '@mui/icons-material';

// Type definitions matching Daniel's error classification system
export interface AutomatedFix {
  fix_id: string;
  description: string;
  requires_sudo: boolean;
  estimated_time: number;
  command?: string;
  is_safe: boolean;
  rollback_command?: string;
}

export interface ClassifiedError {
  error_code: string;
  category:
    | 'network'
    | 'authentication'
    | 'privilege'
    | 'resource'
    | 'dependency'
    | 'content'
    | 'execution'
    | 'configuration';
  severity: 'critical' | 'error' | 'warning' | 'info';
  message: string;
  technical_details?: Record<string, any>;
  user_guidance: string;
  automated_fixes: AutomatedFix[];
  can_retry: boolean;
  retry_after?: number;
  documentation_url?: string;
  timestamp?: string;
}

interface ErrorClassificationDisplayProps {
  error: ClassifiedError;
  onRetry?: () => void;
  onApplyFix?: (fixId: string) => Promise<void>;
  showTechnicalDetails?: boolean;
  compact?: boolean;
  'data-testid'?: string;
}

const getCategoryIcon = (category: string) => {
  switch (category) {
    case 'network':
      return <NetworkIcon />;
    case 'authentication':
      return <SecurityIcon />;
    case 'privilege':
      return <SecurityIcon />;
    case 'resource':
      return <StorageIcon />;
    case 'dependency':
      return <ExtensionIcon />;
    case 'content':
      return <ComputerIcon />;
    default:
      return <ErrorIcon />;
  }
};

const getCategoryColor = (category: string) => {
  switch (category) {
    case 'network':
      return 'info';
    case 'authentication':
      return 'warning';
    case 'privilege':
      return 'warning';
    case 'resource':
      return 'error';
    case 'dependency':
      return 'info';
    case 'content':
      return 'primary';
    default:
      return 'default';
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case 'critical':
    case 'error':
      return <ErrorIcon color="error" />;
    case 'warning':
      return <WarningIcon color="warning" />;
    case 'info':
      return <InfoIcon color="info" />;
    default:
      return <InfoIcon />;
  }
};

const getSeverityColor = (severity: string): 'error' | 'warning' | 'info' | 'success' => {
  switch (severity) {
    case 'critical':
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'info';
    default:
      return 'info';
  }
};

const formatErrorCode = (errorCode: string, category: string): string => {
  const categoryMap = {
    network: 'Network',
    authentication: 'Authentication',
    privilege: 'Privileges',
    resource: 'Resources',
    dependency: 'Dependencies',
    content: 'Content',
    execution: 'Execution',
    configuration: 'Configuration',
  };
  return `${categoryMap[category as keyof typeof categoryMap] || 'System'} Error ${errorCode}`;
};

export const ErrorClassificationDisplay: React.FC<ErrorClassificationDisplayProps> = ({
  error,
  onRetry,
  onApplyFix,
  showTechnicalDetails = false,
  compact = false,
  'data-testid': testId = 'error-classification',
}) => {
  const [showDetails, setShowDetails] = useState(false);
  const [showFixDialog, setShowFixDialog] = useState(false);
  const [selectedFix, setSelectedFix] = useState<AutomatedFix | null>(null);
  const [applyingFix, setApplyingFix] = useState(false);

  const handleApplyFix = async (fix: AutomatedFix) => {
    if (!onApplyFix) return;

    setApplyingFix(true);
    try {
      await onApplyFix(fix.fix_id);
      setShowFixDialog(false);
      setSelectedFix(null);
    } finally {
      setApplyingFix(false);
    }
  };

  const handleShowFix = (fix: AutomatedFix) => {
    setSelectedFix(fix);
    setShowFixDialog(true);
  };

  if (compact) {
    return (
      <Alert
        severity={getSeverityColor(error.severity)}
        icon={getSeverityIcon(error.severity)}
        data-testid={testId}
        sx={{ mb: 1 }}
      >
        <AlertTitle>{formatErrorCode(error.error_code, error.category)}</AlertTitle>
        {error.message}
        {error.automated_fixes.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Button
              size="small"
              startIcon={<BuildIcon />}
              onClick={() => handleShowFix(error.automated_fixes[0])}
              data-testid="quick-fix-button"
            >
              Quick Fix Available
            </Button>
          </Box>
        )}
      </Alert>
    );
  }

  return (
    <Box data-testid={testId}>
      <Card sx={{ mb: 2 }}>
        <CardContent>
          {/* Error Header */}
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            {getSeverityIcon(error.severity)}
            <Box flex={1}>
              <Typography variant="h6" component="h3">
                {formatErrorCode(error.error_code, error.category)}
              </Typography>
              <Box display="flex" gap={1} mt={0.5}>
                <Chip
                  icon={getCategoryIcon(error.category)}
                  label={error.category.charAt(0).toUpperCase() + error.category.slice(1)}
                  color={getCategoryColor(error.category) as any}
                  size="small"
                />
                <Chip
                  label={error.severity.toUpperCase()}
                  color={getSeverityColor(error.severity)}
                  size="small"
                  variant="outlined"
                />
              </Box>
            </Box>
          </Box>

          {/* Error Message */}
          <Alert severity={getSeverityColor(error.severity)} sx={{ mb: 2 }}>
            <Typography variant="body1" sx={{ fontWeight: 'medium' }}>
              {error.message}
            </Typography>
            {error.user_guidance && (
              <Typography variant="body2" sx={{ mt: 1, opacity: 0.9 }}>
                {error.user_guidance}
              </Typography>
            )}
          </Alert>

          {/* Automated Fixes */}
          {error.automated_fixes.length > 0 && (
            <Box mb={2}>
              <Typography
                variant="subtitle2"
                gutterBottom
                sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
              >
                <BuildIcon fontSize="small" />
                Automated Fixes Available
              </Typography>
              <Box display="flex" gap={1} flexWrap="wrap">
                {error.automated_fixes.map((fix, index) => (
                  <Button
                    key={fix.fix_id}
                    variant={index === 0 ? 'contained' : 'outlined'}
                    size="small"
                    startIcon={<BuildIcon />}
                    onClick={() => handleShowFix(fix)}
                    data-testid={`fix-button-${fix.fix_id}`}
                  >
                    {fix.description}
                    {fix.requires_sudo && (
                      <Chip label="Requires Sudo" size="small" sx={{ ml: 1 }} />
                    )}
                  </Button>
                ))}
              </Box>
            </Box>
          )}

          {/* Action Buttons */}
          <Box display="flex" gap={2} alignItems="center">
            {error.can_retry && onRetry && (
              <Button
                variant="contained"
                startIcon={<RefreshIcon />}
                onClick={onRetry}
                data-testid="retry-button"
              >
                {error.retry_after ? `Retry (wait ${error.retry_after}s)` : 'Retry'}
              </Button>
            )}

            {error.documentation_url && (
              <Button
                variant="outlined"
                startIcon={<OpenInNewIcon />}
                onClick={() => window.open(error.documentation_url, '_blank')}
                data-testid="documentation-button"
              >
                View Documentation
              </Button>
            )}

            {(showTechnicalDetails || error.technical_details) && (
              <Button
                variant="text"
                startIcon={showDetails ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                onClick={() => setShowDetails(!showDetails)}
                data-testid="technical-details-toggle"
              >
                Technical Details
              </Button>
            )}
          </Box>

          {/* Technical Details */}
          <Collapse in={showDetails}>
            <Box mt={2}>
              <Divider sx={{ mb: 2 }} />
              <Typography variant="subtitle2" gutterBottom>
                Technical Details
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
                <Typography variant="caption" display="block" gutterBottom>
                  Error Code: {error.error_code}
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  Category: {error.category}
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  Timestamp:{' '}
                  {error.timestamp ? new Date(error.timestamp).toLocaleString() : 'Not available'}
                </Typography>
                {error.technical_details && (
                  <Box mt={1}>
                    <Typography variant="caption" display="block" gutterBottom>
                      Additional Details:
                    </Typography>
                    <pre
                      style={{
                        fontSize: '0.75rem',
                        overflow: 'auto',
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                      }}
                    >
                      {JSON.stringify(error.technical_details, null, 2)}
                    </pre>
                  </Box>
                )}
              </Paper>
            </Box>
          </Collapse>
        </CardContent>
      </Card>

      {/* Fix Application Dialog */}
      <Dialog
        open={showFixDialog}
        onClose={() => setShowFixDialog(false)}
        maxWidth="md"
        fullWidth
        data-testid="fix-dialog"
      >
        <DialogTitle>
          <Box display="flex" alignItems="center" gap={2}>
            <BuildIcon />
            Apply Automated Fix
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedFix && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedFix.description}
              </Typography>

              <Box display="flex" gap={1} mb={2}>
                <Chip label={`~${selectedFix.estimated_time}s`} size="small" variant="outlined" />
                {selectedFix.requires_sudo && (
                  <Chip label="Requires Sudo" color="warning" size="small" />
                )}
                <Chip
                  label={selectedFix.is_safe ? 'Safe' : 'Use Caution'}
                  color={selectedFix.is_safe ? 'success' : 'error'}
                  size="small"
                />
              </Box>

              {selectedFix.command && (
                <Box mb={2}>
                  <Typography variant="subtitle2" gutterBottom>
                    Command to Execute:
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.100' }}>
                    <Typography variant="body2" component="code" sx={{ fontFamily: 'monospace' }}>
                      {selectedFix.command}
                    </Typography>
                  </Paper>
                </Box>
              )}

              {selectedFix.rollback_command && (
                <Box mb={2}>
                  <Typography variant="subtitle2" gutterBottom>
                    Rollback Available:
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
                    <Typography variant="body2" component="code" sx={{ fontFamily: 'monospace' }}>
                      {selectedFix.rollback_command}
                    </Typography>
                  </Paper>
                </Box>
              )}

              {!selectedFix.is_safe && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  <AlertTitle>Use Caution</AlertTitle>
                  This fix makes system changes that could affect other services. Ensure you have
                  appropriate backups and permissions before proceeding.
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowFixDialog(false)} disabled={applyingFix}>
            Cancel
          </Button>
          <Button
            onClick={() => selectedFix && handleApplyFix(selectedFix)}
            variant="contained"
            disabled={applyingFix}
            startIcon={applyingFix ? <CircularProgress size={16} /> : <PlayArrowIcon />}
            data-testid="apply-fix-confirm"
          >
            {applyingFix ? 'Applying...' : 'Apply Fix'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ErrorClassificationDisplay;
