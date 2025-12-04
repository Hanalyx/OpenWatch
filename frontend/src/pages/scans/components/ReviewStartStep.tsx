/**
 * ReviewStartStep - Step 4 of the ComplianceScanWizard
 *
 * Final step for reviewing scan configuration and initiating the scan:
 * - Configuration summary display
 * - Editable scan name with auto-generation
 * - Pre-flight validation checklist
 * - Start scan button
 *
 * @module ReviewStartStep
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for design specifications
 */

import React, { useEffect, useMemo } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  TextField,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  Divider,
  LinearProgress,
  Button,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Folder as FolderIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  Rule as RuleIcon,
  NetworkCheck as NetworkCheckIcon,
  VpnKey as VpnKeyIcon,
  CheckCircle as CheckCircleIcon,
  Memory as MemoryIcon,
  HourglassEmpty as PendingIcon,
  SyncAlt as ConnectingIcon,
  Scanner as ScanningIcon,
  Error as ErrorIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import type {
  WizardHost,
  WizardHostGroup,
  ScanMode,
  HostScanProgress,
} from '../hooks/useScanWizard';
import { generateScanName } from '../hooks/useScanWizard';
import {
  SUPPORTED_FRAMEWORKS,
  SUPPORTED_PLATFORMS,
  type Framework,
  type Platform,
} from '../../../constants/complianceFrameworks';

/**
 * Props for ReviewStartStep component
 */
interface ReviewStartStepProps {
  /** Type of target selection (hosts or groups) */
  targetType: 'hosts' | 'groups' | null;
  /** Array of selected hosts */
  selectedHosts: WizardHost[];
  /** Array of selected host groups */
  selectedGroups: WizardHostGroup[];
  /** Selected platform ID */
  platform: string;
  /** Selected platform version */
  platformVersion: string;
  /** Selected framework ID */
  framework: string;
  /** Scan mode (full or custom) */
  scanMode: ScanMode;
  /** Number of selected rules (for custom mode) */
  selectedRuleCount: number;
  /** Current scan name */
  scanName: string;
  /** Whether scan is currently starting */
  isStarting: boolean;
  /** Per-host scan progress tracking */
  hostScanProgress: HostScanProgress[];
  /** Whether cancellation is in progress */
  isCancelling: boolean;
  /** Callback when scan name changes */
  onScanNameChange: (name: string) => void;
  /** Callback to cancel the scan */
  onCancelScan?: () => void;
}

/**
 * Pre-flight validation check item
 * Used to display what will be validated before scan starts
 */
interface ValidationCheckItem {
  id: string;
  icon: React.ReactNode;
  label: string;
  description: string;
}

/**
 * List of pre-flight validation checks that will be performed
 */
const VALIDATION_CHECKS: ValidationCheckItem[] = [
  {
    id: 'network',
    icon: <NetworkCheckIcon />,
    label: 'Network Connectivity',
    description: 'Verify target hosts are reachable via network',
  },
  {
    id: 'ssh',
    icon: <VpnKeyIcon />,
    label: 'SSH Authentication',
    description: 'Validate SSH credentials and access permissions',
  },
  {
    id: 'oscap',
    icon: <CheckCircleIcon />,
    label: 'OpenSCAP Installation',
    description: 'Confirm oscap command is available on target hosts',
  },
  {
    id: 'resources',
    icon: <MemoryIcon />,
    label: 'System Resources',
    description: 'Check sufficient disk space and memory for scanning',
  },
];

/**
 * Get platform display name from platform ID
 *
 * @param platformId - Platform identifier (e.g., 'rhel')
 * @returns Platform object or undefined
 */
function getPlatformInfo(platformId: string): Platform | undefined {
  return SUPPORTED_PLATFORMS.find((p) => p.id === platformId);
}

/**
 * Get framework display name from framework ID
 *
 * @param frameworkId - Framework identifier (e.g., 'disa_stig')
 * @returns Framework object or undefined
 */
function getFrameworkInfo(frameworkId: string): Framework | undefined {
  return SUPPORTED_FRAMEWORKS.find((f) => f.id === frameworkId);
}

/**
 * Format target summary text
 *
 * @param targetType - Type of target (hosts or groups)
 * @param hosts - Array of selected hosts
 * @param groups - Array of selected groups
 * @returns Formatted summary string
 */
function formatTargetSummary(
  targetType: 'hosts' | 'groups' | null,
  hosts: WizardHost[],
  groups: WizardHostGroup[]
): string {
  if (targetType === 'hosts') {
    if (hosts.length === 0) return 'No hosts selected';
    if (hosts.length === 1) return hosts[0].displayName;
    if (hosts.length <= 3) {
      return hosts.map((h) => h.displayName).join(', ');
    }
    return `${hosts[0].displayName}, ${hosts[1].displayName}, and ${hosts.length - 2} more`;
  }

  if (targetType === 'groups') {
    if (groups.length === 0) return 'No groups selected';
    const totalHosts = groups.reduce((sum, g) => sum + g.hostCount, 0);
    if (groups.length === 1) {
      return `${groups[0].name} (${totalHosts} hosts)`;
    }
    return `${groups.length} groups (${totalHosts} hosts total)`;
  }

  return 'No targets selected';
}

/**
 * ReviewStartStep Component
 *
 * Fourth and final step of the scan wizard for reviewing configuration
 * and initiating the compliance scan.
 */
/**
 * Get status icon and color for a host scan status
 */
function getStatusDisplay(status: HostScanProgress['status']): {
  icon: React.ReactElement;
  color: 'default' | 'primary' | 'success' | 'error' | 'warning';
  label: string;
} {
  switch (status) {
    case 'pending':
      return { icon: <PendingIcon fontSize="small" />, color: 'default', label: 'Pending' };
    case 'connecting':
      return {
        icon: <ConnectingIcon fontSize="small" />,
        color: 'primary',
        label: 'Connecting...',
      };
    case 'scanning':
      return { icon: <ScanningIcon fontSize="small" />, color: 'primary', label: 'Scanning...' };
    case 'completed':
      return { icon: <CheckCircleIcon fontSize="small" />, color: 'success', label: 'Completed' };
    case 'failed':
      return { icon: <ErrorIcon fontSize="small" />, color: 'error', label: 'Failed' };
    case 'cancelled':
      return { icon: <CancelIcon fontSize="small" />, color: 'warning', label: 'Cancelled' };
    default:
      return { icon: <PendingIcon fontSize="small" />, color: 'default', label: 'Unknown' };
  }
}

const ReviewStartStep: React.FC<ReviewStartStepProps> = ({
  targetType,
  selectedHosts,
  selectedGroups,
  platform,
  platformVersion,
  framework,
  scanMode,
  selectedRuleCount,
  scanName,
  isStarting,
  hostScanProgress,
  isCancelling,
  onScanNameChange,
  onCancelScan,
}) => {
  /**
   * Get platform and framework info objects
   */
  const platformInfo = useMemo(() => getPlatformInfo(platform), [platform]);
  const frameworkInfo = useMemo(() => getFrameworkInfo(framework), [framework]);

  /**
   * Calculate target count for scan name generation
   */
  const targetCount = useMemo(() => {
    if (targetType === 'hosts') return selectedHosts.length;
    if (targetType === 'groups') {
      return selectedGroups.reduce((sum, g) => sum + g.hostCount, 0);
    }
    return 0;
  }, [targetType, selectedHosts, selectedGroups]);

  /**
   * Auto-generate scan name when configuration changes
   * Only if scan name is empty or was previously auto-generated
   */
  useEffect(() => {
    if (!scanName && framework && platform && platformVersion) {
      const generatedName = generateScanName(
        frameworkInfo || null,
        platform,
        platformVersion,
        targetCount
      );
      onScanNameChange(generatedName);
    }
    // Only run when framework/platform/version change, not when scanName changes
    // to avoid overwriting user edits
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [framework, platform, platformVersion, targetCount, frameworkInfo]);

  /**
   * Get rule count display text
   */
  const getRuleCountText = (): string => {
    if (scanMode === 'full') {
      return 'All applicable rules (Full Scan)';
    }
    if (selectedRuleCount === 0) {
      return 'All applicable rules (No custom selection)';
    }
    return `${selectedRuleCount} rules (Custom Scan)`;
  };

  /**
   * Check if configuration is complete for summary display
   */
  const isConfigComplete = Boolean(
    targetType &&
      (selectedHosts.length > 0 || selectedGroups.length > 0) &&
      platform &&
      platformVersion &&
      framework
  );

  return (
    <Box>
      {/* Step Header */}
      <Typography variant="h6" gutterBottom>
        Review & Start Scan
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Review your scan configuration and start the compliance scan.
      </Typography>

      <Grid container spacing={3}>
        {/* Configuration Summary Card */}
        <Grid item xs={12} md={7}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                Scan Configuration Summary
              </Typography>

              {!isConfigComplete ? (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  Configuration is incomplete. Please go back and complete all required steps.
                </Alert>
              ) : (
                <List dense>
                  {/* Targets */}
                  <ListItem>
                    <ListItemIcon>
                      {targetType === 'groups' ? (
                        <FolderIcon color="primary" />
                      ) : (
                        <ComputerIcon color="primary" />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary="Targets"
                      secondary={formatTargetSummary(targetType, selectedHosts, selectedGroups)}
                    />
                    <Chip
                      label={
                        targetType === 'hosts'
                          ? `${selectedHosts.length} host${selectedHosts.length !== 1 ? 's' : ''}`
                          : `${selectedGroups.length} group${selectedGroups.length !== 1 ? 's' : ''}`
                      }
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  </ListItem>

                  <Divider component="li" />

                  {/* Platform */}
                  <ListItem>
                    <ListItemIcon>
                      <StorageIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Platform"
                      secondary={
                        platformInfo
                          ? `${platformInfo.name} ${platformVersion}`
                          : `${platform} ${platformVersion}`
                      }
                    />
                  </ListItem>

                  <Divider component="li" />

                  {/* Framework */}
                  <ListItem>
                    <ListItemIcon>
                      <SecurityIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Compliance Framework"
                      secondary={frameworkInfo?.name || framework}
                    />
                    <Chip
                      label={frameworkInfo?.name || framework.toUpperCase()}
                      size="small"
                      color="secondary"
                      variant="outlined"
                    />
                  </ListItem>

                  <Divider component="li" />

                  {/* Rules */}
                  <ListItem>
                    <ListItemIcon>
                      <RuleIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText primary="Rules" secondary={getRuleCountText()} />
                    <Chip
                      label={scanMode === 'full' ? 'Full' : 'Custom'}
                      size="small"
                      color={scanMode === 'full' ? 'success' : 'info'}
                      variant="outlined"
                    />
                  </ListItem>
                </List>
              )}
            </CardContent>
          </Card>

          {/* Scan Name Input */}
          <Card variant="outlined" sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                Scan Name
              </Typography>
              <TextField
                fullWidth
                value={scanName}
                onChange={(e) => onScanNameChange(e.target.value)}
                placeholder="Enter a name for this scan..."
                helperText="Auto-generated name can be customized"
                disabled={isStarting}
                size="small"
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Pre-flight Validation Info Card */}
        <Grid item xs={12} md={5}>
          <Card variant="outlined" sx={{ bgcolor: 'action.hover' }}>
            <CardContent>
              <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                Pre-flight Validation
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                When you click &quot;Validate &amp; Start Scan&quot;, the following checks will be
                performed:
              </Typography>

              <List dense>
                {VALIDATION_CHECKS.map((check) => (
                  <ListItem key={check.id} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 36 }}>{check.icon}</ListItemIcon>
                    <ListItemText
                      primary={check.label}
                      secondary={check.description}
                      primaryTypographyProps={{ variant: 'body2', fontWeight: 'medium' }}
                      secondaryTypographyProps={{ variant: 'caption' }}
                    />
                  </ListItem>
                ))}
              </List>

              <Alert severity="info" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  If any checks fail, you will see detailed error information with suggestions for
                  resolution.
                </Typography>
              </Alert>
            </CardContent>
          </Card>

          {/* Online/Offline Host Status */}
          {targetType === 'hosts' && selectedHosts.length > 0 && (
            <Card variant="outlined" sx={{ mt: 2 }}>
              <CardContent>
                <Typography variant="subtitle2" fontWeight="medium" gutterBottom>
                  Host Status
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Chip
                    icon={<CheckCircleIcon />}
                    label={`${selectedHosts.filter((h) => h.status === 'online').length} online`}
                    size="small"
                    color="success"
                    variant="outlined"
                  />
                  {selectedHosts.filter((h) => h.status === 'offline').length > 0 && (
                    <Chip
                      label={`${selectedHosts.filter((h) => h.status === 'offline').length} offline`}
                      size="small"
                      color="error"
                      variant="outlined"
                    />
                  )}
                  {selectedHosts.filter((h) => h.status === 'unknown').length > 0 && (
                    <Chip
                      label={`${selectedHosts.filter((h) => h.status === 'unknown').length} unknown`}
                      size="small"
                      color="default"
                      variant="outlined"
                    />
                  )}
                </Box>

                {selectedHosts.some((h) => h.status !== 'online') && (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      Some hosts may not be reachable. Pre-flight validation will verify
                      connectivity.
                    </Typography>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>

      {/* Per-Host Scan Progress */}
      {isStarting && hostScanProgress.length > 0 && (
        <Card variant="outlined" sx={{ mt: 3 }}>
          <CardContent>
            <Box
              sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
            >
              <Typography variant="subtitle1" fontWeight="medium">
                Scan Progress
              </Typography>
              {onCancelScan && !isCancelling && (
                <Button
                  variant="outlined"
                  color="error"
                  size="small"
                  startIcon={<CancelIcon />}
                  onClick={onCancelScan}
                >
                  Cancel Scan
                </Button>
              )}
              {isCancelling && (
                <Chip icon={<CancelIcon />} label="Cancelling..." color="warning" size="small" />
              )}
            </Box>

            {/* Overall progress bar */}
            <Box sx={{ mb: 2 }}>
              <LinearProgress
                variant="determinate"
                value={
                  (hostScanProgress.filter(
                    (h) =>
                      h.status === 'completed' || h.status === 'failed' || h.status === 'cancelled'
                  ).length /
                    hostScanProgress.length) *
                  100
                }
                color={
                  hostScanProgress.some((h) => h.status === 'failed')
                    ? 'error'
                    : hostScanProgress.some((h) => h.status === 'cancelled')
                      ? 'warning'
                      : 'primary'
                }
              />
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ mt: 0.5, display: 'block' }}
              >
                {hostScanProgress.filter((h) => h.status === 'completed').length} of{' '}
                {hostScanProgress.length} hosts completed
                {hostScanProgress.filter((h) => h.status === 'failed').length > 0 &&
                  ` (${hostScanProgress.filter((h) => h.status === 'failed').length} failed)`}
                {hostScanProgress.filter((h) => h.status === 'cancelled').length > 0 &&
                  ` (${hostScanProgress.filter((h) => h.status === 'cancelled').length} cancelled)`}
              </Typography>
            </Box>

            {/* Per-host status list */}
            <List dense sx={{ maxHeight: 300, overflow: 'auto' }}>
              {hostScanProgress.map((progress) => {
                const statusDisplay = getStatusDisplay(progress.status);
                return (
                  <ListItem
                    key={progress.hostId}
                    sx={{
                      bgcolor:
                        progress.status === 'scanning' || progress.status === 'connecting'
                          ? 'action.selected'
                          : 'transparent',
                      borderRadius: 1,
                      mb: 0.5,
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <ComputerIcon fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                      primary={progress.hostname}
                      secondary={progress.errorMessage}
                      primaryTypographyProps={{ variant: 'body2' }}
                      secondaryTypographyProps={{
                        variant: 'caption',
                        color: 'error.main',
                      }}
                    />
                    <Chip
                      icon={statusDisplay.icon}
                      label={statusDisplay.label}
                      size="small"
                      color={statusDisplay.color}
                      variant={
                        progress.status === 'scanning' || progress.status === 'connecting'
                          ? 'filled'
                          : 'outlined'
                      }
                    />
                  </ListItem>
                );
              })}
            </List>
          </CardContent>
        </Card>
      )}

      {/* Simple progress for when no host progress is available */}
      {isStarting && hostScanProgress.length === 0 && (
        <Box sx={{ mt: 3 }}>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: 'center' }}>
            Starting scan...
          </Typography>
        </Box>
      )}

      {/* Ready to Start Message */}
      {isConfigComplete && !isStarting && (
        <Alert severity="success" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>Ready to scan!</strong> Click &quot;Validate &amp; Start Scan&quot; to perform
            pre-flight checks and begin the compliance scan.
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default ReviewStartStep;
