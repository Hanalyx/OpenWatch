/**
 * ComplianceScanWizard - Unified 4-step compliance scan creation wizard
 *
 * Consolidates NewScapScan.tsx and ComplianceScans.tsx into a single,
 * intuitive wizard with the best features of both:
 *
 * Step 1: Select Targets
 *   - Choose between individual hosts or host groups
 *   - Multi-select with search and filter
 *   - Status indicators (online/offline)
 *
 * Step 2: Framework & Platform
 *   - Platform/version selection with auto-detection
 *   - Compliance framework selection (NIST, CIS, STIG, etc.)
 *
 * Step 3: Configure Rules (Optional)
 *   - Full scan mode (all rules) or custom rule selection
 *   - Rule table with search and severity filter
 *
 * Step 4: Review & Start
 *   - Configuration summary
 *   - Pre-flight validation with error classification
 *   - Automated fix suggestions
 *
 * @module ComplianceScanWizard
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for implementation details
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Button,
  Paper,
  Typography,
  Stepper,
  Step,
  StepLabel,
  Alert,
  Snackbar,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  ArrowForward as ArrowForwardIcon,
  PlayArrow as PlayArrowIcon,
  NetworkCheck as NetworkCheckIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  useScanWizard,
  type WizardHost,
  type WizardHostGroup,
  type HostScanStatus,
} from './hooks/useScanWizard';
import TargetSelectionStep from './components/TargetSelectionStep';
import FrameworkConfigStep from './components/FrameworkConfigStep';
import RuleConfigStep from './components/RuleConfigStep';
import ReviewStartStep from './components/ReviewStartStep';
import { api } from '../../services/api';
import { ScanService, type ConnectionParams } from '../../services/scanService';
import { SUPPORTED_FRAMEWORKS, type Framework } from '../../constants/complianceFrameworks';
import PreFlightValidationDialog from '../../components/errors/PreFlightValidationDialog';
import ErrorClassificationDisplay, {
  type ClassifiedError,
} from '../../components/errors/ErrorClassificationDisplay';
import { errorService } from '../../services/errorService';

/**
 * Wizard step definitions
 */
const WIZARD_STEPS = [
  'Select Targets',
  'Framework & Platform',
  'Configure Rules',
  'Review & Start',
] as const;

/**
 * Raw host data from API response
 */
interface RawHostData {
  id: string;
  hostname: string;
  display_name?: string;
  operating_system: string;
  status: string;
  // OS detection fields from backend (populated by OS discovery task)
  os_family?: string; // e.g., "rhel", "ubuntu", "debian"
  os_version?: string; // e.g., "9", "22.04", "12"
  platform_identifier?: string; // e.g., "rhel9", "ubuntu2204" - normalized for OVAL selection
  // SSH connection fields for remote scan execution
  ip_address?: string;
  port?: number;
  username?: string;
  auth_method?: string;
}

/**
 * Raw host group data from API response
 */
interface RawHostGroupData {
  id: number;
  name: string;
  description?: string;
  host_count?: number;
}

/**
 * Router location state for preselected host
 */
interface LocationState {
  preselectedHostId?: string;
}

/**
 * Snackbar notification state
 */
interface SnackbarState {
  open: boolean;
  message: string;
  severity: 'success' | 'error' | 'warning' | 'info';
}

/**
 * ComplianceScanWizard Component
 *
 * Main wizard component that orchestrates the 4-step scan creation flow.
 * Uses the useScanWizard hook for state management.
 */
const ComplianceScanWizard: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const locationState = location.state as LocationState | null;

  // Initialize wizard with preselected host from router state
  const [state, actions] = useScanWizard(locationState?.preselectedHostId);

  // Data loaded from API
  const [hosts, setHosts] = useState<WizardHost[]>([]);
  const [hostGroups, setHostGroups] = useState<WizardHostGroup[]>([]);

  // UI state
  const [dataLoading, setDataLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [showPreFlightDialog, setShowPreFlightDialog] = useState(false);
  const [scanError, setScanError] = useState<ClassifiedError | null>(null);
  const [snackbar, setSnackbar] = useState<SnackbarState>({
    open: false,
    message: '',
    severity: 'info',
  });

  // Ref to track cancellation request (survives re-renders during async loop)
  const cancelRequestedRef = useRef(false);
  // Track scan IDs that were started (for cleanup on cancellation)
  const startedScanIdsRef = useRef<string[]>([]);

  /**
   * Display snackbar notification
   */
  const showSnackbar = (
    message: string,
    severity: 'success' | 'error' | 'warning' | 'info' = 'info'
  ) => {
    setSnackbar({ open: true, message, severity });
  };

  /**
   * Fetch hosts from API on mount
   */
  useEffect(() => {
    const fetchData = async () => {
      setDataLoading(true);
      try {
        // Fetch hosts and host groups in parallel
        const [hostsData, groupsData] = await Promise.all([
          api.get('/api/hosts/'),
          api.get('/api/host-groups/').catch(() => []), // Groups may not exist
        ]);

        // Transform hosts to WizardHost format
        // Use os_family/os_version from backend OS discovery for platform auto-detection
        // Include SSH connection fields for remote scan execution
        const formattedHosts: WizardHost[] = hostsData.map((host: RawHostData) => ({
          id: host.id,
          hostname: host.hostname,
          displayName: host.display_name || host.hostname,
          operatingSystem: host.operating_system || 'Unknown',
          status: (host.status as 'online' | 'offline' | 'unknown') || 'unknown',
          // Map backend os_family to frontend platform (e.g., "rhel" -> "rhel")
          platform: host.os_family || undefined,
          // Map backend os_version to frontend platformVersion (e.g., "9" -> "9")
          platformVersion: host.os_version || undefined,
          // SSH connection fields for remote scan execution
          ipAddress: host.ip_address || undefined,
          port: host.port || undefined,
          username: host.username || undefined,
          authMethod: (host.auth_method as 'ssh_key' | 'password') || undefined,
        }));
        setHosts(formattedHosts);

        // Transform host groups to WizardHostGroup format
        const formattedGroups: WizardHostGroup[] = (groupsData || []).map(
          (group: RawHostGroupData) => ({
            id: group.id,
            name: group.name,
            description: group.description,
            hostCount: group.host_count || 0,
          })
        );
        setHostGroups(formattedGroups);
      } catch (error) {
        console.error('Failed to load data:', error);
        showSnackbar('Failed to load hosts', 'error');
      } finally {
        setDataLoading(false);
      }
    };

    fetchData();
  }, []);

  /**
   * Get the selected framework object from ID
   * Note: Prefixed with underscore as it will be used in Phase 3-5
   */
  const _getSelectedFramework = (): Framework | null => {
    return SUPPORTED_FRAMEWORKS.find((f) => f.id === state.framework) || null;
  };

  /**
   * Get selected hosts based on current selection
   */
  const getSelectedHosts = (): WizardHost[] => {
    return hosts.filter((h) => state.selectedHostIds.includes(h.id));
  };

  /**
   * Build validation request for pre-flight checks
   */
  const getValidationRequest = () => {
    const selectedHosts = getSelectedHosts();
    if (selectedHosts.length === 0) return null;

    // For multi-host, validate the first host (Phase 5 will add bulk validation)
    const firstHost = selectedHosts[0];
    return {
      host_id: firstHost.id,
      platform: state.platform,
      platform_version: state.platformVersion,
      framework: state.framework,
    };
  };

  /**
   * Build SSH connection parameters for remote scan execution
   * Returns undefined if host lacks SSH credentials (will fall back to local scan)
   */
  const buildConnectionParams = (host: WizardHost): ConnectionParams | undefined => {
    if (!host.username || !host.port) {
      return undefined;
    }
    return {
      host_id: host.id,
      username: host.username,
      port: host.port,
      auth_method: host.authMethod || 'ssh_key',
    };
  };

  /**
   * Handle pre-flight validation completion and start scan
   */
  const handlePreFlightComplete = async () => {
    try {
      setStarting(true);
      setShowPreFlightDialog(false);
      cancelRequestedRef.current = false;
      startedScanIdsRef.current = [];

      const selectedHosts = getSelectedHosts();

      if (state.targetType === 'hosts' && selectedHosts.length > 0) {
        // Initialize per-host progress tracking
        actions.initializeHostProgress(
          selectedHosts.map((h) => ({ id: h.id, hostname: h.ipAddress || h.hostname }))
        );

        // Scan all selected hosts sequentially
        // Sequential execution ensures scans don't overwhelm target hosts or backend
        let lastScanId: string | null = null;
        let completedCount = 0;
        let failedCount = 0;

        for (const host of selectedHosts) {
          // Check if cancellation was requested
          if (cancelRequestedRef.current) {
            // Mark remaining hosts as cancelled
            actions.updateHostStatus(host.id, 'cancelled' as HostScanStatus);
            continue;
          }

          const connectionParams = buildConnectionParams(host);

          // Use IP address for hostname when available (better for DNS resolution)
          const scanHostname = host.ipAddress || host.hostname;

          // Use per-host platform info when available (from OS discovery)
          // Fall back to wizard-selected platform for hosts without detected platform
          const hostPlatform = host.platform || state.platform;
          const hostPlatformVersion = host.platformVersion || state.platformVersion;

          // Update status to connecting
          actions.updateHostStatus(host.id, 'connecting' as HostScanStatus);

          try {
            // Update status to scanning
            actions.updateHostStatus(host.id, 'scanning' as HostScanStatus);

            const result = await ScanService.startComplianceScan(
              host.id,
              scanHostname,
              hostPlatform,
              hostPlatformVersion,
              state.framework,
              connectionParams,
              state.scanMode === 'custom' ? state.selectedRuleIds : undefined
            );

            lastScanId = result.scan_id;
            startedScanIdsRef.current.push(result.scan_id);

            // Update status to completed
            actions.updateHostStatus(host.id, 'completed' as HostScanStatus, result.scan_id);
            completedCount++;
          } catch (hostError: unknown) {
            console.error(`Scan failed for host ${host.hostname}:`, hostError);
            const errorMsg = hostError instanceof Error ? hostError.message : 'Unknown error';
            actions.updateHostStatus(host.id, 'failed' as HostScanStatus, undefined, errorMsg);
            failedCount++;
          }
        }

        // Show summary based on results
        const cancelledCount = selectedHosts.length - completedCount - failedCount;
        if (cancelRequestedRef.current) {
          showSnackbar(
            `Scan cancelled. ${completedCount} completed, ${cancelledCount} cancelled.`,
            'warning'
          );
        } else if (failedCount > 0 && completedCount > 0) {
          showSnackbar(`${completedCount} scans completed, ${failedCount} failed.`, 'warning');
        } else if (failedCount === selectedHosts.length) {
          showSnackbar('All scans failed. Check host connectivity.', 'error');
        } else {
          const hostCount = selectedHosts.length;
          showSnackbar(
            hostCount === 1
              ? 'Scan started successfully!'
              : `${hostCount} scans started successfully!`,
            'success'
          );
        }

        // Navigate to scan detail page for single host, or scans list for multiple
        // Delay navigation to let user see final status
        setTimeout(() => {
          if (selectedHosts.length === 1 && lastScanId && !cancelRequestedRef.current) {
            navigate(`/scans/${lastScanId}`);
          } else {
            navigate('/scans');
          }
        }, 2000);
      } else if (state.targetType === 'groups' && state.selectedGroupIds.length > 0) {
        // For host groups, use ScanService.startGroupScan
        // Note: This will be enhanced in Phase 5 to handle multiple groups
        const firstGroupId = state.selectedGroupIds[0];
        await ScanService.startGroupScan(firstGroupId, {
          scan_name: state.scanName,
          profile_id: state.framework,
        });

        showSnackbar('Group scan started successfully!', 'success');

        // Navigate to scans list to see the group scan session
        setTimeout(() => {
          navigate(`/scans`);
        }, 1500);
      }
    } catch (error: unknown) {
      console.error('Scan creation failed:', error);

      // Type-safe error classification
      const classification = errorService.getErrorClassification(error);
      if (classification) {
        setScanError(classification);
      } else {
        setScanError(errorService.classifyGenericError(error));
      }
    } finally {
      setStarting(false);
      actions.setCancelling(false);
    }
  };

  /**
   * Handle start scan button click - show pre-flight validation
   */
  const handleStartScan = () => {
    setScanError(null);
    setShowPreFlightDialog(true);
  };

  /**
   * Handle scan cancellation request
   * Sets the cancellation flag and triggers cleanup for started scans
   */
  const handleCancelScan = useCallback(async () => {
    cancelRequestedRef.current = true;
    actions.setCancelling(true);

    // Mark any pending hosts as cancelled immediately
    state.hostScanProgress
      .filter((p) => p.status === 'pending')
      .forEach((p) => {
        actions.updateHostStatus(p.hostId, 'cancelled' as HostScanStatus);
      });

    // Cancel any started scans on the backend
    // This will trigger cleanup of transferred files
    if (startedScanIdsRef.current.length > 0) {
      try {
        await Promise.all(
          startedScanIdsRef.current.map((scanId) =>
            ScanService.cancelScan(scanId).catch((err) => {
              console.warn(`Failed to cancel scan ${scanId}:`, err);
            })
          )
        );
      } catch (error) {
        console.error('Error cancelling scans:', error);
      }
    }

    showSnackbar('Cancelling scan...', 'warning');
  }, [actions, state.hostScanProgress]);

  /**
   * Handle error retry
   */
  const handleErrorRetry = async () => {
    setScanError(null);
    await handlePreFlightComplete();
  };

  /**
   * Handle automated fix application
   */
  const handleApplyFix = async (fixId: string) => {
    const selectedHosts = getSelectedHosts();
    if (selectedHosts.length === 0) return;

    try {
      await errorService.applyAutomatedFix(selectedHosts[0].id, fixId);
      showSnackbar('Fix applied successfully', 'success');
      setScanError(null);
    } catch (error: unknown) {
      showSnackbar(errorService.getUserFriendlyError(error), 'error');
    }
  };

  /**
   * Render step content based on active step
   * Phase 2-4 will implement the actual step components
   */
  const renderStepContent = () => {
    switch (state.activeStep) {
      case 0:
        return (
          <TargetSelectionStep
            targetType={state.targetType}
            selectedHostIds={state.selectedHostIds}
            selectedGroupIds={state.selectedGroupIds}
            hosts={hosts}
            hostGroups={hostGroups}
            isLoading={dataLoading}
            preselectedHostId={locationState?.preselectedHostId}
            onTargetTypeChange={actions.setTargetType}
            onToggleHost={actions.toggleHost}
            onToggleGroup={actions.toggleGroup}
            onSelectAllHosts={actions.selectAllHosts}
            onClearHosts={actions.clearHosts}
            onSelectAllGroups={actions.selectAllGroups}
            onClearGroups={actions.clearGroups}
          />
        );

      case 1:
        return (
          <FrameworkConfigStep
            platform={state.platform}
            platformVersion={state.platformVersion}
            framework={state.framework}
            platformAutoDetected={state.platformAutoDetected}
            selectedHosts={getSelectedHosts()}
            onPlatformChange={actions.setPlatform}
            onPlatformVersionChange={actions.setPlatformVersion}
            onFrameworkChange={actions.setFramework}
            onPlatformAutoDetectedChange={actions.setPlatformAutoDetected}
          />
        );

      case 2:
        return (
          <RuleConfigStep
            scanMode={state.scanMode}
            selectedRuleIds={state.selectedRuleIds}
            platform={state.platform}
            platformVersion={state.platformVersion}
            framework={state.framework}
            onScanModeChange={actions.setScanMode}
            onToggleRule={actions.toggleRule}
            onSelectAllRules={actions.selectAllRules}
            onClearRules={actions.clearRules}
          />
        );

      case 3:
        return (
          <ReviewStartStep
            targetType={state.targetType}
            selectedHosts={getSelectedHosts()}
            selectedGroups={hostGroups.filter((g) => state.selectedGroupIds.includes(g.id))}
            platform={state.platform}
            platformVersion={state.platformVersion}
            framework={state.framework}
            scanMode={state.scanMode}
            selectedRuleCount={state.selectedRuleIds.length}
            scanName={state.scanName}
            isStarting={starting}
            hostScanProgress={state.hostScanProgress}
            isCancelling={state.isCancelling}
            onScanNameChange={actions.setScanName}
            onCancelScan={handleCancelScan}
          />
        );

      default:
        return null;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Create Compliance Scan
      </Typography>

      <Paper sx={{ p: 3, mt: 3 }}>
        {/* Stepper */}
        <Stepper activeStep={state.activeStep} sx={{ mb: 4 }}>
          {WIZARD_STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Step Content */}
        <Box sx={{ minHeight: 400 }}>{renderStepContent()}</Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
          <Button
            onClick={actions.prevStep}
            disabled={state.activeStep === 0}
            startIcon={<ArrowBackIcon />}
          >
            Back
          </Button>

          <Box>
            {state.activeStep === WIZARD_STEPS.length - 1 ? (
              <Button
                variant="contained"
                onClick={handleStartScan}
                disabled={starting}
                startIcon={starting ? <NetworkCheckIcon /> : <PlayArrowIcon />}
                data-testid="start-scan-button"
              >
                {starting ? 'Starting...' : 'Validate & Start Scan'}
              </Button>
            ) : (
              <Button variant="contained" onClick={actions.nextStep} endIcon={<ArrowForwardIcon />}>
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

      {/* Snackbar Notifications */}
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

export default ComplianceScanWizard;
