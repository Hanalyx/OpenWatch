/**
 * useScanWizard - Comprehensive state management hook for the ComplianceScanWizard
 *
 * Provides centralized state management for the 4-step scan creation wizard:
 * 1. Target Selection (hosts or groups)
 * 2. Framework & Platform Configuration
 * 3. Rule Configuration (optional)
 * 4. Review & Start
 *
 * Features:
 * - Step navigation with validation
 * - Multi-host and host group selection
 * - Platform auto-detection from host OS
 * - Full and custom rule scan modes
 * - Auto-generated scan names
 *
 * @module useScanWizard
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for implementation details
 */

import { useState, useCallback, useMemo } from 'react';
import type { Framework } from '../../../constants/complianceFrameworks';

/**
 * Represents a host that can be selected for scanning
 * Includes SSH connection fields required for remote scan execution
 */
export interface WizardHost {
  id: string;
  hostname: string;
  displayName: string;
  operatingSystem: string;
  status: 'online' | 'offline' | 'unknown';
  platform?: string;
  platformVersion?: string;
  /** IP address for SSH connection (preferred over hostname for DNS resolution) */
  ipAddress?: string;
  /** SSH port for remote connection */
  port?: number;
  /** SSH username for authentication */
  username?: string;
  /** SSH authentication method */
  authMethod?: 'ssh_key' | 'password';
}

/**
 * Represents a host group that can be selected for bulk scanning
 */
export interface WizardHostGroup {
  id: number;
  name: string;
  description?: string;
  hostCount: number;
}

/**
 * Compliance rule available for selection in custom scan mode
 */
export interface WizardRule {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category?: string;
  description?: string;
}

/**
 * Type of target selection: individual hosts or host groups
 */
export type TargetType = 'hosts' | 'groups' | null;

/**
 * Scan mode: full (all rules) or custom (selected rules)
 */
export type ScanMode = 'full' | 'custom';

/**
 * Wizard step identifiers
 */
export type WizardStep = 0 | 1 | 2 | 3;

/**
 * Status of a single host's scan operation
 */
export type HostScanStatus =
  | 'pending'
  | 'connecting'
  | 'scanning'
  | 'completed'
  | 'failed'
  | 'cancelled';

/**
 * Tracking info for a host's scan progress
 */
export interface HostScanProgress {
  hostId: string;
  hostname: string;
  status: HostScanStatus;
  scanId?: string;
  errorMessage?: string;
  startedAt?: Date;
  completedAt?: Date;
}

/**
 * Complete wizard state
 */
export interface WizardState {
  /** Current active step (0-3) */
  activeStep: WizardStep;

  /** Step 1: Target Selection */
  targetType: TargetType;
  selectedHostIds: string[];
  selectedGroupIds: number[];

  /** Step 2: Framework & Platform */
  platform: string;
  platformVersion: string;
  framework: string;
  platformAutoDetected: boolean;

  /** Step 3: Rule Configuration */
  scanMode: ScanMode;
  selectedRuleIds: string[];

  /** Step 4: Review & Start */
  scanName: string;

  /** Scan Progress Tracking */
  hostScanProgress: HostScanProgress[];
  isCancelling: boolean;

  /** UI State */
  isLoading: boolean;
  error: string | null;
}

/**
 * Actions available for wizard state management
 */
export interface WizardActions {
  /** Step navigation */
  setActiveStep: (step: WizardStep) => void;
  nextStep: () => void;
  prevStep: () => void;

  /** Step 1: Target selection */
  setTargetType: (type: TargetType) => void;
  toggleHost: (hostId: string) => void;
  toggleGroup: (groupId: number) => void;
  selectAllHosts: (hostIds: string[]) => void;
  clearHosts: () => void;
  selectAllGroups: (groupIds: number[]) => void;
  clearGroups: () => void;

  /** Step 2: Framework & Platform */
  setPlatform: (platform: string) => void;
  setPlatformVersion: (version: string) => void;
  setFramework: (framework: string) => void;
  setPlatformAutoDetected: (detected: boolean) => void;

  /** Step 3: Rule Configuration */
  setScanMode: (mode: ScanMode) => void;
  toggleRule: (ruleId: string) => void;
  selectAllRules: (ruleIds: string[]) => void;
  clearRules: () => void;

  /** Step 4: Review */
  setScanName: (name: string) => void;

  /** Scan Progress Tracking */
  initializeHostProgress: (hosts: Array<{ id: string; hostname: string }>) => void;
  updateHostStatus: (
    hostId: string,
    status: HostScanStatus,
    scanId?: string,
    errorMessage?: string
  ) => void;
  setCancelling: (cancelling: boolean) => void;
  clearHostProgress: () => void;

  /** UI State */
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;

  /** Validation */
  canProceedToNextStep: () => boolean;

  /** Reset */
  reset: () => void;
}

/**
 * Initial state for the wizard
 */
const initialState: WizardState = {
  activeStep: 0,
  targetType: null,
  selectedHostIds: [],
  selectedGroupIds: [],
  platform: '',
  platformVersion: '',
  framework: '',
  platformAutoDetected: false,
  scanMode: 'full',
  selectedRuleIds: [],
  scanName: '',
  hostScanProgress: [],
  isCancelling: false,
  isLoading: false,
  error: null,
};

/**
 * Generate default scan name based on configuration
 *
 * @param framework - Selected framework object
 * @param platform - Platform identifier
 * @param platformVersion - Platform version
 * @param targetCount - Number of hosts or groups selected
 * @returns Generated scan name with timestamp
 */
export function generateScanName(
  framework: Framework | null,
  platform: string,
  platformVersion: string,
  targetCount: number
): string {
  const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const frameworkName = framework?.name || 'Compliance';
  const platformLabel = platform
    ? `${platform.toUpperCase()} ${platformVersion}`
    : 'Multi-Platform';
  const targetLabel = targetCount === 1 ? '1 host' : `${targetCount} hosts`;

  return `${frameworkName} - ${platformLabel} - ${targetLabel} - ${timestamp}`;
}

/**
 * Custom hook for managing ComplianceScanWizard state
 *
 * Provides comprehensive state management and actions for the 4-step
 * scan creation wizard. Supports preselected host from router state.
 *
 * @param preselectedHostId - Optional host ID to pre-select (from router state)
 * @returns Tuple of [state, actions] for wizard management
 *
 * @example
 * ```tsx
 * const [state, actions] = useScanWizard(preselectedHostId);
 *
 * // Navigate steps
 * actions.nextStep();
 * actions.prevStep();
 *
 * // Select hosts
 * actions.setTargetType('hosts');
 * actions.toggleHost('host-uuid-123');
 *
 * // Configure scan
 * actions.setFramework('disa_stig');
 * actions.setScanMode('full');
 *
 * // Check if can proceed
 * if (actions.canProceedToNextStep()) {
 *   actions.nextStep();
 * }
 * ```
 */
export function useScanWizard(preselectedHostId?: string): [WizardState, WizardActions] {
  // Initialize state with preselected host if provided
  const [state, setState] = useState<WizardState>(() => ({
    ...initialState,
    selectedHostIds: preselectedHostId ? [preselectedHostId] : [],
    targetType: preselectedHostId ? 'hosts' : null,
  }));

  // Step navigation actions
  const setActiveStep = useCallback((step: WizardStep) => {
    setState((prev) => ({ ...prev, activeStep: step }));
  }, []);

  const nextStep = useCallback(() => {
    setState((prev) => ({
      ...prev,
      activeStep: Math.min(3, prev.activeStep + 1) as WizardStep,
    }));
  }, []);

  const prevStep = useCallback(() => {
    setState((prev) => ({
      ...prev,
      activeStep: Math.max(0, prev.activeStep - 1) as WizardStep,
    }));
  }, []);

  // Step 1: Target selection actions
  const setTargetType = useCallback((type: TargetType) => {
    setState((prev) => ({
      ...prev,
      targetType: type,
      // Clear selections when switching target type
      selectedHostIds: type === 'hosts' ? prev.selectedHostIds : [],
      selectedGroupIds: type === 'groups' ? prev.selectedGroupIds : [],
    }));
  }, []);

  const toggleHost = useCallback((hostId: string) => {
    setState((prev) => {
      const isSelected = prev.selectedHostIds.includes(hostId);
      return {
        ...prev,
        selectedHostIds: isSelected
          ? prev.selectedHostIds.filter((id) => id !== hostId)
          : [...prev.selectedHostIds, hostId],
      };
    });
  }, []);

  const toggleGroup = useCallback((groupId: number) => {
    setState((prev) => {
      const isSelected = prev.selectedGroupIds.includes(groupId);
      return {
        ...prev,
        selectedGroupIds: isSelected
          ? prev.selectedGroupIds.filter((id) => id !== groupId)
          : [...prev.selectedGroupIds, groupId],
      };
    });
  }, []);

  const selectAllHosts = useCallback((hostIds: string[]) => {
    setState((prev) => ({ ...prev, selectedHostIds: hostIds }));
  }, []);

  const clearHosts = useCallback(() => {
    setState((prev) => ({ ...prev, selectedHostIds: [] }));
  }, []);

  const selectAllGroups = useCallback((groupIds: number[]) => {
    setState((prev) => ({ ...prev, selectedGroupIds: groupIds }));
  }, []);

  const clearGroups = useCallback(() => {
    setState((prev) => ({ ...prev, selectedGroupIds: [] }));
  }, []);

  // Step 2: Framework & Platform actions
  const setPlatform = useCallback((platform: string) => {
    setState((prev) => ({
      ...prev,
      platform,
      // Reset version when platform changes
      platformVersion: '',
      platformAutoDetected: false,
    }));
  }, []);

  const setPlatformVersion = useCallback((version: string) => {
    setState((prev) => ({ ...prev, platformVersion: version }));
  }, []);

  const setFramework = useCallback((framework: string) => {
    setState((prev) => ({ ...prev, framework }));
  }, []);

  const setPlatformAutoDetected = useCallback((detected: boolean) => {
    setState((prev) => ({ ...prev, platformAutoDetected: detected }));
  }, []);

  // Step 3: Rule configuration actions
  const setScanMode = useCallback((mode: ScanMode) => {
    setState((prev) => ({
      ...prev,
      scanMode: mode,
      // Clear rule selection when switching to full mode
      selectedRuleIds: mode === 'full' ? [] : prev.selectedRuleIds,
    }));
  }, []);

  const toggleRule = useCallback((ruleId: string) => {
    setState((prev) => {
      const isSelected = prev.selectedRuleIds.includes(ruleId);
      return {
        ...prev,
        selectedRuleIds: isSelected
          ? prev.selectedRuleIds.filter((id) => id !== ruleId)
          : [...prev.selectedRuleIds, ruleId],
      };
    });
  }, []);

  const selectAllRules = useCallback((ruleIds: string[]) => {
    setState((prev) => ({ ...prev, selectedRuleIds: ruleIds }));
  }, []);

  const clearRules = useCallback(() => {
    setState((prev) => ({ ...prev, selectedRuleIds: [] }));
  }, []);

  // Step 4: Review actions
  const setScanName = useCallback((name: string) => {
    setState((prev) => ({ ...prev, scanName: name }));
  }, []);

  // Scan Progress Tracking actions
  const initializeHostProgress = useCallback((hosts: Array<{ id: string; hostname: string }>) => {
    setState((prev) => ({
      ...prev,
      hostScanProgress: hosts.map((host) => ({
        hostId: host.id,
        hostname: host.hostname,
        status: 'pending' as HostScanStatus,
      })),
      isCancelling: false,
    }));
  }, []);

  const updateHostStatus = useCallback(
    (hostId: string, status: HostScanStatus, scanId?: string, errorMessage?: string) => {
      setState((prev) => ({
        ...prev,
        hostScanProgress: prev.hostScanProgress.map((progress) =>
          progress.hostId === hostId
            ? {
                ...progress,
                status,
                scanId,
                errorMessage,
                startedAt:
                  status === 'connecting' && !progress.startedAt ? new Date() : progress.startedAt,
                completedAt:
                  status === 'completed' || status === 'failed' || status === 'cancelled'
                    ? new Date()
                    : progress.completedAt,
              }
            : progress
        ),
      }));
    },
    []
  );

  const setCancelling = useCallback((cancelling: boolean) => {
    setState((prev) => ({ ...prev, isCancelling: cancelling }));
  }, []);

  const clearHostProgress = useCallback(() => {
    setState((prev) => ({
      ...prev,
      hostScanProgress: [],
      isCancelling: false,
    }));
  }, []);

  // UI State actions
  const setLoading = useCallback((loading: boolean) => {
    setState((prev) => ({ ...prev, isLoading: loading }));
  }, []);

  const setError = useCallback((error: string | null) => {
    setState((prev) => ({ ...prev, error }));
  }, []);

  // Validation: can proceed to next step
  const canProceedToNextStep = useCallback((): boolean => {
    switch (state.activeStep) {
      case 0:
        // Step 1: Must have target type selected and at least one target
        if (state.targetType === 'hosts') {
          return state.selectedHostIds.length > 0;
        }
        if (state.targetType === 'groups') {
          return state.selectedGroupIds.length > 0;
        }
        return false;

      case 1:
        // Step 2: Must have platform, version, and framework selected
        return state.platform !== '' && state.platformVersion !== '' && state.framework !== '';

      case 2:
        // Step 3: Rule configuration is optional, always can proceed
        // If custom mode, should have at least one rule (but we allow empty for now)
        return true;

      case 3:
        // Step 4: Must have scan name
        return state.scanName.trim() !== '';

      default:
        return false;
    }
  }, [state]);

  // Reset wizard to initial state
  const reset = useCallback(() => {
    setState({
      ...initialState,
      selectedHostIds: preselectedHostId ? [preselectedHostId] : [],
      targetType: preselectedHostId ? 'hosts' : null,
    });
  }, [preselectedHostId]);

  // Memoize actions object to prevent unnecessary re-renders
  const actions = useMemo<WizardActions>(
    () => ({
      setActiveStep,
      nextStep,
      prevStep,
      setTargetType,
      toggleHost,
      toggleGroup,
      selectAllHosts,
      clearHosts,
      selectAllGroups,
      clearGroups,
      setPlatform,
      setPlatformVersion,
      setFramework,
      setPlatformAutoDetected,
      setScanMode,
      toggleRule,
      selectAllRules,
      clearRules,
      setScanName,
      initializeHostProgress,
      updateHostStatus,
      setCancelling,
      clearHostProgress,
      setLoading,
      setError,
      canProceedToNextStep,
      reset,
    }),
    [
      setActiveStep,
      nextStep,
      prevStep,
      setTargetType,
      toggleHost,
      toggleGroup,
      selectAllHosts,
      clearHosts,
      selectAllGroups,
      clearGroups,
      setPlatform,
      setPlatformVersion,
      setFramework,
      setPlatformAutoDetected,
      setScanMode,
      toggleRule,
      selectAllRules,
      clearRules,
      setScanName,
      initializeHostProgress,
      updateHostStatus,
      setCancelling,
      clearHostProgress,
      setLoading,
      setError,
      canProceedToNextStep,
      reset,
    ]
  );

  return [state, actions];
}

export default useScanWizard;
