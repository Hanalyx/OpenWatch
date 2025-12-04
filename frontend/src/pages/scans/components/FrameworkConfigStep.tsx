/**
 * FrameworkConfigStep - Step 2 of the ComplianceScanWizard
 *
 * Allows users to configure platform and compliance framework:
 * - Platform selection with version dropdown
 * - Auto-detection from selected hosts' OS (via OS Discovery or JIT detection)
 * - Compliance framework selection cards
 * - Mixed platform warnings
 *
 * Platform Detection Strategy:
 * 1. Check if hosts have os_family/os_version from OS Discovery (database)
 * 2. If not, trigger JIT detection via /api/hosts/{id}/detect-platform
 * 3. JIT detection performs SSH-based platform detection and persists results
 *
 * @module FrameworkConfigStep
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for design specifications
 */

import React, { useEffect, useMemo, useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Chip,
  CircularProgress,
} from '@mui/material';
import {
  Security as SecurityIcon,
  AutoFixHigh as AutoDetectIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import type { SelectChangeEvent } from '@mui/material/Select';
import {
  SUPPORTED_PLATFORMS,
  SUPPORTED_FRAMEWORKS,
  type Platform,
  type Framework,
} from '../../../constants/complianceFrameworks';
import type { WizardHost } from '../hooks/useScanWizard';
import { api } from '../../../services/api';

/**
 * Normalize version string to match SUPPORTED_PLATFORMS version format.
 *
 * Backend OS Discovery returns full versions like "9.3", "8.6", "22.04"
 * but SUPPORTED_PLATFORMS has normalized versions:
 * - RHEL/CentOS/Debian: ['7', '8', '9'] (major only)
 * - Ubuntu: ['18.04', '20.04', '22.04', '24.04'] (major.minor)
 *
 * @param version - Full version string from backend (e.g., "9.3", "22.04.1")
 * @param platformId - Platform ID to determine normalization rules
 * @returns Normalized version matching SUPPORTED_PLATFORMS format
 */
function normalizeVersionForPlatform(version: string, platformId: string): string {
  if (!version) return '';

  // Ubuntu uses YY.MM format - keep major.minor (first two parts)
  if (platformId === 'ubuntu') {
    const parts = version.split('.');
    if (parts.length >= 2) {
      return `${parts[0]}.${parts[1]}`;
    }
    return version;
  }

  // RHEL, CentOS, Debian, Fedora, SUSE - use major version only
  const majorVersion = version.split('.')[0];
  return majorVersion;
}

/**
 * Find matching version in supported versions list.
 *
 * @param version - Version string from backend
 * @param platformId - Platform ID
 * @param supportedVersions - List of supported versions
 * @returns Matching supported version or null
 */
function findMatchingVersion(
  version: string,
  platformId: string,
  supportedVersions: string[]
): string | null {
  if (!version || supportedVersions.length === 0) return null;

  // First try exact match
  if (supportedVersions.includes(version)) {
    return version;
  }

  // Try normalized version
  const normalized = normalizeVersionForPlatform(version, platformId);
  if (supportedVersions.includes(normalized)) {
    return normalized;
  }

  return null;
}

/**
 * Props for FrameworkConfigStep component
 */
interface FrameworkConfigStepProps {
  /** Currently selected platform ID */
  platform: string;
  /** Currently selected platform version */
  platformVersion: string;
  /** Currently selected framework ID */
  framework: string;
  /** Whether platform was auto-detected */
  platformAutoDetected: boolean;
  /** Selected hosts (for auto-detection) */
  selectedHosts: WizardHost[];
  /** Callback when platform changes */
  onPlatformChange: (platform: string) => void;
  /** Callback when platform version changes */
  onPlatformVersionChange: (version: string) => void;
  /** Callback when framework changes */
  onFrameworkChange: (framework: string) => void;
  /** Callback when auto-detection status changes */
  onPlatformAutoDetectedChange: (detected: boolean) => void;
}

/**
 * Platform detection result with match statistics
 */
interface PlatformDetectionResult {
  platform: string;
  version: string;
  matchCount: number;
  totalHosts: number;
  isMixed: boolean;
  detectedPlatforms: Map<string, number>;
}

/**
 * Response from JIT platform detection API
 */
interface JITDetectionResponse {
  host_id: string;
  task_id: string | null;
  status: 'completed' | 'failed' | 'queued' | 'pending';
  os_family: string | null;
  os_version: string | null;
  platform_identifier: string | null;
  architecture: string | null;
  discovered_at: string | null;
  error: string | null;
}

/**
 * Detect platform from selected hosts using OS Discovery data.
 *
 * This function checks if hosts have os_family/os_version from OS Discovery.
 * If not, the component will trigger JIT detection via the backend API.
 *
 * Version normalization is applied to match SUPPORTED_PLATFORMS format:
 * - RHEL/CentOS: "9.3" -> "9"
 * - Ubuntu: "22.04.1" -> "22.04"
 *
 * @param hosts - Array of selected hosts
 * @returns Detection result with platform info and statistics, or null if no OS discovery data
 */
function detectPlatformFromHosts(hosts: WizardHost[]): PlatformDetectionResult | null {
  if (hosts.length === 0) return null;

  const platformCounts = new Map<string, number>();
  const versionCounts = new Map<string, number>();

  // Count platforms from hosts with OS Discovery data
  for (const host of hosts) {
    // Only use OS Discovery data (os_family/os_version from backend)
    // Do NOT fall back to string parsing - that's unreliable
    // If OS Discovery hasn't run, user selects manually and backend does JIT detection
    if (host.platform && host.platformVersion) {
      const platformId = host.platform.toLowerCase();
      // Normalize version to match SUPPORTED_PLATFORMS format
      const normalizedVersion = normalizeVersionForPlatform(host.platformVersion, platformId);

      const key = `${platformId}:${normalizedVersion}`;
      platformCounts.set(platformId, (platformCounts.get(platformId) || 0) + 1);
      versionCounts.set(key, (versionCounts.get(key) || 0) + 1);
    }
    // No fallback - hosts without OS Discovery data are not counted
  }

  if (platformCounts.size === 0) return null;

  // Find most common platform
  let mostCommonPlatform = '';
  let maxPlatformCount = 0;
  platformCounts.forEach((count, platform) => {
    if (count > maxPlatformCount) {
      maxPlatformCount = count;
      mostCommonPlatform = platform;
    }
  });

  // Find most common version for that platform (already normalized)
  let mostCommonVersion = '';
  let maxVersionCount = 0;
  versionCounts.forEach((count, key) => {
    const [platform, version] = key.split(':');
    if (platform === mostCommonPlatform && count > maxVersionCount) {
      maxVersionCount = count;
      mostCommonVersion = version;
    }
  });

  return {
    platform: mostCommonPlatform,
    version: mostCommonVersion,
    matchCount: maxPlatformCount,
    totalHosts: hosts.length,
    isMixed: platformCounts.size > 1,
    detectedPlatforms: platformCounts,
  };
}

/**
 * Get platform display name by ID
 */
function getPlatformName(platformId: string): string {
  const platform = SUPPORTED_PLATFORMS.find((p) => p.id === platformId);
  return platform?.name || platformId;
}

/**
 * FrameworkConfigStep Component
 *
 * Second step of the scan wizard for configuring platform and framework.
 */
const FrameworkConfigStep: React.FC<FrameworkConfigStepProps> = ({
  platform,
  platformVersion,
  framework,
  platformAutoDetected,
  selectedHosts,
  onPlatformChange,
  onPlatformVersionChange,
  onFrameworkChange,
  onPlatformAutoDetectedChange,
}) => {
  // JIT detection state
  const [jitDetecting, setJitDetecting] = useState(false);
  const [jitError, setJitError] = useState<string | null>(null);
  const [jitAttempted, setJitAttempted] = useState(false);

  /**
   * Check if hosts have OS Discovery data (from database)
   */
  const detectionResult = useMemo(() => {
    return detectPlatformFromHosts(selectedHosts);
  }, [selectedHosts]);

  /**
   * Check if any hosts need JIT detection (no OS Discovery data)
   */
  const hostsNeedingJIT = useMemo(() => {
    return selectedHosts.filter((h) => !h.platform || !h.platformVersion);
  }, [selectedHosts]);

  /**
   * Perform JIT platform detection for hosts without OS Discovery data
   */
  const performJITDetection = useCallback(async () => {
    if (hostsNeedingJIT.length === 0 || jitAttempted) return;

    setJitDetecting(true);
    setJitError(null);
    setJitAttempted(true);

    try {
      // Detect platform for the first host that needs JIT detection
      // The backend will persist results to database
      const hostToDetect = hostsNeedingJIT[0];
      const response = await api.post<JITDetectionResponse>(
        `/api/hosts/${hostToDetect.id}/detect-platform`
      );

      if (response.status === 'completed' && response.os_family && response.os_version) {
        // Successfully detected - apply to form
        const platformId = response.os_family.toLowerCase();
        const detectedPlatform = SUPPORTED_PLATFORMS.find((p) => p.id === platformId);

        if (detectedPlatform) {
          // Find matching version using normalization
          const matchedVersion = findMatchingVersion(
            response.os_version,
            platformId,
            detectedPlatform.versions
          );

          onPlatformChange(platformId);
          if (matchedVersion) {
            onPlatformVersionChange(matchedVersion);
            onPlatformAutoDetectedChange(true);
          }
          // If no version match, platform is set but user must select version
        }
      } else if (response.status === 'failed') {
        setJitError(response.error || 'Platform detection failed');
      }
    } catch (error) {
      console.error('JIT platform detection failed:', error);
      setJitError('Failed to detect platform. Please select manually.');
    } finally {
      setJitDetecting(false);
    }
  }, [
    hostsNeedingJIT,
    jitAttempted,
    onPlatformChange,
    onPlatformVersionChange,
    onPlatformAutoDetectedChange,
  ]);

  /**
   * Auto-apply detected platform from OS Discovery if available
   */
  useEffect(() => {
    if (detectionResult && !platform && !platformVersion) {
      // OS Discovery data exists - apply it
      // Note: detectionResult.version is already normalized by detectPlatformFromHosts
      const detectedPlatform = SUPPORTED_PLATFORMS.find((p) => p.id === detectionResult.platform);
      if (detectedPlatform && detectedPlatform.versions.includes(detectionResult.version)) {
        onPlatformChange(detectionResult.platform);
        onPlatformVersionChange(detectionResult.version);
        onPlatformAutoDetectedChange(true);
      } else if (detectedPlatform) {
        // Platform found but version not in supported list - set platform only
        onPlatformChange(detectionResult.platform);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detectionResult]);

  /**
   * Trigger JIT detection when no OS Discovery data and hosts selected
   */
  useEffect(() => {
    if (!detectionResult && hostsNeedingJIT.length > 0 && !jitAttempted && !platform) {
      // No OS Discovery data - trigger JIT detection
      performJITDetection();
    }
  }, [detectionResult, hostsNeedingJIT, jitAttempted, platform, performJITDetection]);

  /**
   * Get available versions for selected platform
   */
  const availableVersions = useMemo((): string[] => {
    if (!platform) return [];
    const selectedPlatform = SUPPORTED_PLATFORMS.find((p) => p.id === platform);
    return selectedPlatform?.versions || [];
  }, [platform]);

  /**
   * Handle platform selection change
   */
  const handlePlatformChange = (event: SelectChangeEvent<string>) => {
    const newPlatform = event.target.value;
    onPlatformChange(newPlatform);
    onPlatformVersionChange(''); // Reset version when platform changes
    onPlatformAutoDetectedChange(false); // User manually changed, not auto-detected
  };

  /**
   * Handle platform version selection change
   */
  const handleVersionChange = (event: SelectChangeEvent<string>) => {
    onPlatformVersionChange(event.target.value);
    onPlatformAutoDetectedChange(false); // User manually changed
  };

  /**
   * Handle framework selection
   */
  const handleFrameworkSelect = (frameworkId: string) => {
    onFrameworkChange(frameworkId);
  };

  /**
   * Get the selected platform object
   */
  const selectedPlatform: Platform | undefined = SUPPORTED_PLATFORMS.find((p) => p.id === platform);

  /**
   * Get the selected framework object
   */
  const selectedFramework: Framework | undefined = SUPPORTED_FRAMEWORKS.find(
    (f) => f.id === framework
  );

  return (
    <Box>
      {/* Step Header */}
      <Typography variant="h6" gutterBottom>
        Framework & Platform Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Select the compliance framework and target platform for the scan.
      </Typography>

      {/* Platform Configuration Section */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
          Platform Configuration
        </Typography>

        <Grid container spacing={2} sx={{ mb: 2 }}>
          {/* Platform Dropdown */}
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth>
              <InputLabel id="platform-select-label">Platform</InputLabel>
              <Select
                labelId="platform-select-label"
                id="platform-select"
                value={platform}
                label="Platform"
                onChange={handlePlatformChange}
              >
                {SUPPORTED_PLATFORMS.map((p) => (
                  <MenuItem key={p.id} value={p.id}>
                    {p.name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          {/* Version Dropdown */}
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!platform}>
              <InputLabel id="version-select-label">Version</InputLabel>
              <Select
                labelId="version-select-label"
                id="version-select"
                value={platformVersion}
                label="Version"
                onChange={handleVersionChange}
              >
                {availableVersions.map((version) => (
                  <MenuItem key={version} value={version}>
                    {version}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>

        {/* JIT Detection In Progress */}
        {jitDetecting && (
          <Alert severity="info" icon={<CircularProgress size={20} />} sx={{ mb: 2 }}>
            <Typography variant="body2">
              Detecting platform via SSH... This may take a few seconds.
            </Typography>
          </Alert>
        )}

        {/* JIT Detection Error */}
        {jitError && !jitDetecting && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>Platform detection failed:</strong> {jitError}
              <br />
              Please select the platform and version manually.
            </Typography>
          </Alert>
        )}

        {/* Auto-detection Success - from OS Discovery */}
        {platformAutoDetected && detectionResult && !jitDetecting && (
          <Alert severity="info" icon={<AutoDetectIcon />} sx={{ mb: 2 }}>
            <Typography variant="body2">
              Auto-detected from OS Discovery: {getPlatformName(detectionResult.platform)}{' '}
              {detectionResult.version} ({detectionResult.matchCount} of{' '}
              {detectionResult.totalHosts} hosts match)
            </Typography>
          </Alert>
        )}

        {/* Auto-detection Success - from JIT */}
        {platformAutoDetected && !detectionResult && platform && !jitDetecting && !jitError && (
          <Alert severity="info" icon={<AutoDetectIcon />} sx={{ mb: 2 }}>
            <Typography variant="body2">
              Auto-detected via SSH: {getPlatformName(platform)} {platformVersion}
            </Typography>
          </Alert>
        )}

        {/* Mixed Platform Warning */}
        {detectionResult?.isMixed && (
          <Alert severity="warning" icon={<WarningIcon />} sx={{ mb: 2 }}>
            <Typography variant="body2" gutterBottom>
              <strong>Mixed platforms detected:</strong> Selected hosts have different operating
              systems.
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
              {Array.from(detectionResult.detectedPlatforms.entries()).map(
                ([platformId, count]) => (
                  <Chip
                    key={platformId}
                    label={`${getPlatformName(platformId)}: ${count} hosts`}
                    size="small"
                    variant="outlined"
                  />
                )
              )}
            </Box>
            <Typography variant="body2" sx={{ mt: 1 }} color="text.secondary">
              Choose the platform that matches the majority of your hosts. Hosts with different
              platforms may have limited rule coverage.
            </Typography>
          </Alert>
        )}

        {/* Platform Selection Summary */}
        {platform && platformVersion && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Selected:
            </Typography>
            <Chip
              label={`${selectedPlatform?.name || platform} ${platformVersion}`}
              color="primary"
              size="small"
            />
          </Box>
        )}
      </Box>

      {/* Framework Selection Section */}
      <Box>
        <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
          Compliance Framework
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Select the compliance framework to use for scanning.
        </Typography>

        <Grid container spacing={2}>
          {SUPPORTED_FRAMEWORKS.map((fw) => (
            <Grid item xs={12} sm={6} md={4} key={fw.id}>
              <Card
                sx={{
                  cursor: 'pointer',
                  height: '100%',
                  border: 2,
                  borderColor: framework === fw.id ? 'primary.main' : 'divider',
                  transition: 'all 0.2s ease-in-out',
                  '&:hover': {
                    borderColor: 'primary.main',
                    boxShadow: 2,
                  },
                }}
                onClick={() => handleFrameworkSelect(fw.id)}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
                    <SecurityIcon
                      sx={{
                        fontSize: 28,
                        color: framework === fw.id ? 'primary.main' : 'text.secondary',
                        mt: 0.5,
                      }}
                    />
                    <Box sx={{ flex: 1 }}>
                      <Typography
                        variant="subtitle1"
                        fontWeight="medium"
                        sx={{
                          color: framework === fw.id ? 'primary.main' : 'text.primary',
                        }}
                      >
                        {fw.name}
                      </Typography>
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                          overflow: 'hidden',
                        }}
                      >
                        {fw.description}
                      </Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        {/* Framework Selection Summary */}
        {framework && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Selected framework:
            </Typography>
            <Chip
              icon={<SecurityIcon />}
              label={selectedFramework?.name || framework}
              color="primary"
              size="small"
            />
          </Box>
        )}
      </Box>

      {/* Configuration Complete Summary */}
      {platform && platformVersion && framework && (
        <Alert severity="success" sx={{ mt: 3 }}>
          <Typography variant="body2">
            <strong>Configuration complete:</strong> {selectedPlatform?.name} {platformVersion} with{' '}
            {selectedFramework?.name}
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default FrameworkConfigStep;
