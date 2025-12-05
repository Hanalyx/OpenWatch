/**
 * Version Display Component
 *
 * Shows OpenWatch version in footer, login page, or settings.
 * Fetches from backend /api/version for full info, falls back to frontend version.
 */

import React, { useState, useEffect } from 'react';
import { Typography, Tooltip, Box, Link, Skeleton } from '@mui/material';
import { APP_VERSION, CODENAME } from '../../version';

interface VersionInfo {
  version: string;
  codename: string;
  api_version: string;
  git_commit: string | null;
  build_date: string | null;
}

interface VersionDisplayProps {
  /** Show full version info (including git commit, build date) */
  detailed?: boolean;
  /** Typography variant */
  variant?: 'body2' | 'caption' | 'subtitle2';
  /** Text color */
  color?: string;
  /** Align text */
  align?: 'left' | 'center' | 'right';
}

/**
 * Displays OpenWatch version information.
 *
 * Basic: "OpenWatch v0.1.0 Eyrie"
 * Detailed: Includes git commit and build date in tooltip
 */
export const VersionDisplay: React.FC<VersionDisplayProps> = ({
  detailed = false,
  variant = 'caption',
  color = 'text.secondary',
  align = 'center',
}) => {
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  const [loading, setLoading] = useState(detailed);

  useEffect(() => {
    if (!detailed) return;

    const fetchVersion = async () => {
      try {
        const response = await fetch('/api/version');
        if (response.ok) {
          const data = await response.json();
          setVersionInfo(data);
        }
      } catch {
        // Fall back to frontend version
        setVersionInfo({
          version: APP_VERSION,
          codename: CODENAME,
          api_version: '1',
          git_commit: null,
          build_date: null,
        });
      } finally {
        setLoading(false);
      }
    };

    fetchVersion();
  }, [detailed]);

  if (loading) {
    return (
      <Box sx={{ textAlign: align }}>
        <Skeleton width={150} height={20} sx={{ display: 'inline-block' }} />
      </Box>
    );
  }

  const displayVersion = versionInfo?.version || APP_VERSION;
  const displayCodename = versionInfo?.codename || CODENAME;
  const displayText = `OpenWatch v${displayVersion} ${displayCodename}`;

  // Simple display without tooltip
  if (!detailed) {
    return (
      <Typography variant={variant} color={color} sx={{ textAlign: align }}>
        {displayText}
      </Typography>
    );
  }

  // Detailed display with tooltip
  const tooltipContent = (
    <Box>
      <Typography variant="body2">Version: {displayVersion}</Typography>
      <Typography variant="body2">Codename: {displayCodename}</Typography>
      {versionInfo?.api_version && (
        <Typography variant="body2">API Version: {versionInfo.api_version}</Typography>
      )}
      {versionInfo?.git_commit && (
        <Typography variant="body2">Commit: {versionInfo.git_commit}</Typography>
      )}
      {versionInfo?.build_date && (
        <Typography variant="body2">Built: {versionInfo.build_date}</Typography>
      )}
    </Box>
  );

  return (
    <Tooltip title={tooltipContent} arrow placement="top">
      <Typography variant={variant} color={color} sx={{ textAlign: align, cursor: 'help' }}>
        {displayText}
      </Typography>
    </Tooltip>
  );
};

/**
 * Footer version display with link to docs.
 */
export const FooterVersion: React.FC = () => {
  return (
    <Box
      sx={{
        py: 2,
        textAlign: 'center',
        borderTop: 1,
        borderColor: 'divider',
      }}
    >
      <VersionDisplay detailed variant="caption" />
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
        <Link
          href="https://github.com/hanalyx/openwatch"
          target="_blank"
          rel="noopener noreferrer"
          color="inherit"
          underline="hover"
        >
          GitHub
        </Link>
        {' | '}
        <Link href="/docs" color="inherit" underline="hover">
          Documentation
        </Link>
      </Typography>
    </Box>
  );
};

export default VersionDisplay;
