/**
 * Drift Indicator Component
 *
 * Visual indicator for compliance drift status.
 * Shows drift type with appropriate color coding and iconography.
 *
 * Drift Types:
 * - major: Red - Score drop >= 10 percentage points
 * - minor: Orange - Score drop 5-10 percentage points
 * - improvement: Green - Score increase >= 5 percentage points
 * - stable: Grey - Score change < 5 percentage points
 */

import React from 'react';
import { Box, Chip, Typography, Tooltip } from '@mui/material';
import {
  TrendingDown as TrendingDownIcon,
  TrendingUp as TrendingUpIcon,
  Remove as RemoveIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

interface DriftIndicatorProps {
  driftType: 'major' | 'minor' | 'improvement' | 'stable' | null;
  scoreDelta?: number;
  baselineScore?: number;
  currentScore?: number;
  size?: 'small' | 'medium';
}

const DriftIndicator: React.FC<DriftIndicatorProps> = ({
  driftType,
  scoreDelta,
  baselineScore,
  currentScore,
  size = 'medium',
}) => {
  if (!driftType) {
    return <Chip label="No Baseline" size={size} variant="outlined" color="default" />;
  }

  const getDriftConfig = () => {
    switch (driftType) {
      case 'major':
        return {
          label: 'Major Drift',
          color: 'error' as const,
          icon: <WarningIcon />,
          tooltip: 'Compliance score dropped by 10+ percentage points',
          bgColor: '#ffebee',
          textColor: '#c62828',
        };
      case 'minor':
        return {
          label: 'Minor Drift',
          color: 'warning' as const,
          icon: <TrendingDownIcon />,
          tooltip: 'Compliance score dropped by 5-10 percentage points',
          bgColor: '#fff3e0',
          textColor: '#e65100',
        };
      case 'improvement':
        return {
          label: 'Improvement',
          color: 'success' as const,
          icon: <TrendingUpIcon />,
          tooltip: 'Compliance score improved by 5+ percentage points',
          bgColor: '#e8f5e9',
          textColor: '#2e7d32',
        };
      case 'stable':
        return {
          label: 'Stable',
          color: 'default' as const,
          icon: <RemoveIcon />,
          tooltip: 'Compliance score changed by less than 5 percentage points',
          bgColor: '#f5f5f5',
          textColor: '#616161',
        };
      default:
        return {
          label: 'Unknown',
          color: 'default' as const,
          icon: <RemoveIcon />,
          tooltip: 'Unknown drift status',
          bgColor: '#f5f5f5',
          textColor: '#616161',
        };
    }
  };

  const config = getDriftConfig();

  const tooltipContent = (
    <Box>
      <Typography variant="body2" fontWeight="bold" gutterBottom>
        {config.label}
      </Typography>
      {scoreDelta !== undefined && (
        <Typography variant="body2">
          Score change: {scoreDelta > 0 ? '+' : ''}
          {scoreDelta.toFixed(2)}pp
        </Typography>
      )}
      {baselineScore !== undefined && currentScore !== undefined && (
        <Typography variant="body2">
          {baselineScore.toFixed(1)}% → {currentScore.toFixed(1)}%
        </Typography>
      )}
      <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
        {config.tooltip}
      </Typography>
    </Box>
  );

  return (
    <Tooltip title={tooltipContent} arrow>
      <Chip
        label={
          <Box display="flex" alignItems="center" gap={0.5}>
            {config.label}
            {scoreDelta !== undefined && (
              <Typography variant="caption" fontWeight="bold" sx={{ ml: 0.5 }}>
                ({scoreDelta > 0 ? '+' : ''}
                {scoreDelta.toFixed(1)}pp)
              </Typography>
            )}
          </Box>
        }
        icon={config.icon}
        size={size}
        color={config.color}
        sx={{
          bgcolor: config.bgColor,
          color: config.textColor,
          '& .MuiChip-icon': {
            color: config.textColor,
          },
        }}
      />
    </Tooltip>
  );
};

export default DriftIndicator;
