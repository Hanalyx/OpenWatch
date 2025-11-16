import React from 'react';
import { Box, Typography, LinearProgress, Tooltip, Chip } from '@mui/material';
import { useTheme, alpha } from '@mui/material/styles';
import { Circle } from '@mui/icons-material';

export interface SeverityRiskBarsProps {
  // Overall metrics
  totalRules: number;
  passedRules: number;

  // Severity-specific counts
  criticalIssues?: number;
  highIssues?: number;
  mediumIssues?: number;
  lowIssues?: number;

  // Display options
  size?: 'small' | 'medium' | 'large';
  variant?: 'full' | 'compact'; // full: multi-bar, compact: single bar + counts
}

const SeverityRiskBars: React.FC<SeverityRiskBarsProps> = ({
  totalRules,
  passedRules,
  criticalIssues = 0,
  highIssues = 0,
  mediumIssues = 0,
  lowIssues = 0,
  size = 'medium',
  variant = 'compact',
}) => {
  const theme = useTheme();

  // Calculate overall pass rate
  const overallPassRate = totalRules > 0 ? (passedRules / totalRules) * 100 : 0;
  const failedRules = totalRules - passedRules;

  // Determine overall color based on pass rate thresholds
  const getOverallColor = (rate: number) => {
    if (rate >= 95) return theme.palette.success.main; // Green: Compliant (95%+)
    if (rate >= 75) return theme.palette.warning.main; // Yellow: Near compliant (75-94%)
    return theme.palette.error.main; // Red: Non-compliant (<75%)
  };

  const getOverallLabel = (rate: number) => {
    if (rate >= 95) return 'Compliant';
    if (rate >= 75) return 'Near Compliant';
    return 'Non-Compliant';
  };

  // Bar height and font size based on size prop
  const barHeight = size === 'small' ? 4 : size === 'medium' ? 6 : 8;
  const fontSize = size === 'small' ? '0.65rem' : size === 'medium' ? '0.75rem' : '0.875rem';

  // Handle no scan data
  if (totalRules === 0) {
    return (
      <Box sx={{ p: 1, textAlign: 'center' }}>
        <Typography variant="caption" color="text.secondary">
          Not scanned
        </Typography>
      </Box>
    );
  }

  const overallColor = getOverallColor(overallPassRate);
  const overallLabel = getOverallLabel(overallPassRate);

  return (
    <Box>
      {/* Overall Score Bar */}
      <Box sx={{ mb: 1 }}>
        {/* Label and percentage row */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            mb: 0.5,
          }}
        >
          <Typography
            variant="caption"
            sx={{
              fontSize,
              fontWeight: 600,
              color: 'text.primary',
            }}
          >
            Overall: {overallLabel}
          </Typography>
          <Typography
            variant="caption"
            sx={{
              fontSize,
              fontWeight: 600,
              color: 'text.primary',
            }}
          >
            {overallPassRate.toFixed(0)}%
          </Typography>
        </Box>

        {/* Progress bar with tooltip */}
        <Tooltip
          title={`${passedRules} passed, ${failedRules} failed of ${totalRules} rules`}
          placement="top"
          arrow
        >
          <LinearProgress
            variant="determinate"
            value={overallPassRate}
            sx={{
              height: barHeight,
              borderRadius: 1,
              backgroundColor: theme.palette.grey[200],
              '& .MuiLinearProgress-bar': {
                backgroundColor: overallColor,
                borderRadius: 1,
              },
            }}
          />
        </Tooltip>
      </Box>

      {/* Compact severity indicators - color dots + counts */}
      {(criticalIssues > 0 || highIssues > 0 || mediumIssues > 0 || lowIssues > 0) && (
        <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', flexWrap: 'wrap' }}>
          {criticalIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: theme.palette.error.main }} />
              <Typography variant="caption" sx={{ fontSize, color: 'text.secondary' }}>
                {criticalIssues}
              </Typography>
            </Box>
          )}

          {highIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: theme.palette.warning.main }} />
              <Typography variant="caption" sx={{ fontSize, color: 'text.secondary' }}>
                {highIssues}
              </Typography>
            </Box>
          )}

          {mediumIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: '#fdd835' }} />
              <Typography variant="caption" sx={{ fontSize, color: 'text.secondary' }}>
                {mediumIssues}
              </Typography>
            </Box>
          )}

          {lowIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: theme.palette.info.main }} />
              <Typography variant="caption" sx={{ fontSize, color: 'text.secondary' }}>
                {lowIssues}
              </Typography>
            </Box>
          )}
        </Box>
      )}
    </Box>
  );
};

export default SeverityRiskBars;
