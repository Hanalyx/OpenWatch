import React from 'react';
import { Box, Typography, useTheme, alpha, Tooltip } from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { Circle } from '@mui/icons-material';

interface ComplianceRingProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
  label?: string;
  tooltip?: string;
  onClick?: () => void;
  trend?: 'up' | 'down' | 'stable';

  // Failed rule counts by severity
  criticalIssues?: number;
  highIssues?: number;
  mediumIssues?: number;
  lowIssues?: number;

  // Per-severity pass/fail breakdown for accurate compliance visualization
  criticalPassed?: number;
  criticalFailed?: number;
  highPassed?: number;
  highFailed?: number;
  mediumPassed?: number;
  mediumFailed?: number;
  lowPassed?: number;
  lowFailed?: number;
}

const ComplianceRing: React.FC<ComplianceRingProps> = ({
  score,
  size = 'medium',
  showLabel: _showLabel = true,
  label: _label,
  tooltip,
  onClick,
  trend,
  // Failed counts
  criticalIssues = 0,
  highIssues = 0,
  mediumIssues = 0,
  lowIssues = 0,
  // Pass/fail breakdown
  criticalPassed,
  criticalFailed,
  highPassed,
  highFailed,
  mediumPassed,
  mediumFailed,
  lowPassed,
  lowFailed,
}) => {
  const theme = useTheme();

  /**
   * Real per-severity pass rate calculation
   *
   * NIST SP 800-137 Continuous Monitoring requires accurate severity-level
   * compliance tracking for risk assessment and visualization.
   *
   * Calculate real pass rates from passed/failed counts:
   *   passRate = (passed / (passed + failed)) * 100
   *
   * If per-severity data unavailable, fall back to overall score.
   */
  const calculatePassRate = (passed?: number, failed?: number): number => {
    // If no per-severity data available, use overall score as fallback
    if (passed === undefined || failed === undefined) {
      return score;
    }

    const total = passed + failed;
    // If no rules of this severity, return 100% (no failures)
    if (total === 0) {
      return 100;
    }

    return (passed / total) * 100;
  };

  // Enable severity breakdown if ANY per-severity data is available
  const showSeverityBreakdown =
    criticalPassed !== undefined ||
    criticalFailed !== undefined ||
    highPassed !== undefined ||
    highFailed !== undefined ||
    mediumPassed !== undefined ||
    mediumFailed !== undefined ||
    lowPassed !== undefined ||
    lowFailed !== undefined;

  const sizeConfig = {
    small: {
      diameter: 48,
      criticalRadius: 12,
      highRadius: 16,
      mediumRadius: 20,
      lowRadius: 24,
      fontSize: '0.75rem',
      fontWeight: 600,
    },
    medium: {
      diameter: 80,
      criticalRadius: 20,
      highRadius: 26,
      mediumRadius: 32,
      lowRadius: 38,
      fontSize: '1rem',
      fontWeight: 600,
    },
    large: {
      diameter: 100,
      criticalRadius: 22,
      highRadius: 30,
      mediumRadius: 38,
      lowRadius: 46,
      fontSize: '1rem', // Option 2: Smaller than original, balanced with rings
      fontWeight: 700,
    },
  };

  const config = sizeConfig[size];

  // Calculate REAL per-severity pass rates using actual passed/failed counts
  // Replaces fake algorithm that caused identical rings for different compliance scores
  const criticalPassRate = calculatePassRate(criticalPassed, criticalFailed);
  const highPassRate = calculatePassRate(highPassed, highFailed);
  const mediumPassRate = calculatePassRate(mediumPassed, mediumFailed);
  const lowPassRate = calculatePassRate(lowPassed, lowFailed);

  // Data for each severity ring
  const criticalData = [
    { name: 'Passed', value: criticalPassRate },
    { name: 'Failed', value: 100 - criticalPassRate },
  ];
  const highData = [
    { name: 'Passed', value: highPassRate },
    { name: 'Failed', value: 100 - highPassRate },
  ];
  const mediumData = [
    { name: 'Passed', value: mediumPassRate },
    { name: 'Failed', value: 100 - mediumPassRate },
  ];
  const lowData = [
    { name: 'Passed', value: lowPassRate },
    { name: 'Failed', value: 100 - lowPassRate },
  ];

  const getTrendIndicator = () => {
    if (!trend) return null;

    const trendConfig = {
      up: { symbol: '↗', color: theme.palette.success.main },
      down: { symbol: '↘', color: theme.palette.error.main },
      stable: { symbol: '→', color: theme.palette.text.secondary },
    };

    const trendInfo = trendConfig[trend];

    return (
      <Typography
        variant="caption"
        sx={{
          color: trendInfo.color,
          fontWeight: 'bold',
          ml: 0.5,
        }}
      >
        {trendInfo.symbol}
      </Typography>
    );
  };

  const ringContent = showSeverityBreakdown ? (
    // Horizontal layout: Rings on left, legend on right
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      {/* Left: 4 Concentric Rings */}
      <Box
        sx={{
          position: 'relative',
          width: config.diameter,
          height: config.diameter,
          flexShrink: 0,
          cursor: onClick ? 'pointer' : 'default',
          transition: 'all 0.3s ease',
          '&:hover': onClick ? { transform: 'scale(1.05)' } : undefined,
        }}
        onClick={onClick}
      >
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            {/* Ring 4 (Outermost): Low/Overall - Light Blue */}
            <Pie
              data={lowData}
              cx="50%"
              cy="50%"
              innerRadius={config.lowRadius - 8}
              outerRadius={config.lowRadius}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              stroke="none"
            >
              <Cell fill="rgb(144, 202, 249)" />
              <Cell fill={alpha(theme.palette.action.disabled, 0.15)} />
            </Pie>

            {/* Ring 3: Medium - Light Orange */}
            <Pie
              data={mediumData}
              cx="50%"
              cy="50%"
              innerRadius={config.mediumRadius - 8}
              outerRadius={config.mediumRadius}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              stroke="none"
            >
              <Cell fill="rgb(255, 183, 77)" />
              <Cell fill={alpha(theme.palette.action.disabled, 0.15)} />
            </Pie>

            {/* Ring 2: High - Dark Orange */}
            <Pie
              data={highData}
              cx="50%"
              cy="50%"
              innerRadius={config.highRadius - 8}
              outerRadius={config.highRadius}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              stroke="none"
            >
              <Cell fill="rgb(255, 152, 0)" />
              <Cell fill={alpha(theme.palette.action.disabled, 0.15)} />
            </Pie>

            {/* Ring 1 (Innermost): Critical - Red */}
            <Pie
              data={criticalData}
              cx="50%"
              cy="50%"
              innerRadius={config.criticalRadius - 8}
              outerRadius={config.criticalRadius}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              stroke="none"
            >
              <Cell fill="rgb(244, 67, 54)" />
              <Cell fill={alpha(theme.palette.action.disabled, 0.15)} />
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </Box>

      {/* Right: Compliance Score + Legend */}
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        {/* Overall Score */}
        <Typography
          variant="body2"
          sx={{
            fontSize: config.fontSize,
            fontWeight: config.fontWeight,
            color: 'text.primary',
            lineHeight: 1.2,
          }}
        >
          Overall score: {score.toFixed(2)}%
        </Typography>

        {/* Vertical Legend */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25, mt: 0.5 }}>
          {criticalIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: 'rgb(244, 67, 54)' }} />
              <Typography variant="caption" sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                Critical ({criticalIssues})
              </Typography>
            </Box>
          )}
          {highIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: 'rgb(255, 152, 0)' }} />
              <Typography variant="caption" sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                High ({highIssues})
              </Typography>
            </Box>
          )}
          {mediumIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: 'rgb(255, 183, 77)' }} />
              <Typography variant="caption" sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                Medium ({mediumIssues})
              </Typography>
            </Box>
          )}
          {lowIssues > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Circle sx={{ fontSize: '0.5rem', color: 'rgb(144, 202, 249)' }} />
              <Typography variant="caption" sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                Low ({lowIssues})
              </Typography>
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  ) : (
    // Empty ring when no severity data available (no scan performed)
    <Box
      sx={{
        position: 'relative',
        width: config.diameter,
        height: config.diameter,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.3s ease',
        '&:hover': onClick ? { transform: 'scale(1.05)' } : undefined,
      }}
      onClick={onClick}
    >
      {/* Empty ring border */}
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: config.lowRadius * 2,
          height: config.lowRadius * 2,
          borderRadius: '50%',
          border: `2px solid ${alpha(theme.palette.action.disabled, 0.2)}`,
        }}
      />

      {/* Center Content */}
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
        }}
      >
        <Typography
          variant="caption"
          sx={{
            fontSize: config.fontSize,
            fontWeight: config.fontWeight,
            color: 'text.secondary',
            lineHeight: 1,
          }}
        >
          No Data
        </Typography>
      </Box>
    </Box>
  );

  if (tooltip) {
    return (
      <Tooltip title={tooltip} arrow>
        {ringContent}
      </Tooltip>
    );
  }

  return ringContent;
};

export default ComplianceRing;
