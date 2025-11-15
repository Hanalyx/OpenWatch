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

  // Severity breakdown (optional - for enhanced display)
  criticalIssues?: number;
  highIssues?: number;
  mediumIssues?: number;
  lowIssues?: number;
  criticalHighScore?: number; // Pass rate for critical+high severity only
}

const ComplianceRing: React.FC<ComplianceRingProps> = ({
  score,
  size = 'medium',
  showLabel = true,
  label,
  tooltip,
  onClick,
  trend,
  criticalIssues = 0,
  highIssues = 0,
  mediumIssues = 0,
  lowIssues = 0,
  criticalHighScore,
}) => {
  const theme = useTheme();

  // Show severity breakdown if any severity data provided
  const showSeverityBreakdown = criticalIssues > 0 || highIssues > 0 || mediumIssues > 0 || lowIssues > 0;

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
      fontSize: '1rem',  // Option 2: Smaller than original, balanced with rings
      fontWeight: 700,
    },
  };

  const config = sizeConfig[size];

  const getScoreColor = (score: number) => {
    if (score >= 95) return theme.palette.success.main;    // Green: Compliant (95%+)
    if (score >= 75) return theme.palette.warning.main;    // Yellow: Near compliant (75-94%)
    return theme.palette.error.main;                       // Red: Non-compliant (<75%)
  };

  const getScoreLabel = (score: number) => {
    if (score >= 95) return 'Compliant';
    if (score >= 75) return 'Near Compliant';
    return 'Non-Compliant';
  };

  const scoreColor = getScoreColor(score);
  const displayLabel = label || getScoreLabel(score);

  // Calculate individual severity pass rates (simplified - assume equal distribution)
  const totalIssues = criticalIssues + highIssues + mediumIssues + lowIssues;
  const criticalPassRate = totalIssues > 0 ? Math.max(0, 100 - (criticalIssues / totalIssues) * 100) : score;
  const highPassRate = totalIssues > 0 ? Math.max(0, 100 - (highIssues / totalIssues) * 100) : score;
  const mediumPassRate = totalIssues > 0 ? Math.max(0, 100 - (mediumIssues / totalIssues) * 100) : score;
  const lowPassRate = totalIssues > 0 ? Math.max(0, 100 - (lowIssues / totalIssues) * 100) : score;

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
    // Original single ring layout (fallback when no severity data)
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
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={[
              { name: 'Compliant', value: score },
              { name: 'Non-compliant', value: 100 - score },
            ]}
            cx="50%"
            cy="50%"
            innerRadius={config.lowRadius - 6}
            outerRadius={config.lowRadius}
            startAngle={90}
            endAngle={-270}
            dataKey="value"
          >
            <Cell fill={scoreColor} />
            <Cell fill={alpha(theme.palette.action.disabled, 0.2)} />
          </Pie>
        </PieChart>
      </ResponsiveContainer>

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
            color: scoreColor,
            lineHeight: 1,
          }}
        >
          {score}%
        </Typography>
        {showLabel && size !== 'small' && (
          <Typography
            variant="caption"
            sx={{
              fontSize: '0.625rem',
              color: 'text.secondary',
              lineHeight: 1,
              mt: 0.25,
              display: 'block',
            }}
          >
            {displayLabel}
          </Typography>
        )}
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
