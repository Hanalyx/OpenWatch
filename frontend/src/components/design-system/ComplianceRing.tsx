import React from 'react';
import { Box, Typography, useTheme, alpha, Tooltip } from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

interface ComplianceRingProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
  label?: string;
  tooltip?: string;
  onClick?: () => void;
  trend?: 'up' | 'down' | 'stable';
}

const ComplianceRing: React.FC<ComplianceRingProps> = ({
  score,
  size = 'medium',
  showLabel = true,
  label,
  tooltip,
  onClick,
  trend,
}) => {
  const theme = useTheme();

  const sizeConfig = {
    small: {
      diameter: 48,
      innerRadius: 16,
      outerRadius: 22,
      fontSize: '0.75rem',
      fontWeight: 600,
    },
    medium: {
      diameter: 64,
      innerRadius: 22,
      outerRadius: 30,
      fontSize: '0.875rem',
      fontWeight: 600,
    },
    large: {
      diameter: 80,
      innerRadius: 28,
      outerRadius: 38,
      fontSize: '1rem',
      fontWeight: 700,
    },
  };

  const config = sizeConfig[size];

  const getScoreColor = (score: number) => {
    if (score >= 90) return theme.palette.success.main;
    if (score >= 75) return theme.palette.warning.main;
    if (score >= 60) return theme.palette.warning.dark;
    return theme.palette.error.main;
  };

  const getScoreLabel = (score: number) => {
    if (score >= 90) return 'Excellent';
    if (score >= 75) return 'Good';
    if (score >= 60) return 'Fair';
    return 'Poor';
  };

  const scoreColor = getScoreColor(score);
  const displayLabel = label || getScoreLabel(score);

  const data = [
    { name: 'Compliant', value: score },
    { name: 'Non-compliant', value: 100 - score },
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

  const ringContent = (
    <Box
      sx={{
        position: 'relative',
        width: config.diameter,
        height: config.diameter,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.3s ease',
        '&:hover': onClick
          ? {
              transform: 'scale(1.05)',
            }
          : undefined,
      }}
      onClick={onClick}
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={config.innerRadius}
            outerRadius={config.outerRadius}
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
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
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
          {getTrendIndicator()}
        </Box>
        {showLabel && size !== 'small' && (
          <Typography
            variant="caption"
            sx={{
              fontSize: size === 'large' ? '0.75rem' : '0.625rem',
              color: 'text.secondary',
              lineHeight: 1,
              mt: 0.25,
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
