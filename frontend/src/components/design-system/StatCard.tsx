import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  IconButton,
  Skeleton,
  useTheme,
  alpha,
} from '@mui/material';
import {
  TrendingUp,
  TrendingDown,
  TrendingFlat,
  MoreVert,
  InfoOutlined,
} from '@mui/icons-material';

interface StatCardProps {
  title: React.ReactNode;
  value: string | number;
  subtitle?: string;
  trend?: 'up' | 'down' | 'flat';
  trendValue?: string;
  color?: 'primary' | 'success' | 'warning' | 'error' | 'info';
  icon?: React.ReactNode;
  loading?: boolean;
  onClick?: () => void;
  onMoreClick?: () => void;
  size?: 'small' | 'medium' | 'large';
}

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  trend,
  trendValue,
  color = 'primary',
  icon,
  loading = false,
  onClick,
  onMoreClick,
  size = 'medium',
}) => {
  const theme = useTheme();

  const sizeConfig = {
    small: {
      titleVariant: 'body2' as const,
      valueVariant: 'h5' as const,
      padding: 2,
      iconSize: 32,
    },
    medium: {
      titleVariant: 'body1' as const,
      valueVariant: 'h4' as const,
      padding: 2.5,
      iconSize: 40,
    },
    large: {
      titleVariant: 'h6' as const,
      valueVariant: 'h3' as const,
      padding: 3,
      iconSize: 48,
    },
  };

  const config = sizeConfig[size];
  const colorValue = theme.palette[color].main;

  const getTrendIcon = () => {
    switch (trend) {
      case 'up':
        return <TrendingUp fontSize="small" color="success" />;
      case 'down':
        return <TrendingDown fontSize="small" color="error" />;
      case 'flat':
        return <TrendingFlat fontSize="small" color="disabled" />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <Card
        sx={{
          height: '100%',
          transition: 'all 0.3s ease',
        }}
      >
        <CardContent sx={{ p: config.padding }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
            <Skeleton variant="text" width="60%" height={24} />
            <Skeleton variant="circular" width={24} height={24} />
          </Box>
          <Skeleton variant="text" width="40%" height={48} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="80%" height={20} />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card
      sx={{
        height: '100%',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.2s cubic-bezier(0.4, 0.0, 0.2, 1)', // Gmail-style smooth transitions
        position: 'relative',
        borderRadius: 2, // Standard theme border-radius
        border: 'none', // Remove solid border
        boxShadow:
          theme.palette.mode === 'light'
            ? '0 1px 2px 0 rgba(60, 64, 67, .3), 0 1px 3px 1px rgba(60, 64, 67, .15)'
            : '0 1px 2px 0 rgba(0, 0, 0, .3), 0 1px 3px 1px rgba(0, 0, 0, .15)',
        '&:hover': onClick
          ? {
              transform: 'translateY(-2px)',
              boxShadow:
                theme.palette.mode === 'light'
                  ? '0 1px 3px 0 rgba(60, 64, 67, .3), 0 4px 8px 3px rgba(60, 64, 67, .15)'
                  : '0 1px 3px 0 rgba(0, 0, 0, .3), 0 4px 8px 3px rgba(0, 0, 0, .15)',
            }
          : {
              boxShadow:
                theme.palette.mode === 'light'
                  ? '0 1px 3px 0 rgba(60, 64, 67, .3), 0 4px 8px 3px rgba(60, 64, 67, .15)'
                  : '0 1px 3px 0 rgba(0, 0, 0, .3), 0 4px 8px 3px rgba(0, 0, 0, .15)',
            },
      }}
      onClick={onClick}
    >
      <CardContent sx={{ p: config.padding, height: '100%' }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {icon && (
              <Box
                sx={{
                  width: config.iconSize,
                  height: config.iconSize,
                  borderRadius: '50%', // Gmail-style circular icon containers
                  backgroundColor: alpha(colorValue, 0.12),
                  color: colorValue,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.2s cubic-bezier(0.4, 0.0, 0.2, 1)',
                  '&:hover': {
                    backgroundColor: alpha(colorValue, 0.2),
                    transform: 'scale(1.05)',
                  },
                }}
              >
                {icon}
              </Box>
            )}
            <Typography variant={config.titleVariant} color="text.secondary" fontWeight={500}>
              {title}
            </Typography>
          </Box>
          {onMoreClick && (
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                onMoreClick();
              }}
              sx={{ opacity: 0.7, '&:hover': { opacity: 1 } }}
            >
              <MoreVert fontSize="small" />
            </IconButton>
          )}
        </Box>

        {/* Main Value */}
        <Typography
          variant={config.valueVariant}
          fontWeight="bold"
          color={colorValue}
          sx={{ mb: 1, lineHeight: 1.2 }}
        >
          {value}
        </Typography>

        {/* Subtitle and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {subtitle && (
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          )}
          {trend && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 'auto' }}>
              {getTrendIcon()}
              {trendValue && (
                <Typography variant="caption" color="text.secondary">
                  {trendValue}
                </Typography>
              )}
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default StatCard;
