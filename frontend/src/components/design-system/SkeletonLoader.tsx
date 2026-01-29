import React from 'react';
import { Box, Skeleton, useTheme, alpha, keyframes } from '@mui/material';
import Grid from '@mui/material/GridLegacy';

// Custom animations
const shimmer = keyframes`
  0% {
    background-position: -200px 0;
  }
  100% {
    background-position: calc(200px + 100%) 0;
  }
`;

const _pulse = keyframes`
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
`;

const wave = keyframes`
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
`;

export interface SkeletonLoaderProps {
  variant?: 'text' | 'rectangular' | 'circular' | 'card' | 'table' | 'list' | 'dashboard';
  width?: number | string;
  height?: number | string;
  animation?: 'pulse' | 'wave' | 'shimmer';
  count?: number;
  spacing?: number;
  className?: string;
}

const SkeletonLoader: React.FC<SkeletonLoaderProps> = ({
  variant = 'text',
  width,
  height,
  animation = 'pulse',
  count = 1,
  spacing = 2,
  className,
}) => {
  const theme = useTheme();

  const getAnimationStyle = () => {
    switch (animation) {
      case 'shimmer':
        return {
          background: `linear-gradient(90deg, 
            ${alpha(theme.palette.primary.main, 0.1)} 25%, 
            ${alpha(theme.palette.primary.main, 0.2)} 50%, 
            ${alpha(theme.palette.primary.main, 0.1)} 75%)`,
          backgroundSize: '200px 100%',
          animation: `${shimmer} 1.5s ease-in-out infinite`,
        };
      case 'wave':
        return {
          position: 'relative' as const,
          overflow: 'hidden',
          '&::after': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            background: `linear-gradient(90deg, 
              transparent, 
              ${alpha(theme.palette.primary.main, 0.3)}, 
              transparent)`,
            animation: `${wave} 1.5s ease-in-out infinite`,
          },
        };
      default:
        return {};
    }
  };

  const renderSkeleton = () => {
    const baseProps = {
      animation: animation === 'pulse' ? ('pulse' as const) : (false as const),
      sx: {
        borderRadius: theme.shape.borderRadius,
        ...getAnimationStyle(),
      },
    };

    switch (variant) {
      case 'card':
        return (
          <Box
            sx={{
              p: 3,
              border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
              borderRadius: theme.shape.borderRadius,
              backgroundColor: theme.palette.background.paper,
            }}
          >
            <Skeleton
              variant="rectangular"
              height={20}
              width="60%"
              {...baseProps}
              sx={{ mb: 2, ...baseProps.sx }}
            />
            <Skeleton
              variant="rectangular"
              height={16}
              width="100%"
              {...baseProps}
              sx={{ mb: 1, ...baseProps.sx }}
            />
            <Skeleton
              variant="rectangular"
              height={16}
              width="80%"
              {...baseProps}
              sx={{ mb: 1, ...baseProps.sx }}
            />
            <Skeleton variant="rectangular" height={16} width="90%" {...baseProps} />
          </Box>
        );

      case 'table':
        return (
          <Box>
            {/* Header */}
            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
              {[1, 2, 3, 4, 5].map((i) => (
                <Skeleton
                  key={i}
                  variant="rectangular"
                  height={20}
                  width={i === 1 ? '25%' : i === 2 ? '20%' : '15%'}
                  {...baseProps}
                />
              ))}
            </Box>
            {/* Rows */}
            {[1, 2, 3, 4, 5].map((row) => (
              <Box key={row} sx={{ display: 'flex', gap: 2, mb: 1 }}>
                {[1, 2, 3, 4, 5].map((col) => (
                  <Skeleton
                    key={col}
                    variant="rectangular"
                    height={16}
                    width={col === 1 ? '25%' : col === 2 ? '20%' : '15%'}
                    {...baseProps}
                  />
                ))}
              </Box>
            ))}
          </Box>
        );

      case 'list':
        return (
          <Box>
            {[1, 2, 3, 4].map((item) => (
              <Box key={item} sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Skeleton
                  variant="circular"
                  width={40}
                  height={40}
                  {...baseProps}
                  sx={{ mr: 2, ...baseProps.sx }}
                />
                <Box sx={{ flexGrow: 1 }}>
                  <Skeleton
                    variant="rectangular"
                    height={16}
                    width="70%"
                    {...baseProps}
                    sx={{ mb: 1, ...baseProps.sx }}
                  />
                  <Skeleton variant="rectangular" height={12} width="50%" {...baseProps} />
                </Box>
                <Skeleton variant="rectangular" height={20} width={60} {...baseProps} />
              </Box>
            ))}
          </Box>
        );

      case 'dashboard':
        return (
          <Box>
            {/* Header */}
            <Box sx={{ mb: 4 }}>
              <Skeleton
                variant="rectangular"
                height={32}
                width="40%"
                {...baseProps}
                sx={{ mb: 2, ...baseProps.sx }}
              />
              <Skeleton variant="rectangular" height={20} width="60%" {...baseProps} />
            </Box>
            {/* Stats Grid */}
            <Box sx={{ mb: 4 }}>
              <Grid container spacing={3}>
                {[1, 2, 3, 4].map((stat) => (
                  <Grid item xs={12} sm={6} md={3} key={stat}>
                    <Box
                      sx={{
                        p: 3,
                        border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                        borderRadius: theme.shape.borderRadius,
                        backgroundColor: theme.palette.background.paper,
                        textAlign: 'center',
                      }}
                    >
                      <Skeleton
                        variant="circular"
                        width={48}
                        height={48}
                        {...baseProps}
                        sx={{ mx: 'auto', mb: 2, ...baseProps.sx }}
                      />
                      <Skeleton
                        variant="rectangular"
                        height={24}
                        width="80%"
                        {...baseProps}
                        sx={{ mx: 'auto', mb: 1, ...baseProps.sx }}
                      />
                      <Skeleton
                        variant="rectangular"
                        height={16}
                        width="60%"
                        {...baseProps}
                        sx={{ mx: 'auto', ...baseProps.sx }}
                      />
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Box>
            {/* Content Grid */}
            <Grid container spacing={3}>
              <Grid item xs={12} lg={8}>
                <Skeleton variant="rectangular" height={300} {...baseProps} />
              </Grid>
              <Grid item xs={12} lg={4}>
                <Skeleton variant="rectangular" height={300} {...baseProps} />
              </Grid>
            </Grid>
          </Box>
        );

      default:
        return <Skeleton variant={variant} width={width} height={height} {...baseProps} />;
    }
  };

  if (count === 1) {
    return <Box className={className}>{renderSkeleton()}</Box>;
  }

  return (
    <Box className={className}>
      {Array.from({ length: count }).map((_, index) => (
        <Box key={index} sx={{ mb: index < count - 1 ? spacing : 0 }}>
          {renderSkeleton()}
        </Box>
      ))}
    </Box>
  );
};

export default SkeletonLoader;
