import React from 'react';
import {
  Card,
  CardContent,
  CardActions,
  CardHeader,
  Typography,
  Button,
  Chip,
  Box,
  Stack,
  IconButton,
  Tooltip,
  useTheme,
  alpha,
  Avatar,
} from '@mui/material';
import {
  Computer as PlatformIcon,
  Visibility as BrowseIcon,
  GetApp as ExportIcon,
  Assessment as MetricsIcon,
  TrendingUp as TrendingIcon,
} from '@mui/icons-material';
import { PlatformStatistics } from '../../types/content.types';
import { CategoryBreakdown } from './CategoryBreakdown';

interface PlatformCardProps {
  platform: PlatformStatistics;
  onBrowse?: (platform: PlatformStatistics) => void;
  onExport?: (platform: PlatformStatistics) => void;
  onViewMetrics?: (platform: PlatformStatistics) => void;
  loading?: boolean;
}

export const PlatformCard: React.FC<PlatformCardProps> = ({
  platform,
  onBrowse,
  onExport,
  onViewMetrics,
  loading = false,
}) => {
  const theme = useTheme();

  // Get platform-specific icon and color
  const getPlatformAvatar = () => {
    const platformLower = platform.name.toLowerCase();
    
    let bgColor = theme.palette.primary.main;
    let icon = '🖥️';
    
    if (platformLower.includes('rhel') || platformLower.includes('red')) {
      bgColor = '#EE0000'; // Red Hat color
      icon = '🔴';
    } else if (platformLower.includes('ubuntu')) {
      bgColor = '#E95420'; // Ubuntu orange
      icon = '🟠';
    } else if (platformLower.includes('windows')) {
      bgColor = '#0078D4'; // Microsoft blue
      icon = '🪟';
    } else if (platformLower.includes('debian')) {
      bgColor = '#A81E35'; // Debian red
      icon = '🔺';
    } else if (platformLower.includes('centos')) {
      bgColor = '#262577'; // CentOS purple
      icon = '🟣';
    }
    
    return (
      <Avatar sx={{ bgcolor: bgColor, width: 48, height: 48 }}>
        <Typography fontSize="1.5rem">{icon}</Typography>
      </Avatar>
    );
  };

  // Get coverage color based on percentage
  const getCoverageColor = (coverage: number) => {
    if (coverage >= 80) return theme.palette.success.main;
    if (coverage >= 60) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const coverageColor = getCoverageColor(platform.coverage);

  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        transition: 'all 0.2s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: theme.shadows[8],
        },
        opacity: loading ? 0.7 : 1,
      }}
    >
      <CardHeader
        avatar={getPlatformAvatar()}
        title={
          <Box display="flex" alignItems="center" gap={1}>
            <Typography variant="h6" component="div">
              {platform.name}
            </Typography>
            <Chip 
              label={`v${platform.version}`} 
              size="small" 
              variant="outlined"
              sx={{ fontSize: '0.75rem' }}
            />
          </Box>
        }
        subheader={
          <Box display="flex" alignItems="center" gap={1} mt={0.5}>
            <Typography variant="body2" color="text.secondary">
              {platform.ruleCount.toLocaleString()} rules available
            </Typography>
            <Chip
              label={`${platform.coverage}% coverage`}
              size="small"
              sx={{
                backgroundColor: alpha(coverageColor, 0.1),
                color: coverageColor,
                fontWeight: 'bold',
                fontSize: '0.75rem',
              }}
            />
          </Box>
        }
        action={
          <Tooltip title="View detailed metrics">
            <span>
              <IconButton 
                size="small" 
                onClick={() => onViewMetrics?.(platform)}
                disabled={loading}
              >
                <MetricsIcon />
              </IconButton>
            </span>
          </Tooltip>
        }
      />

      <CardContent sx={{ flex: 1, pt: 0 }}>
        {/* Framework Support */}
        <Box mb={2}>
          <Typography variant="subtitle2" gutterBottom color="text.secondary">
            Compliance Frameworks
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {platform.frameworks.map((framework) => (
              <Chip
                key={framework}
                label={framework.toUpperCase()}
                size="small"
                variant="outlined"
                sx={{ 
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  fontWeight: 'bold',
                }}
              />
            ))}
          </Stack>
        </Box>

        {/* Category Breakdown */}
        <CategoryBreakdown
          categories={platform.categories}
          maxCategories={4}
          compact={false}
        />
      </CardContent>

      <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
        <Button
          variant="contained"
          startIcon={<BrowseIcon />}
          onClick={() => onBrowse?.(platform)}
          disabled={loading}
          sx={{ flex: 1, mr: 1 }}
        >
          Browse Rules
        </Button>
        
        <Tooltip title="Export rule list">
          <span>
            <IconButton
              onClick={() => onExport?.(platform)}
              disabled={loading}
              sx={{
                border: `1px solid ${theme.palette.divider}`,
                '&:hover': {
                  backgroundColor: alpha(theme.palette.primary.main, 0.08),
                },
              }}
            >
              <ExportIcon />
            </IconButton>
          </span>
        </Tooltip>
      </CardActions>

      {/* Platform Stats Footer */}
      <Box
        sx={{
          px: 2,
          py: 1,
          backgroundColor: alpha(theme.palette.primary.main, 0.02),
          borderTop: `1px solid ${theme.palette.divider}`,
        }}
      >
        <Stack direction="row" spacing={2} alignItems="center">
          <Box display="flex" alignItems="center" gap={0.5}>
            <TrendingIcon fontSize="small" color="action" />
            <Typography variant="caption" color="text.secondary">
              {platform.categories.length} categories
            </Typography>
          </Box>
          <Box display="flex" alignItems="center" gap={0.5}>
            <PlatformIcon fontSize="small" color="action" />
            <Typography variant="caption" color="text.secondary">
              Multi-version support
            </Typography>
          </Box>
        </Stack>
      </Box>
    </Card>
  );
};