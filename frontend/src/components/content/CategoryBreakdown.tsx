import React from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Stack,
  Chip,
  useTheme,
  alpha,
  Tooltip,
} from '@mui/material';
import { CategoryCount } from '../../types/content.types';

interface CategoryBreakdownProps {
  categories: CategoryCount[];
  maxCategories?: number;
  showPercentages?: boolean;
  compact?: boolean;
}

export const CategoryBreakdown: React.FC<CategoryBreakdownProps> = ({
  categories,
  maxCategories = 6,
  showPercentages = true,
  compact = false,
}) => {
  const theme = useTheme();

  // Color palette for different categories
  const getCategoryColor = (index: number) => {
    const colors = [
      theme.palette.primary.main,
      theme.palette.secondary.main,
      theme.palette.success.main,
      theme.palette.warning.main,
      theme.palette.info.main,
      theme.palette.error.main,
    ];
    return colors[index % colors.length];
  };

  // Sort categories by count and limit display
  const displayCategories = categories
    .sort((a, b) => b.count - a.count)
    .slice(0, maxCategories);

  const otherCount = categories
    .slice(maxCategories)
    .reduce((sum, cat) => sum + cat.count, 0);

  if (compact) {
    return (
      <Stack direction="row" spacing={1} flexWrap="wrap">
        {displayCategories.map((category, index) => (
          <Tooltip
            key={category.name}
            title={`${category.count} rules (${category.percentage}%)`}
            arrow
          >
            <Chip
              label={`${category.name} (${category.count})`}
              size="small"
              sx={{
                backgroundColor: alpha(getCategoryColor(index), 0.1),
                color: getCategoryColor(index),
                border: `1px solid ${alpha(getCategoryColor(index), 0.3)}`,
                fontSize: '0.75rem',
              }}
            />
          </Tooltip>
        ))}
        {otherCount > 0 && (
          <Tooltip title={`${otherCount} rules in other categories`} arrow>
            <Chip
              label={`+${otherCount} other`}
              size="small"
              variant="outlined"
              sx={{ fontSize: '0.75rem' }}
            />
          </Tooltip>
        )}
      </Stack>
    );
  }

  return (
    <Box>
      <Typography variant="subtitle2" gutterBottom color="text.secondary">
        Rule Categories
      </Typography>
      
      <Stack spacing={1.5}>
        {displayCategories.map((category, index) => {
          const color = getCategoryColor(index);
          
          return (
            <Box key={category.name}>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={0.5}>
                <Typography variant="body2" fontWeight="medium">
                  {category.name}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {category.count} rules
                  {showPercentages && ` (${category.percentage}%)`}
                </Typography>
              </Box>
              
              <LinearProgress
                variant="determinate"
                value={category.percentage}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: alpha(color, 0.1),
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: color,
                    borderRadius: 3,
                  },
                }}
              />
            </Box>
          );
        })}
        
        {otherCount > 0 && (
          <Box>
            <Typography variant="caption" color="text.secondary">
              +{otherCount} rules in other categories
            </Typography>
          </Box>
        )}
      </Stack>
      
      {categories.length === 0 && (
        <Typography variant="body2" color="text.secondary" fontStyle="italic">
          No category breakdown available
        </Typography>
      )}
    </Box>
  );
};