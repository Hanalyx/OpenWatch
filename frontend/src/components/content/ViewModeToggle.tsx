import React from 'react';
import { ToggleButton, ToggleButtonGroup, Box, Tooltip, useTheme, alpha } from '@mui/material';
import {
  Computer as PlatformIcon,
  AccountTree as FrameworkIcon,
  Category as CategoryIcon,
  List as ListIcon,
} from '@mui/icons-material';

export type ViewMode = 'platform' | 'framework' | 'category' | 'all';

interface ViewModeToggleProps {
  value: ViewMode;
  onChange: (mode: ViewMode) => void;
  disabled?: boolean;
}

export const ViewModeToggle: React.FC<ViewModeToggleProps> = ({
  value,
  onChange,
  disabled = false,
}) => {
  const theme = useTheme();

  const handleChange = (event: React.MouseEvent<HTMLElement>, newMode: ViewMode | null) => {
    if (newMode !== null) {
      onChange(newMode);
    }
  };

  const viewOptions = [
    {
      value: 'platform' as ViewMode,
      icon: <PlatformIcon />,
      label: 'By Platform',
      tooltip: 'Organize rules by operating system and version',
    },
    {
      value: 'framework' as ViewMode,
      icon: <FrameworkIcon />,
      label: 'By Framework',
      tooltip: 'Organize rules by compliance framework (NIST, CIS, etc.)',
    },
    {
      value: 'category' as ViewMode,
      icon: <CategoryIcon />,
      label: 'By Category',
      tooltip: 'Organize rules by security category',
    },
    {
      value: 'all' as ViewMode,
      icon: <ListIcon />,
      label: 'All Rules',
      tooltip: 'View all rules in a single list',
    },
  ];

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      <ToggleButtonGroup
        value={value}
        exclusive
        onChange={handleChange}
        aria-label="rule view mode"
        disabled={disabled}
        sx={{
          backgroundColor: theme.palette.background.paper,
          border: `1px solid ${theme.palette.divider}`,
          borderRadius: 1,
          '& .MuiToggleButton-root': {
            px: 2,
            py: 1,
            textTransform: 'none',
            fontSize: '0.875rem',
            fontWeight: 500,
            color: theme.palette.text.secondary,
            border: 'none',
            borderRadius: 1,
            '&:hover': {
              backgroundColor: alpha(theme.palette.primary.main, 0.08),
            },
            '&.Mui-selected': {
              backgroundColor: alpha(theme.palette.primary.main, 0.12),
              color: theme.palette.primary.main,
              '&:hover': {
                backgroundColor: alpha(theme.palette.primary.main, 0.16),
              },
            },
            '&:not(:last-child)': {
              borderRight: `1px solid ${theme.palette.divider}`,
              borderRadius: 0,
              '&:first-of-type': {
                borderTopLeftRadius: theme.shape.borderRadius,
                borderBottomLeftRadius: theme.shape.borderRadius,
              },
            },
            '&:last-child': {
              borderTopRightRadius: theme.shape.borderRadius,
              borderBottomRightRadius: theme.shape.borderRadius,
            },
          },
        }}
      >
        {viewOptions.map((option) => (
          <Tooltip key={option.value} title={option.tooltip} arrow>
            <span>
              <ToggleButton value={option.value} aria-label={option.label}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {option.icon}
                  <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                    {option.label}
                  </Box>
                </Box>
              </ToggleButton>
            </span>
          </Tooltip>
        ))}
      </ToggleButtonGroup>
    </Box>
  );
};
