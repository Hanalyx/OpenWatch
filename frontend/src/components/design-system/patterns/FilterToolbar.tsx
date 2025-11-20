import React from 'react';
import {
  Box,
  TextField,
  InputAdornment,
  ToggleButton,
  ToggleButtonGroup,
  IconButton,
  Badge,
  Chip,
} from '@mui/material';
import { Search, FilterList, ViewModule, ViewList, ViewCompact } from '@mui/icons-material';

export type ViewMode = 'grid' | 'list' | 'compact';
export type GroupBy = 'none' | string;

interface FilterToolbarProps {
  // Search
  searchQuery?: string;
  onSearchChange?: (query: string) => void;
  searchPlaceholder?: string;

  // View Mode
  viewMode?: ViewMode;
  onViewModeChange?: (mode: ViewMode) => void;
  showViewMode?: boolean;

  // Grouping
  groupBy?: GroupBy;
  onGroupByChange?: (group: GroupBy) => void;
  groupOptions?: { value: string; label: string }[];
  showGrouping?: boolean;

  // Filters
  filterCount?: number;
  onFilterClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  showFilters?: boolean;

  // Selection
  selectedCount?: number;
  onClearSelection?: () => void;
  bulkActions?: React.ReactNode;

  // Custom actions
  actions?: React.ReactNode;
}

const FilterToolbar: React.FC<FilterToolbarProps> = ({
  searchQuery = '',
  onSearchChange,
  searchPlaceholder = 'Search...',
  viewMode = 'grid',
  onViewModeChange,
  showViewMode = true,
  groupBy = 'none',
  onGroupByChange,
  groupOptions = [],
  showGrouping = true,
  filterCount = 0,
  onFilterClick,
  showFilters = true,
  selectedCount = 0,
  onClearSelection,
  bulkActions,
  actions,
}) => {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
      {/* Search */}
      <TextField
        placeholder={searchPlaceholder}
        variant="outlined"
        size="small"
        value={searchQuery}
        onChange={(e) => onSearchChange?.(e.target.value)}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <Search />
            </InputAdornment>
          ),
        }}
        sx={{ minWidth: 300 }}
      />

      {/* View Mode */}
      {showViewMode && onViewModeChange && (
        <ToggleButtonGroup
          value={viewMode}
          exclusive
          onChange={(e, newMode) => newMode && onViewModeChange(newMode)}
          size="small"
        >
          <ToggleButton value="grid" aria-label="grid view">
            <ViewModule />
          </ToggleButton>
          <ToggleButton value="list" aria-label="list view">
            <ViewList />
          </ToggleButton>
          <ToggleButton value="compact" aria-label="compact view">
            <ViewCompact />
          </ToggleButton>
        </ToggleButtonGroup>
      )}

      {/* Grouping */}
      {showGrouping && onGroupByChange && groupOptions.length > 0 && (
        <ToggleButtonGroup
          value={groupBy}
          exclusive
          onChange={(e, newGroup) => newGroup !== null && onGroupByChange(newGroup)}
          size="small"
        >
          {groupOptions.map((option) => (
            <ToggleButton key={option.value} value={option.value}>
              {option.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      )}

      {/* Spacer */}
      <Box sx={{ flexGrow: 1 }} />

      {/* Bulk Actions */}
      {selectedCount > 0 && (
        <>
          <Chip
            label={`${selectedCount} selected`}
            onDelete={onClearSelection}
            color="primary"
            variant="outlined"
          />
          {bulkActions}
        </>
      )}

      {/* Custom Actions */}
      {actions}

      {/* Filter */}
      {showFilters && onFilterClick && (
        <IconButton
          onClick={onFilterClick}
          color={filterCount > 0 ? 'primary' : 'default'}
          aria-label="filters"
        >
          <Badge badgeContent={filterCount} color="primary">
            <FilterList />
          </Badge>
        </IconButton>
      )}
    </Box>
  );
};

export default FilterToolbar;
