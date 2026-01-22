import React, { useState, useMemo } from 'react';
import {
  Box,
  Paper,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Stack,
  IconButton,
  Tooltip,
  Badge,
  Typography,
  FormControlLabel,
  Checkbox,
  Button,
  Collapse,
  useTheme,
  alpha,
} from '@mui/material';
import {
  FilterList as FilterIcon,
  ViewModule as GridIcon,
  ViewList as ListIcon,
  AccountTree as TreeIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { type FilterState } from '../../store/slices/ruleSlice';
import EnhancedSearchInput, { type SearchSuggestion } from './EnhancedSearchInput';

interface RuleFilterToolbarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onSearchSuggestionSelect?: (suggestion: SearchSuggestion) => void;
  filters: FilterState;
  onFiltersChange: (filters: Partial<FilterState>) => void;
  onClearFilters: () => void;
  viewMode: 'grid' | 'list' | 'tree';
  onViewModeChange: (mode: 'grid' | 'list' | 'tree') => void;
  availablePlatforms: string[];
  availableCategories: string[];
  availableFrameworks: string[];
  onRefresh?: () => void;
  isLoading?: boolean;
  totalResults?: number;
  showAdvancedFilters?: boolean;
}

const RuleFilterToolbar: React.FC<RuleFilterToolbarProps> = ({
  searchQuery,
  onSearchChange,
  onSearchSuggestionSelect,
  filters,
  onFiltersChange,
  onClearFilters,
  viewMode,
  onViewModeChange,
  availablePlatforms,
  availableCategories,
  availableFrameworks,
  onRefresh,
  isLoading = false,
  totalResults,
  showAdvancedFilters = true,
}) => {
  const theme = useTheme();
  const [expandedFilters, setExpandedFilters] = useState(false);

  const activeFilterCount = [
    filters.platforms.length,
    filters.severities.length,
    filters.categories.length,
    filters.frameworks.length,
    filters.tags.length,
    filters.abstract !== null ? 1 : 0,
  ].reduce((sum, count) => sum + count, 0);

  const severityOptions = ['high', 'medium', 'low', 'info'];

  // Handle filter changes - value type depends on which filter is being changed
  // Array filters (platforms, severities, etc.) accept string[], abstract accepts boolean | null
  const handleFilterChange = (filterType: keyof FilterState, value: string[] | boolean | null) => {
    onFiltersChange({ [filterType]: value });
  };

  const handleRemoveFilter = (filterType: keyof FilterState, value: string) => {
    const currentValues = filters[filterType] as string[];
    onFiltersChange({
      [filterType]: currentValues.filter((v) => v !== value),
    });
  };

  const QuickFilters = useMemo(() => {
    const QuickFiltersComponent = () => (
      <Stack direction="row" spacing={1} alignItems="center">
        <Chip
          label="High Priority"
          size="small"
          variant={filters.severities.includes('high') ? 'filled' : 'outlined'}
          color={filters.severities.includes('high') ? 'error' : 'default'}
          onClick={() => {
            const newSeverities = filters.severities.includes('high')
              ? filters.severities.filter((s) => s !== 'high')
              : [...filters.severities, 'high'];
            handleFilterChange('severities', newSeverities);
          }}
        />
        <Chip
          label="Recently Updated"
          size="small"
          variant="outlined"
          onClick={() => {
            // This would trigger a sort by updated date
          }}
        />
        <Chip
          label="Has Dependencies"
          size="small"
          variant="outlined"
          onClick={() => {
            // This would filter rules with dependencies
          }}
        />
      </Stack>
    );
    QuickFiltersComponent.displayName = 'QuickFilters';
    return QuickFiltersComponent;
  }, [filters.severities, handleFilterChange]);

  return (
    <Paper
      elevation={0}
      sx={{
        p: 2,
        borderRadius: 2,
        backgroundColor: alpha(theme.palette.background.paper, 0.8),
        backdropFilter: 'blur(8px)',
        border: `1px solid ${theme.palette.divider}`,
      }}
    >
      {/* Main Toolbar */}
      <Box display="flex" alignItems="center" gap={2} mb={expandedFilters ? 2 : 0}>
        {/* Enhanced Search Bar */}
        <EnhancedSearchInput
          value={searchQuery}
          onChange={onSearchChange}
          onSuggestionSelect={onSearchSuggestionSelect}
          placeholder="Search rules, tags, categories, or frameworks..."
          disabled={isLoading}
          showHistory={true}
          showSavedSearches={true}
        />

        {/* Quick Filters */}
        <Box sx={{ display: { xs: 'none', md: 'flex' } }}>
          <QuickFilters />
        </Box>

        {/* Filter Toggle */}
        <Tooltip title={expandedFilters ? 'Hide filters' : 'Show filters'}>
          <IconButton
            onClick={() => setExpandedFilters(!expandedFilters)}
            color={activeFilterCount > 0 ? 'primary' : 'default'}
          >
            <Badge badgeContent={activeFilterCount} color="primary">
              <FilterIcon />
            </Badge>
          </IconButton>
        </Tooltip>

        {/* View Mode Toggle */}
        <Box sx={{ borderLeft: `1px solid ${theme.palette.divider}`, pl: 1 }}>
          <Tooltip title="Grid view">
            <IconButton
              size="small"
              onClick={() => onViewModeChange('grid')}
              color={viewMode === 'grid' ? 'primary' : 'default'}
            >
              <GridIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="List view">
            <IconButton
              size="small"
              onClick={() => onViewModeChange('list')}
              color={viewMode === 'list' ? 'primary' : 'default'}
            >
              <ListIcon />
            </IconButton>
          </Tooltip>
          {showAdvancedFilters && (
            <Tooltip title="Tree view">
              <IconButton
                size="small"
                onClick={() => onViewModeChange('tree')}
                color={viewMode === 'tree' ? 'primary' : 'default'}
              >
                <TreeIcon />
              </IconButton>
            </Tooltip>
          )}
        </Box>

        {/* Refresh */}
        {onRefresh && (
          <Tooltip title="Refresh rules">
            <IconButton onClick={onRefresh} disabled={isLoading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      {/* Mobile Quick Filters */}
      <Box sx={{ display: { xs: 'flex', md: 'none' }, mb: 2 }}>
        <QuickFilters />
      </Box>

      {/* Expanded Filters */}
      <Collapse in={expandedFilters}>
        <Box>
          {/* Active Filters Display */}
          {activeFilterCount > 0 && (
            <Box mb={2}>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="subtitle2" color="text.secondary">
                  Active Filters ({activeFilterCount})
                </Typography>
                <Button size="small" onClick={onClearFilters}>
                  Clear All
                </Button>
              </Box>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                {/* Platform filters */}
                {filters.platforms.map((platform) => (
                  <Chip
                    key={`platform-${platform}`}
                    label={`Platform: ${platform}`}
                    size="small"
                    onDelete={() => handleRemoveFilter('platforms', platform)}
                  />
                ))}

                {/* Severity filters */}
                {filters.severities.map((severity) => (
                  <Chip
                    key={`severity-${severity}`}
                    label={`Severity: ${severity}`}
                    size="small"
                    color={
                      severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'default'
                    }
                    onDelete={() => handleRemoveFilter('severities', severity)}
                  />
                ))}

                {/* Category filters */}
                {filters.categories.map((category) => (
                  <Chip
                    key={`category-${category}`}
                    label={`Category: ${category}`}
                    size="small"
                    onDelete={() => handleRemoveFilter('categories', category)}
                  />
                ))}

                {/* Framework filters */}
                {filters.frameworks.map((framework) => (
                  <Chip
                    key={`framework-${framework}`}
                    label={`Framework: ${framework}`}
                    size="small"
                    onDelete={() => handleRemoveFilter('frameworks', framework)}
                  />
                ))}

                {/* Abstract filter */}
                {filters.abstract !== null && (
                  <Chip
                    label={filters.abstract ? 'Abstract rules only' : 'Concrete rules only'}
                    size="small"
                    onDelete={() => handleFilterChange('abstract', null)}
                  />
                )}
              </Stack>
            </Box>
          )}

          {/* Filter Controls */}
          <Box display="grid" gridTemplateColumns="repeat(auto-fit, minmax(200px, 1fr))" gap={2}>
            {/* Platform Filter */}
            <FormControl size="small" fullWidth>
              <InputLabel>Platforms</InputLabel>
              <Select
                multiple
                value={filters.platforms}
                onChange={(e) => handleFilterChange('platforms', e.target.value)}
                renderValue={(selected) => `${selected.length} selected`}
              >
                {availablePlatforms.map((platform) => (
                  <MenuItem key={platform} value={platform}>
                    <Checkbox checked={filters.platforms.includes(platform)} />
                    {platform}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            {/* Severity Filter */}
            <FormControl size="small" fullWidth>
              <InputLabel>Severities</InputLabel>
              <Select
                multiple
                value={filters.severities}
                onChange={(e) => handleFilterChange('severities', e.target.value)}
                renderValue={(selected) => `${selected.length} selected`}
              >
                {severityOptions.map((severity) => (
                  <MenuItem key={severity} value={severity}>
                    <Checkbox checked={filters.severities.includes(severity)} />
                    {severity.charAt(0).toUpperCase() + severity.slice(1)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            {/* Category Filter */}
            <FormControl size="small" fullWidth>
              <InputLabel>Categories</InputLabel>
              <Select
                multiple
                value={filters.categories}
                onChange={(e) => handleFilterChange('categories', e.target.value)}
                renderValue={(selected) => `${selected.length} selected`}
              >
                {availableCategories.map((category) => (
                  <MenuItem key={category} value={category}>
                    <Checkbox checked={filters.categories.includes(category)} />
                    {category
                      .split('_')
                      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
                      .join(' ')}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            {/* Framework Filter */}
            <FormControl size="small" fullWidth>
              <InputLabel>Frameworks</InputLabel>
              <Select
                multiple
                value={filters.frameworks}
                onChange={(e) => handleFilterChange('frameworks', e.target.value)}
                renderValue={(selected) => `${selected.length} selected`}
              >
                {availableFrameworks.map((framework) => (
                  <MenuItem key={framework} value={framework}>
                    <Checkbox checked={filters.frameworks.includes(framework)} />
                    {framework.toUpperCase()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>

          {/* Advanced Options */}
          {showAdvancedFilters && (
            <Box mt={2}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={filters.abstract === true}
                    indeterminate={filters.abstract === null}
                    onChange={() => {
                      if (filters.abstract === null) {
                        handleFilterChange('abstract', false);
                      } else if (filters.abstract === false) {
                        handleFilterChange('abstract', true);
                      } else {
                        handleFilterChange('abstract', null);
                      }
                    }}
                  />
                }
                label="Show abstract rules"
              />
            </Box>
          )}

          {/* Results Count */}
          {totalResults !== undefined && (
            <Box mt={2}>
              <Typography variant="body2" color="text.secondary">
                {totalResults} {totalResults === 1 ? 'rule' : 'rules'} found
              </Typography>
            </Box>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
};

export default RuleFilterToolbar;
