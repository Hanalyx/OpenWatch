import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Skeleton,
  Pagination,
  Alert,
  AlertTitle,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
  Snackbar,
  IconButton,
  Fab,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Close as CloseIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState, AppDispatch } from '../../store';
import {
  selectRule,
  setViewMode,
  setSearchQuery,
  updateFilters,
  clearFilters,
  setPagination,
  clearError,
  Rule,
} from '../../store/slices/ruleSlice';
import { ruleService } from '../../services/ruleService';
import RuleCard from './RuleCard';
import RuleFilterToolbar from './RuleFilterToolbar';
import RuleDetailDialog from './RuleDetailDialog';
import RuleDependencyDialog from './RuleDependencyDialog';
import EmptyState from '../design-system/patterns/EmptyState';

interface RulesExplorerProps {
  contentId?: string; // Optional: filter by specific content
  onRuleSelect?: (rule: Rule) => void; // Optional: callback when rule is selected
}

const RulesExplorer: React.FC<RulesExplorerProps> = ({
  contentId,
  onRuleSelect,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch<AppDispatch>();
  
  // Redux state
  const {
    rules,
    filteredRules,
    selectedRule,
    searchQuery,
    searchResults,
    activeFilters,
    viewMode,
    isLoading,
    isSearching,
    error,
    pagination,
    availablePlatforms,
    availableCategories,
    availableFrameworks,
  } = useSelector((state: RootState) => state.rules);

  // Local state
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [dependencyDialogOpen, setDependencyDialogOpen] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [exportLoading, setExportLoading] = useState(false);

  // Initial load
  useEffect(() => {
    loadRules();
  }, []);

  // Load rules function
  const loadRules = async () => {
    try {
      const rulesData = await ruleService.getRules({
        offset: pagination.offset,
        limit: pagination.limit,
        ...activeFilters,
      });
      // Handle rules data - this would typically update the store
    } catch (error) {
      console.error('Error loading rules:', error);
    }
  };

  // Handle refresh
  const handleRefresh = useCallback(() => {
    dispatch(fetchRules({
      offset: pagination.offset,
      limit: pagination.limit,
      ...activeFilters,
    }));
  }, [pagination, activeFilters, dispatch]);

  // Search function
  const performSearch = async (searchParams: any) => {
    try {
      const searchResults = await ruleService.searchRules(searchParams);
      // Handle search results
    } catch (error) {
      console.error('Error searching rules:', error);
    }
  };

  // Handle search
  const handleSearch = useCallback((query: string) => {
    dispatch(setSearchQuery(query));
    if (query) {
      performSearch({
        query,
        filters: {
          platform: activeFilters.platforms?.length > 0 ? activeFilters.platforms : undefined,
          severity: activeFilters.severities?.length > 0 ? activeFilters.severities : undefined,
          category: activeFilters.categories.length > 0 ? activeFilters.categories : undefined,
          framework: activeFilters.frameworks.length > 0 ? activeFilters.frameworks : undefined,
        },
        limit: 50,
      });
    } else {
      // Clear search and reload regular rules
      handleRefresh();
    }
  }, [activeFilters, dispatch, handleRefresh]);

  // Handle filter changes
  const handleFilterChange = useCallback((filters: any) => {
    dispatch(updateFilters(filters));
    dispatch(setPagination({ offset: 0, limit: pagination.limit }));

    // Reload rules with new filters
    dispatch(fetchRules({
      offset: 0,
      limit: pagination.limit,
      ...activeFilters,
      ...filters,
    }));
  }, [activeFilters, pagination.limit, dispatch]);

  // Handle rule selection
  const handleRuleSelect = useCallback(async (rule: Rule) => {
    dispatch(selectRule(rule));
    setSelectedRuleId(rule.rule_id);
    
    // Fetch detailed rule information
    await dispatch(fetchRuleDetails({
      ruleId: rule.rule_id,
      includeInheritance: true,
    }));
    
    setDetailDialogOpen(true);
    
    // Call external callback if provided
    if (onRuleSelect) {
      onRuleSelect(rule);
    }
  }, [dispatch, onRuleSelect]);

  // Handle dependency view
  const handleViewDependencies = useCallback(async (ruleId: string) => {
    setSelectedRuleId(ruleId);
    
    await dispatch(fetchRuleDependencies({
      ruleIds: [ruleId],
      includeTransitive: true,
      maxDepth: 5,
    }));
    
    setDependencyDialogOpen(true);
  }, [dispatch]);

  // Handle pagination
  const handlePageChange = (event: React.ChangeEvent<unknown>, page: number) => {
    const newOffset = (page - 1) * pagination.limit;
    dispatch(setPagination({ offset: newOffset, limit: pagination.limit }));
    
    dispatch(fetchRules({
      offset: newOffset,
      limit: pagination.limit,
      ...activeFilters,
    }));
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Handle export
  const handleExport = async (format: 'json' | 'csv' | 'xml') => {
    setExportLoading(true);
    try {
      const ruleIds = searchQuery ? searchResults.map(r => r.rule_id) : filteredRules.map(r => r.rule_id);
      
      if (ruleIds.length === 0) {
        setSnackbarMessage('No rules to export');
        return;
      }
      
      const response = await dispatch(exportRules({
        ruleIds: ruleIds.slice(0, 1000), // Limit to 1000 rules
        format,
        includeMetadata: true,
      })).unwrap();
      
      // Create download link
      const blob = new Blob([
        format === 'json' ? JSON.stringify(response.data, null, 2) : response.data
      ], {
        type: format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'application/xml'
      });
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `openwatch-rules-${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      setSnackbarMessage(`Successfully exported ${ruleIds.length} rules`);
    } catch (error) {
      setSnackbarMessage('Failed to export rules');
    } finally {
      setExportLoading(false);
    }
  };

  // Determine which rules to display
  const displayRules = searchQuery && searchResults.length > 0 ? searchResults : filteredRules;
  const totalCount = searchQuery ? searchResults.length : pagination.totalCount;
  const currentPage = Math.floor(pagination.offset / pagination.limit) + 1;
  const totalPages = Math.ceil(totalCount / pagination.limit);

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Filter Toolbar */}
      <Box mb={3}>
        <RuleFilterToolbar
          searchQuery={searchQuery}
          onSearchChange={handleSearch}
          filters={activeFilters}
          onFiltersChange={handleFilterChange}
          onClearFilters={() => {
            dispatch(clearFilters());
            handleRefresh();
          }}
          viewMode={viewMode}
          onViewModeChange={(mode) => dispatch(setViewMode(mode))}
          availablePlatforms={availablePlatforms}
          availableCategories={availableCategories}
          availableFrameworks={availableFrameworks}
          onRefresh={handleRefresh}
          isLoading={isLoading}
          totalResults={totalCount}
        />
      </Box>

      {/* Error Display */}
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 2 }}
          action={
            <IconButton
              aria-label="close"
              color="inherit"
              size="small"
              onClick={() => dispatch(clearError())}
            >
              <CloseIcon fontSize="inherit" />
            </IconButton>
          }
        >
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {/* Loading Progress */}
      {(isLoading || isSearching) && (
        <Box sx={{ width: '100%', mb: 2 }}>
          <LinearProgress />
        </Box>
      )}

      {/* Rules Display */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {!isLoading && displayRules.length === 0 ? (
          <EmptyState
            icon={searchQuery ? SearchIcon : FilterIcon}
            title={searchQuery ? 'No rules found' : 'No rules available'}
            description={
              searchQuery
                ? `No rules match your search for "${searchQuery}"`
                : activeFilters && Object.values(activeFilters).some(f => 
                    Array.isArray(f) ? f.length > 0 : f !== null
                  )
                ? 'No rules match the selected filters'
                : 'No rules have been imported yet'
            }
            action={
              searchQuery || Object.values(activeFilters).some(f => 
                Array.isArray(f) ? f.length > 0 : f !== null
              ) ? (
                <Button
                  variant="contained"
                  onClick={() => {
                    dispatch(clearFilters());
                    dispatch(setSearchQuery(''));
                    handleRefresh();
                  }}
                >
                  Clear Filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            {/* Grid/List View */}
            {viewMode !== 'tree' ? (
              <Grid
                container
                spacing={viewMode === 'grid' ? 2 : 0}
                sx={{
                  ...(viewMode === 'list' && {
                    display: 'block',
                  }),
                }}
              >
                {isLoading
                  ? Array.from({ length: 8 }).map((_, index) => (
                      <Grid
                        item
                        xs={12}
                        sm={viewMode === 'grid' ? 6 : 12}
                        lg={viewMode === 'grid' ? 4 : 12}
                        key={`skeleton-${index}`}
                      >
                        <Skeleton
                          variant="rectangular"
                          height={viewMode === 'grid' ? 280 : 120}
                          sx={{ borderRadius: 1 }}
                        />
                      </Grid>
                    ))
                  : displayRules.map((rule) => (
                      <Grid
                        item
                        xs={12}
                        sm={viewMode === 'grid' ? 6 : 12}
                        lg={viewMode === 'grid' ? 4 : 12}
                        key={rule.rule_id}
                      >
                        <RuleCard
                          rule={rule}
                          viewMode={viewMode}
                          onSelect={handleRuleSelect}
                          onViewDependencies={handleViewDependencies}
                          selected={selectedRule?.rule_id === rule.rule_id}
                          showRelevance={!!searchQuery && !!rule.relevance_score}
                        />
                      </Grid>
                    ))}
              </Grid>
            ) : (
              // Tree View (placeholder)
              <Paper sx={{ p: 4, textAlign: 'center' }}>
                <Typography variant="h6" color="text.secondary">
                  Tree view coming soon
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  This view will show rules organized by category and inheritance
                </Typography>
              </Paper>
            )}

            {/* Pagination */}
            {!searchQuery && totalPages > 1 && (
              <Box display="flex" justifyContent="center" mt={4} mb={2}>
                <Pagination
                  count={totalPages}
                  page={currentPage}
                  onChange={handlePageChange}
                  color="primary"
                  showFirstButton
                  showLastButton
                />
              </Box>
            )}
          </>
        )}
      </Box>

      {/* Floating Action Button for Export */}
      <Box sx={{ position: 'fixed', bottom: 24, right: 24 }}>
        <Fab
          color="primary"
          aria-label="export"
          onClick={() => handleExport('json')}
          disabled={exportLoading || displayRules.length === 0}
        >
          <DownloadIcon />
        </Fab>
      </Box>

      {/* Dialogs */}
      {selectedRule && (
        <RuleDetailDialog
          open={detailDialogOpen}
          onClose={() => setDetailDialogOpen(false)}
          rule={selectedRule}
        />
      )}

      <RuleDependencyDialog
        open={dependencyDialogOpen}
        onClose={() => setDependencyDialogOpen(false)}
        ruleId={selectedRuleId || ''}
      />

      {/* Snackbar for notifications */}
      <Snackbar
        open={!!snackbarMessage}
        autoHideDuration={6000}
        onClose={() => setSnackbarMessage('')}
        message={snackbarMessage}
      />
    </Box>
  );
};

export default RulesExplorer;