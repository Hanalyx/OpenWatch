import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Grid,
  Skeleton,
  Pagination,
  Alert,
  AlertTitle,
  LinearProgress,
  Snackbar,
  IconButton,
  Fab,
  Stack,
  useTheme,
} from '@mui/material';
import {
  Download as DownloadIcon,
  Close as CloseIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  PlayArrow as ScanIcon,
} from '@mui/icons-material';
import { type Rule, type FilterState } from '../../store/slices/ruleSlice';
import { ruleService } from '../../services/ruleService';
import RuleCard from './RuleCard';
import RuleFilterToolbar from './RuleFilterToolbar';
import RuleDetailDialog from './RuleDetailDialog';
import EnhancedDependencyDialog from './EnhancedDependencyDialog';
import EmptyState from '../design-system/patterns/EmptyState';
import { type SearchSuggestion } from './EnhancedSearchInput';
import ScannerRuleSelection from '../scanner/ScannerRuleSelection';
import RuleIntelligencePanel from './RuleIntelligencePanel';

interface RulesExplorerProps {
  contentId?: string;
  onRuleSelect?: (rule: Rule) => void;
}

const RulesExplorerSimplified: React.FC<RulesExplorerProps> = ({ onRuleSelect }) => {
  const theme = useTheme();

  // Local state
  const [rules, setRules] = useState<Rule[]>([]);
  const [filteredRules, setFilteredRules] = useState<Rule[]>([]);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [searchQuery, setSearchQueryState] = useState('');
  const [searchResults, setSearchResults] = useState<Rule[]>([]);
  const [activeFilters, setActiveFilters] = useState<FilterState>({
    platforms: [],
    severities: [],
    categories: [],
    frameworks: [],
    tags: [],
    abstract: null,
  });
  const [viewMode, setViewModeState] = useState<'grid' | 'list' | 'tree'>('grid');
  const [isLoading, setIsLoading] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPaginationState] = useState({
    offset: 0,
    limit: 50,
    totalCount: 0,
    hasNext: false,
    hasPrev: false,
  });

  // Scanner integration state
  const [selectedRulesForScan, setSelectedRulesForScan] = useState<Rule[]>([]);
  const [scannerDialogOpen, setScannerDialogOpen] = useState(false);

  // Intelligence panel state
  const [intelligencePanelCollapsed, setIntelligencePanelCollapsed] = useState(false);

  // Available options
  const [availablePlatforms, setAvailablePlatforms] = useState<string[]>([]);
  const [availableCategories, setAvailableCategories] = useState<string[]>([]);
  const [availableFrameworks, setAvailableFrameworks] = useState<string[]>([]);

  // Dialog states
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [dependencyDialogOpen, setDependencyDialogOpen] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedRuleName, setSelectedRuleName] = useState<string | null>(null);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [exportLoading, setExportLoading] = useState(false);

  // Load rules
  const loadRules = useCallback(
    async (params: any = {}) => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await ruleService.getRules({
          offset: pagination.offset,
          limit: pagination.limit,
          ...activeFilters,
          ...params,
        });

        if (response.success) {
          setRules(response.data.rules);
          setFilteredRules(response.data.rules);
          setPaginationState({
            offset: response.data.offset,
            limit: response.data.limit,
            totalCount: response.data.total_count,
            hasNext: response.data.has_next,
            hasPrev: response.data.has_prev,
          });

          // Extract filter options
          const platforms = new Set<string>();
          const categories = new Set<string>();
          const frameworks = new Set<string>();

          response.data.rules.forEach((rule) => {
            Object.keys(rule.platform_implementations || {}).forEach((p) => platforms.add(p));
            if (rule.category) categories.add(rule.category);
            Object.keys(rule.frameworks || {}).forEach((f) => frameworks.add(f));
          });

          setAvailablePlatforms(Array.from(platforms).sort());
          setAvailableCategories(Array.from(categories).sort());
          setAvailableFrameworks(Array.from(frameworks).sort());
        } else {
          setError('Failed to load rules');
        }
      } catch (err) {
        setError('Failed to load rules');
        console.error('Error loading rules:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [pagination.offset, pagination.limit, activeFilters]
  );

  // Initial load
  useEffect(() => {
    loadRules();
  }, []);

  // Handle search
  const handleSearch = useCallback(
    async (query: string) => {
      setSearchQueryState(query);

      if (query.trim()) {
        setIsSearching(true);
        try {
          const response = await ruleService.searchRules({
            query,
            filters: {
              platform: activeFilters.platforms.length > 0 ? activeFilters.platforms : undefined,
              severity: activeFilters.severities.length > 0 ? activeFilters.severities : undefined,
              category: activeFilters.categories.length > 0 ? activeFilters.categories : undefined,
              framework: activeFilters.frameworks.length > 0 ? activeFilters.frameworks : undefined,
            },
            limit: 50,
          });

          if (response.success) {
            setSearchResults(response.data.results);
          }
        } catch (err) {
          console.error('Search error:', err);
        } finally {
          setIsSearching(false);
        }
      } else {
        setSearchResults([]);
      }
    },
    [activeFilters]
  );

  // Handle filter changes
  const handleFilterChange = useCallback(
    (filters: Partial<FilterState>) => {
      const newFilters = { ...activeFilters, ...filters };
      setActiveFilters(newFilters);

      // Reset pagination
      setPaginationState((prev) => ({ ...prev, offset: 0 }));

      // Reload rules with new filters
      loadRules({ ...newFilters, offset: 0 });
    },
    [activeFilters, loadRules]
  );

  // Handle rule selection
  const handleRuleSelect = useCallback(
    async (rule: Rule) => {
      setSelectedRule(rule);
      setSelectedRuleId(rule.rule_id);

      try {
        const response = await ruleService.getRuleDetails(rule.rule_id, true);
        if (response.success) {
          setSelectedRule(response.data);
        }
      } catch (err) {
        console.error('Error loading rule details:', err);
      }

      setDetailDialogOpen(true);

      if (onRuleSelect) {
        onRuleSelect(rule);
      }
    },
    [onRuleSelect]
  );

  // Handle search suggestion selection
  const handleSearchSuggestionSelect = useCallback(
    async (suggestion: SearchSuggestion) => {
      // Handle different types of search suggestions
      switch (suggestion.type) {
        case 'rule': {
          // If it's a specific rule, find and select it
          const rule = rules.find(
            (r) =>
              r.metadata.name.toLowerCase().includes(suggestion.value.toLowerCase()) ||
              r.rule_id === suggestion.value
          );
          if (rule) {
            await handleRuleSelect(rule);
          }
          break;
        }

        case 'tag':
          // Filter by tag
          handleFilterChange({ tags: [...activeFilters.tags, suggestion.value] });
          break;

        case 'category':
          // Filter by category
          handleFilterChange({ categories: [...activeFilters.categories, suggestion.value] });
          break;

        case 'framework':
          // Filter by framework
          handleFilterChange({ frameworks: [...activeFilters.frameworks, suggestion.value] });
          break;

        case 'history':
        case 'saved':
        default:
          // For history and saved searches, just set the search query
          handleSearch(suggestion.value);
          break;
      }
    },
    [activeFilters, rules, handleRuleSelect, handleFilterChange, handleSearch]
  );

  // Handle dependency view
  const handleViewDependencies = useCallback(
    async (ruleId: string) => {
      const rule = rules.find((r) => r.rule_id === ruleId);
      setSelectedRuleId(ruleId);
      setSelectedRuleName(rule?.metadata.name || null);
      setDependencyDialogOpen(true);
    },
    [rules]
  );

  // Handle pagination
  const handlePageChange = (event: React.ChangeEvent<unknown>, page: number) => {
    const newOffset = (page - 1) * pagination.limit;
    setPaginationState((prev) => ({ ...prev, offset: newOffset }));
    loadRules({ offset: newOffset });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Handle export
  const handleExport = async (format: 'json' | 'csv' | 'xml') => {
    setExportLoading(true);
    try {
      const ruleIds = searchQuery
        ? searchResults.map((r) => r.rule_id)
        : filteredRules.map((r) => r.rule_id);

      if (ruleIds.length === 0) {
        setSnackbarMessage('No rules to export');
        return;
      }

      const response = await ruleService.exportRules({
        ruleIds: ruleIds.slice(0, 1000),
        format,
        includeMetadata: true,
      });

      // Create download link
      const dataStr = format === 'json' ? JSON.stringify(response, null, 2) : response;
      const blob = new Blob([dataStr], {
        type:
          format === 'json'
            ? 'application/json'
            : format === 'csv'
              ? 'text/csv'
              : 'application/xml',
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
    } catch {
      setSnackbarMessage('Failed to export rules');
    } finally {
      setExportLoading(false);
    }
  };

  // Handle rule selection for scanning
  const handleRuleToggleForScan = useCallback((rule: Rule) => {
    setSelectedRulesForScan((prev) => {
      const isSelected = prev.some((r) => r.rule_id === rule.rule_id);
      if (isSelected) {
        return prev.filter((r) => r.rule_id !== rule.rule_id);
      } else {
        return [...prev, rule];
      }
    });
  }, []);

  // Handle bulk rule selection for scanning
  const _handleSelectAllForScan = useCallback(() => {
    const currentRules = searchQuery && searchResults.length > 0 ? searchResults : filteredRules;
    setSelectedRulesForScan(currentRules);
  }, [searchQuery, searchResults, filteredRules]);

  const _handleClearScanSelection = useCallback(() => {
    setSelectedRulesForScan([]);
  }, []);

  // Handle starting scan
  const handleStartScan = useCallback(
    async (config: any) => {
      try {
        setSnackbarMessage(`Starting scan with ${selectedRulesForScan.length} rules...`);

        // In a real implementation, this would call the scan API
        console.log('Starting scan with config:', config);
        console.log('Selected rules:', selectedRulesForScan);

        // Simulate API call
        await new Promise((resolve) => setTimeout(resolve, 1000));

        setSnackbarMessage('Scan started successfully!');

        // Keep the scanner dialog open to show progress
        // setScannerDialogOpen(false);
      } catch (error) {
        setSnackbarMessage('Failed to start scan');
        console.error('Scan start error:', error);
      }
    },
    [selectedRulesForScan]
  );

  // Determine display rules
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
          onSearchSuggestionSelect={handleSearchSuggestionSelect}
          filters={activeFilters}
          onFiltersChange={handleFilterChange}
          onClearFilters={() => {
            setActiveFilters({
              platforms: [],
              severities: [],
              categories: [],
              frameworks: [],
              tags: [],
              abstract: null,
            });
            setSearchQueryState('');
            setSearchResults([]);
            loadRules();
          }}
          viewMode={viewMode}
          onViewModeChange={setViewModeState}
          availablePlatforms={availablePlatforms}
          availableCategories={availableCategories}
          availableFrameworks={availableFrameworks}
          onRefresh={() => loadRules()}
          isLoading={isLoading}
          totalResults={totalCount}
        />
      </Box>

      {/* Rule Intelligence Panel */}
      <RuleIntelligencePanel
        availableRules={rules}
        currentPlatform={availablePlatforms[0]} // Use first available platform as current
        onRuleSelect={handleRuleSelect}
        onRuleAdd={(rule) => {
          // Add rule to scan selection
          if (!selectedRulesForScan.some((r) => r.rule_id === rule.rule_id)) {
            setSelectedRulesForScan((prev) => [...prev, rule]);
            setSnackbarMessage(`Added ${rule.metadata.name} to scan selection`);
          } else {
            setSnackbarMessage('Rule already in scan selection');
          }
        }}
        collapsed={intelligencePanelCollapsed}
        onToggleCollapse={() => setIntelligencePanelCollapsed(!intelligencePanelCollapsed)}
      />

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
              onClick={() => setError(null)}
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
            type={searchQuery ? 'no-results' : 'no-data'}
            icon={
              searchQuery ? (
                <SearchIcon sx={{ fontSize: 64 }} />
              ) : (
                <FilterIcon sx={{ fontSize: 64 }} />
              )
            }
            title={searchQuery ? 'No rules found' : 'No rules available'}
            description={
              searchQuery
                ? `No rules match your search for "${searchQuery}"`
                : Object.values(activeFilters).some((f) =>
                      Array.isArray(f) ? f.length > 0 : f !== null
                    )
                  ? 'No rules match the selected filters'
                  : 'No rules have been imported yet'
            }
            action={
              searchQuery ||
              Object.values(activeFilters).some((f) =>
                Array.isArray(f) ? f.length > 0 : f !== null
              )
                ? {
                    label: 'Clear Filters',
                    onClick: () => {
                      setActiveFilters({
                        platforms: [],
                        severities: [],
                        categories: [],
                        frameworks: [],
                        tags: [],
                        abstract: null,
                      });
                      setSearchQueryState('');
                      setSearchResults([]);
                      loadRules();
                    },
                    variant: 'contained' as const,
                  }
                : undefined
            }
          />
        ) : (
          <>
            {/* Grid/List View */}
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
                        viewMode={viewMode === 'tree' ? 'list' : viewMode}
                        onSelect={handleRuleSelect}
                        onViewDependencies={handleViewDependencies}
                        selected={selectedRule?.rule_id === rule.rule_id}
                        showRelevance={!!searchQuery && !!rule.relevance_score}
                      />
                    </Grid>
                  ))}
            </Grid>

            {/* Pagination */}
            {!searchQuery && totalPages > 1 && (
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'center',
                  mt: 4,
                  mb: 2,
                  p: 2,
                  bgcolor: 'background.paper',
                  position: 'sticky',
                  bottom: 0,
                  zIndex: 10,
                  boxShadow: theme.shadows[8],
                }}
              >
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

      {/* Floating Action Buttons */}
      <Box sx={{ position: 'fixed', bottom: 24, right: 24 }}>
        <Stack spacing={2}>
          {/* Scan Button */}
          <Fab
            color="secondary"
            aria-label="scan"
            onClick={() => {
              // If no rules are selected for scan, select all current display rules
              if (selectedRulesForScan.length === 0) {
                setSelectedRulesForScan(displayRules.slice(0, 20)); // Limit to 20 for demo
              }
              setScannerDialogOpen(true);
            }}
            disabled={displayRules.length === 0}
            sx={{
              backgroundColor: theme.palette.success.main,
              '&:hover': {
                backgroundColor: theme.palette.success.dark,
              },
            }}
          >
            <ScanIcon />
          </Fab>

          {/* Export Button */}
          <Fab
            color="primary"
            aria-label="export"
            onClick={() => handleExport('json')}
            disabled={exportLoading || displayRules.length === 0}
          >
            <DownloadIcon />
          </Fab>
        </Stack>
      </Box>

      {/* Dialogs */}
      {selectedRule && (
        <RuleDetailDialog
          open={detailDialogOpen}
          onClose={() => setDetailDialogOpen(false)}
          rule={selectedRule}
        />
      )}

      <EnhancedDependencyDialog
        open={dependencyDialogOpen}
        onClose={() => setDependencyDialogOpen(false)}
        ruleId={selectedRuleId || ''}
        ruleName={selectedRuleName || undefined}
        onRuleSelect={(ruleId) => {
          // Close dependency dialog and open rule detail
          setDependencyDialogOpen(false);
          const rule = rules.find((r) => r.rule_id === ruleId);
          if (rule) {
            handleRuleSelect(rule);
          }
        }}
      />

      {/* Scanner Integration Dialog */}
      <ScannerRuleSelection
        open={scannerDialogOpen}
        onClose={() => setScannerDialogOpen(false)}
        selectedRules={selectedRulesForScan}
        onRuleToggle={handleRuleToggleForScan}
        onStartScan={handleStartScan}
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

export default RulesExplorerSimplified;
