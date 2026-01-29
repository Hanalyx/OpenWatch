import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  IconButton,
  Tooltip,
  Alert,
  Pagination,
  Stack,
  InputAdornment,
  Badge,
  useTheme,
  alpha,
  LinearProgress,
  Collapse,
  Divider,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  Refresh as RefreshIcon,
  Visibility as ViewIcon,
  GetApp as ExportIcon,
  Clear as ClearIcon,
  Assessment as ComplianceIcon,
  Security as SecurityIcon,
  Computer as PlatformIcon,
} from '@mui/icons-material';
import { type Rule } from '../../store/slices/ruleSlice';
import { ruleService } from '../../services/ruleService';
import { useDebounce } from '../../hooks/useDebounce';
import { ViewModeToggle, type ViewMode } from '../../components/content/ViewModeToggle';
import { PlatformCard } from '../../components/content/PlatformCard';
import { FrameworkCard } from '../../components/content/FrameworkCard';
import RuleSidePanel from '../../components/content/RuleSidePanel';
import { useComplianceStatistics } from '../../hooks/useComplianceStatistics';
import { useFrameworkStatistics, type FrameworkData } from '../../hooks/useFrameworkStatistics';
import { type PlatformStatistics } from '../../types/content.types';

interface ComplianceFilters {
  search: string;
  framework: string;
  severity: string;
  category: string;
  platform: string;
  compliance_status: string;
}

interface ComplianceRulesContentProps {
  onRuleSelect?: (rule: Rule) => void;
}

const ComplianceRulesContent: React.FC<ComplianceRulesContentProps> = ({ onRuleSelect }) => {
  const theme = useTheme();

  // State management
  // Rules data state - reserved for future direct rule management features
  const [_rules, setRules] = useState<Rule[]>([]);
  const [filteredRules, setFilteredRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Side panel state
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [sidePanelOpen, setSidePanelOpen] = useState(false);

  // Platform statistics for platform view
  const {
    platforms,
    loading: platformsLoading,
    error: platformsError,
    refetch: refetchPlatforms,
    totalPlatforms,
    totalRulesAnalyzed,
    source: _source, // Data source metadata - reserved for future source attribution display
  } = useComplianceStatistics();

  // Framework statistics for framework view
  const {
    frameworks,
    loading: frameworksLoading,
    error: frameworksError,
    refetch: refetchFrameworks,
    totalFrameworks,
    totalRulesAnalyzed: frameworkTotalRulesAnalyzed,
  } = useFrameworkStatistics();

  const [viewMode, setViewMode] = useState<ViewMode>(() => {
    const saved = localStorage.getItem('complianceRulesViewMode');
    return (saved as ViewMode) || 'platform';
  });

  // Filter state
  const [filters, setFilters] = useState<ComplianceFilters>({
    search: '',
    framework: '',
    severity: '',
    category: '',
    platform: '',
    compliance_status: '',
  });

  // Pagination state
  const [pagination, setPagination] = useState({
    page: 1,
    rowsPerPage: 25,
    total: 0,
  });

  // UI state
  const [showFilters, setShowFilters] = useState(false);

  // Helper functions
  const handleRuleSelect = (rule: Rule) => {
    setSelectedRule(rule);
    setSidePanelOpen(true);
    if (onRuleSelect) {
      onRuleSelect(rule);
    }
  };

  const handleCloseSidePanel = () => {
    setSidePanelOpen(false);
    setSelectedRule(null);
  };

  // Debounce search
  const debouncedSearch = useDebounce(filters.search, 300);

  // Available filter options (derived from data)
  const [filterOptions, setFilterOptions] = useState({
    frameworks: [] as string[],
    severities: ['high', 'medium', 'low', 'info'],
    categories: [] as string[],
    platforms: [] as string[],
    compliance_statuses: ['compliant', 'non_compliant', 'not_applicable', 'unknown'],
  });

  // Load compliance rules
  const loadComplianceRules = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await ruleService.getRules({
        offset: (pagination.page - 1) * pagination.rowsPerPage,
        limit: pagination.rowsPerPage,
        is_latest: true,
        ...(filters.framework && { framework: filters.framework }),
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.category && { category: filters.category }),
        ...(filters.platform && { platform: filters.platform }),
        ...(debouncedSearch && { search: debouncedSearch }),
      });

      if (response.success) {
        setRules(response.data.rules);
        setFilteredRules(response.data.rules);
        setPagination((prev) => ({
          ...prev,
          total: response.data.total_count,
        }));

        extractFilterOptions(response.data.rules);
      } else {
        setError('Failed to load compliance rules from database');
      }
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Error loading compliance rules:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(`Error connecting to compliance rules database: ${errorMessage}`);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.rowsPerPage, filters, debouncedSearch]);

  // Extract available filter options from rules data
  const extractFilterOptions = (rulesData: Rule[]) => {
    const frameworks = new Set<string>();
    const categories = new Set<string>();
    const platforms = new Set<string>();

    rulesData.forEach((rule) => {
      if (rule.frameworks) {
        Object.keys(rule.frameworks).forEach((framework) => frameworks.add(framework));
      }
      if (rule.category) {
        categories.add(rule.category);
      }
      if (rule.platform_implementations) {
        Object.keys(rule.platform_implementations).forEach((platform) => platforms.add(platform));
      }
    });

    setFilterOptions((prev) => ({
      ...prev,
      frameworks: Array.from(frameworks).sort(),
      categories: Array.from(categories).sort(),
      platforms: Array.from(platforms).sort(),
    }));
  };

  useEffect(() => {
    loadComplianceRules();
  }, [loadComplianceRules]);

  // Handle filter changes
  const handleFilterChange = (filterName: keyof ComplianceFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [filterName]: value,
    }));
    setPagination((prev) => ({ ...prev, page: 1 }));
  };

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      search: '',
      framework: '',
      severity: '',
      category: '',
      platform: '',
      compliance_status: '',
    });
    setPagination((prev) => ({ ...prev, page: 1 }));
  };

  // Handle pagination
  const handlePageChange = (event: unknown, newPage: number) => {
    setPagination((prev) => ({ ...prev, page: newPage }));
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return theme.palette.error.main;
      case 'medium':
        return theme.palette.warning.main;
      case 'low':
        return theme.palette.info.main;
      case 'info':
        return theme.palette.grey[500];
      default:
        return theme.palette.grey[500];
    }
  };

  // Handle view mode change
  const handleViewModeChange = (mode: ViewMode) => {
    setViewMode(mode);
    localStorage.setItem('complianceRulesViewMode', mode);
  };

  // Handle platform card actions
  const handleBrowsePlatform = (platform: PlatformStatistics) => {
    setViewMode('all');
    handleFilterChange('platform', platform.name.toLowerCase());
    localStorage.setItem('complianceRulesViewMode', 'all');
  };

  const handleExportPlatform = (platform: PlatformStatistics) => {
    // TODO: Implement platform-specific rule export functionality
    void platform; // Suppress unused parameter warning
  };

  const handleViewPlatformMetrics = (platform: PlatformStatistics) => {
    // TODO: Implement platform metrics visualization
    void platform; // Suppress unused parameter warning
  };

  /**
   * Handle framework card click action
   * Switches to 'all' view mode and filters by selected framework
   */
  const handleBrowseFramework = (framework: FrameworkData) => {
    setViewMode('all');
    handleFilterChange('framework', framework.name.toLowerCase());
    localStorage.setItem('complianceRulesViewMode', 'all');
  };

  // Count active filters
  const activeFilterCount = Object.values(filters).filter((value) => value && value !== '').length;

  // Calculate pagination info
  const totalPages = Math.ceil(pagination.total / pagination.rowsPerPage);
  const startItem = (pagination.page - 1) * pagination.rowsPerPage + 1;
  const endItem = Math.min(pagination.page * pagination.rowsPerPage, pagination.total);

  return (
    <Box
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}
    >
      {/* Compact Header */}
      <Box
        sx={{
          p: 2,
          borderBottom: `1px solid ${theme.palette.divider}`,
          backgroundColor: theme.palette.background.paper,
          zIndex: 10,
          flexShrink: 0,
        }}
      >
        {/* Main Header Row */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
          <Box display="flex" alignItems="center" gap={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <ComplianceIcon color="primary" />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Compliance Rules
              </Typography>
            </Box>
            <Divider orientation="vertical" flexItem />
            <Typography variant="body2" color="text.secondary">
              {viewMode === 'platform'
                ? platformsLoading
                  ? 'Loading...'
                  : `${totalRulesAnalyzed} rules, ${totalPlatforms} platforms`
                : viewMode === 'framework'
                  ? frameworksLoading
                    ? 'Loading...'
                    : `${frameworkTotalRulesAnalyzed} rules, ${totalFrameworks} frameworks`
                  : loading
                    ? 'Loading...'
                    : `${pagination.total} rules`}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1}>
            <ViewModeToggle value={viewMode} onChange={handleViewModeChange} disabled={loading} />
            <Tooltip title="Refresh rules">
              <span>
                <IconButton size="small" onClick={loadComplianceRules} disabled={loading}>
                  <RefreshIcon />
                </IconButton>
              </span>
            </Tooltip>
            <Button
              variant="outlined"
              size="small"
              startIcon={<ExportIcon />}
              disabled={filteredRules.length === 0}
            >
              Export
            </Button>
          </Stack>
        </Box>

        {/* Compact Search and Filter Row */}
        <Box display="flex" gap={2} alignItems="center">
          <TextField
            placeholder="Search rules..."
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
              endAdornment: filters.search && (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => handleFilterChange('search', '')}>
                    <ClearIcon />
                  </IconButton>
                </InputAdornment>
              ),
            }}
            size="small"
            sx={{ flexGrow: 1, maxWidth: 400 }}
          />

          <Button
            variant="outlined"
            size="small"
            startIcon={<FilterIcon />}
            onClick={() => setShowFilters(!showFilters)}
            color={activeFilterCount > 0 ? 'primary' : 'inherit'}
          >
            Filters
            {activeFilterCount > 0 && (
              <Badge badgeContent={activeFilterCount} color="primary" sx={{ ml: 1 }} />
            )}
          </Button>

          {activeFilterCount > 0 && (
            <Button variant="text" size="small" onClick={clearFilters}>
              Clear All
            </Button>
          )}
        </Box>

        {/* Collapsible Advanced Filters */}
        <Collapse in={showFilters}>
          <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${theme.palette.divider}` }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Framework</InputLabel>
                  <Select
                    value={filters.framework}
                    label="Framework"
                    onChange={(e) => handleFilterChange('framework', e.target.value)}
                  >
                    <MenuItem value="">All Frameworks</MenuItem>
                    {filterOptions.frameworks.map((framework) => (
                      <MenuItem key={framework} value={framework}>
                        {framework.toUpperCase()}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={filters.severity}
                    label="Severity"
                    onChange={(e) => handleFilterChange('severity', e.target.value)}
                  >
                    <MenuItem value="">All Severities</MenuItem>
                    {filterOptions.severities.map((severity) => (
                      <MenuItem key={severity} value={severity}>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Box
                            sx={{
                              width: 8,
                              height: 8,
                              borderRadius: '50%',
                              backgroundColor: getSeverityColor(severity),
                            }}
                          />
                          {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={filters.category}
                    label="Category"
                    onChange={(e) => handleFilterChange('category', e.target.value)}
                  >
                    <MenuItem value="">All Categories</MenuItem>
                    {filterOptions.categories.map((category) => (
                      <MenuItem key={category} value={category}>
                        {category
                          .split('_')
                          .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
                          .join(' ')}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Platform</InputLabel>
                  <Select
                    value={filters.platform}
                    label="Platform"
                    onChange={(e) => handleFilterChange('platform', e.target.value)}
                  >
                    <MenuItem value="">All Platforms</MenuItem>
                    {filterOptions.platforms.map((platform) => (
                      <MenuItem key={platform} value={platform}>
                        {platform.toUpperCase()}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Box>
        </Collapse>
      </Box>

      {/* Loading */}
      {loading && (
        <Box sx={{ mb: 2 }}>
          <LinearProgress />
        </Box>
      )}

      {/* Error */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
          <Button size="small" onClick={loadComplianceRules} sx={{ ml: 1 }}>
            Retry
          </Button>
        </Alert>
      )}

      {/* Content based on View Mode */}
      {viewMode === 'platform' ? (
        // Platform View - Display platform statistics cards
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, overflow: 'hidden' }}>
          {platformsLoading && (
            <Box sx={{ mb: 2 }}>
              <LinearProgress />
            </Box>
          )}

          {platformsError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {platformsError}
              <Button size="small" onClick={refetchPlatforms} sx={{ ml: 1 }}>
                Retry
              </Button>
            </Alert>
          )}

          {!platformsLoading && !platformsError && (!platforms || platforms.length === 0) && (
            <Box sx={{ flex: 1, p: 3, textAlign: 'center' }}>
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No Platform Data Available
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Platform statistics are not available at this time.
              </Typography>
            </Box>
          )}

          {platforms && platforms.length > 0 && (
            <Paper sx={{ flex: 1, p: 3, overflow: 'auto' }}>
              <Box sx={{ mb: 3 }}>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                >
                  <PlatformIcon color="primary" />
                  Platform Overview
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Compliance rules organized by operating system platform. Click Browse Rules to
                  view platform-specific rules.
                </Typography>
              </Box>

              <Grid container spacing={3}>
                {platforms.map((platform) => (
                  <Grid item xs={12} sm={6} lg={4} key={`${platform.name}-${platform.version}`}>
                    <PlatformCard
                      platform={platform}
                      onBrowse={handleBrowsePlatform}
                      onExport={handleExportPlatform}
                      onViewMetrics={handleViewPlatformMetrics}
                      loading={platformsLoading}
                    />
                  </Grid>
                ))}
              </Grid>
            </Paper>
          )}
        </Box>
      ) : viewMode === 'framework' ? (
        // Framework View - Display framework statistics cards
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, overflow: 'hidden' }}>
          {frameworksLoading && (
            <Box sx={{ mb: 2 }}>
              <LinearProgress />
            </Box>
          )}

          {frameworksError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {frameworksError}
              <Button size="small" onClick={refetchFrameworks} sx={{ ml: 1 }}>
                Retry
              </Button>
            </Alert>
          )}

          {frameworks && frameworks.length > 0 && (
            <Paper sx={{ flex: 1, p: 3, overflow: 'auto' }}>
              <Box sx={{ mb: 3 }}>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                >
                  <SecurityIcon color="primary" />
                  Framework Overview
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Compliance rules organized by regulatory framework and standards.
                </Typography>
              </Box>

              <Grid container spacing={3}>
                {frameworks.map((framework) => (
                  <Grid item xs={12} sm={6} lg={4} key={`${framework.name}-${framework.version}`}>
                    <FrameworkCard
                      name={framework.name}
                      version={framework.version}
                      ruleCount={framework.ruleCount}
                      categories={framework.categories}
                      platforms={framework.platforms}
                      coverage={framework.coverage}
                      onClick={() => handleBrowseFramework(framework)}
                    />
                  </Grid>
                ))}
              </Grid>
            </Paper>
          )}
        </Box>
      ) : viewMode === 'category' ? (
        // Category view placeholder
        <Box sx={{ flex: 1, p: 3, textAlign: 'center' }}>
          <Typography variant="h6" color="text.secondary" gutterBottom>
            Category View Coming Soon
          </Typography>
          <Typography variant="body2" color="text.secondary">
            This view will display compliance rules organized by security category.
          </Typography>
        </Box>
      ) : (
        // Optimized table view for 'all' mode with fixed pagination
        <Box
          sx={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          <TableContainer
            sx={{
              flex: 1,
              overflow: 'auto',
              minHeight: 0,
              marginBottom: 0,
            }}
          >
            <Table stickyHeader size="small" sx={{ tableLayout: 'fixed', width: '100%' }}>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: 400, minWidth: 280, maxWidth: 400 }}>
                    Rule Information
                  </TableCell>
                  <TableCell align="center" sx={{ width: 100, minWidth: 100 }}>
                    Severity
                  </TableCell>
                  <TableCell align="center" sx={{ width: 120, minWidth: 120 }}>
                    Category
                  </TableCell>
                  <TableCell align="center" sx={{ width: 140, minWidth: 140 }}>
                    Frameworks
                  </TableCell>
                  <TableCell align="center" sx={{ width: 120, minWidth: 120 }}>
                    Platforms
                  </TableCell>
                  <TableCell align="center" sx={{ width: 80, minWidth: 80 }}>
                    Actions
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredRules.length === 0 && !loading ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                      <Box display="flex" flexDirection="column" alignItems="center" gap={2}>
                        <SecurityIcon sx={{ fontSize: 48, color: 'text.secondary' }} />
                        <Typography variant="h6" color="text.secondary">
                          No compliance rules found
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {activeFilterCount > 0
                            ? 'Try adjusting your filters or search criteria'
                            : 'No rules are available in the database'}
                        </Typography>
                        {activeFilterCount > 0 && (
                          <Button variant="outlined" onClick={clearFilters}>
                            Clear Filters
                          </Button>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredRules.map((rule) => (
                    <TableRow
                      key={rule.rule_id}
                      hover
                      sx={{
                        '&:hover': { backgroundColor: alpha(theme.palette.primary.main, 0.04) },
                      }}
                    >
                      <TableCell
                        sx={{
                          py: 1.5,
                          maxWidth: 400,
                          minWidth: 280,
                          width: 400,
                          overflow: 'hidden',
                        }}
                      >
                        <Box sx={{ maxWidth: '100%' }}>
                          <Typography
                            variant="body2"
                            fontWeight="medium"
                            sx={{
                              mb: 0.5,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {rule.metadata.name}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            display="block"
                            sx={{
                              mb: 0.5,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {rule.rule_id}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{
                              display: '-webkit-box',
                              WebkitLineClamp: 2,
                              WebkitBoxOrient: 'vertical',
                              overflow: 'hidden',
                              lineHeight: 1.4,
                              wordBreak: 'break-word',
                              overflowWrap: 'break-word',
                            }}
                          >
                            {rule.metadata.description}
                          </Typography>
                        </Box>
                      </TableCell>

                      <TableCell align="center" sx={{ width: 100, minWidth: 100 }}>
                        <Chip
                          label={rule.severity}
                          size="small"
                          sx={{
                            backgroundColor: alpha(getSeverityColor(rule.severity), 0.1),
                            color: getSeverityColor(rule.severity),
                            fontWeight: 'medium',
                          }}
                        />
                      </TableCell>

                      <TableCell align="center" sx={{ width: 120, minWidth: 120 }}>
                        <Typography variant="caption" color="text.secondary">
                          {rule.category
                            .split('_')
                            .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
                            .join(' ')}
                        </Typography>
                      </TableCell>

                      <TableCell
                        align="center"
                        sx={{ width: 140, minWidth: 140, overflow: 'hidden' }}
                      >
                        <Typography variant="caption" color="text.secondary">
                          {rule.frameworks &&
                            Object.keys(rule.frameworks)
                              .filter((framework) => {
                                const fwData = rule.frameworks[framework];
                                // Only show if framework has actual mappings (not empty object)
                                return (
                                  fwData &&
                                  typeof fwData === 'object' &&
                                  Object.keys(fwData).length > 0
                                );
                              })
                              .map((framework) => framework.toUpperCase())
                              .join(', ')}
                        </Typography>
                      </TableCell>

                      <TableCell
                        align="center"
                        sx={{ width: 120, minWidth: 120, overflow: 'hidden' }}
                      >
                        <Typography variant="caption" color="text.secondary">
                          {rule.platform_implementations &&
                            Object.keys(rule.platform_implementations)
                              .filter((platform) => {
                                const impl = rule.platform_implementations[platform];
                                // Only show if platform has actual implementation data (not empty/null object)
                                return (
                                  impl &&
                                  typeof impl === 'object' &&
                                  Object.keys(impl).length > 0 &&
                                  (impl.versions?.length > 0 ||
                                    impl.check_command ||
                                    impl.enable_command)
                                );
                              })
                              .map((platform) => platform.toUpperCase())
                              .join(', ')}
                        </Typography>
                      </TableCell>

                      <TableCell align="center" sx={{ width: 80, minWidth: 80 }}>
                        <Tooltip title="View rule details">
                          <span>
                            <IconButton size="small" onClick={() => handleRuleSelect(rule)}>
                              <ViewIcon />
                            </IconButton>
                          </span>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Pagination - Fixed at bottom */}
          {pagination.total > 0 && (
            <Box
              sx={{
                p: 2,
                borderTop: `2px solid ${theme.palette.primary.main}`,
                backgroundColor: theme.palette.background.paper,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexShrink: 0,
                minHeight: 80,
                zIndex: 100,
                boxShadow: `0 -4px 8px ${alpha(theme.palette.common.black, 0.2)}`,
              }}
            >
              <Typography variant="body2" color="text.secondary">
                <strong>
                  {startItem}-{endItem}
                </strong>{' '}
                of <strong>{pagination.total}</strong>
              </Typography>

              <Pagination
                count={totalPages}
                page={pagination.page}
                onChange={handlePageChange}
                color="primary"
                size="small"
                showFirstButton
                showLastButton
                siblingCount={1}
                boundaryCount={1}
                sx={{
                  '& .MuiPagination-ul': {
                    justifyContent: 'center',
                    margin: 0,
                  },
                }}
              />
            </Box>
          )}
        </Box>
      )}

      {/* Rule Details Side Panel */}
      <RuleSidePanel open={sidePanelOpen} rule={selectedRule} onClose={handleCloseSidePanel} />
    </Box>
  );
};

export default ComplianceRulesContent;
