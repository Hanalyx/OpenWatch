import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
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
  Grid,
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
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
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
  Category as CategoryIcon,
  ExpandLess as ExpandLessIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Build as BuildIcon,
  Info as InfoIcon,
  Link as LinkIcon,
} from '@mui/icons-material';
import { Rule } from '../../store/slices/ruleSlice';
import { ruleService } from '../../services/ruleService';
import { useDebounce } from '../../hooks/useDebounce';

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

const ComplianceRulesContent: React.FC<ComplianceRulesContentProps> = ({
  onRuleSelect,
}) => {
  const theme = useTheme();
  
  // State management
  const [rules, setRules] = useState<Rule[]>([]);
  const [filteredRules, setFilteredRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
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
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  
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

  // Load compliance rules from MongoDB (via enhanced ruleService)
  const loadComplianceRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Use enhanced ruleService that tries MongoDB first, then falls back
      const response = await ruleService.getRules({
        offset: (pagination.page - 1) * pagination.rowsPerPage,
        limit: pagination.rowsPerPage,
        // Apply filters
        ...(filters.framework && { framework: filters.framework }),
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.category && { category: filters.category }),
        ...(filters.platform && { platform: filters.platform }),
        ...(debouncedSearch && { search: debouncedSearch }),
      });
      
      if (response.success) {
        setRules(response.data.rules);
        setFilteredRules(response.data.rules);
        setPagination(prev => ({
          ...prev,
          total: response.data.total_count,
        }));
        
        // Extract filter options from the data
        extractFilterOptions(response.data.rules);
      } else {
        setError('Failed to load compliance rules from database');
      }
    } catch (err: any) {
      console.error('Error loading compliance rules:', err);
      setError(`Error connecting to compliance rules database: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.rowsPerPage, filters, debouncedSearch]);

  // Extract available filter options from rules data
  const extractFilterOptions = (rulesData: Rule[]) => {
    const frameworks = new Set<string>();
    const categories = new Set<string>();
    const platforms = new Set<string>();
    
    rulesData.forEach(rule => {
      // Extract frameworks
      if (rule.frameworks) {
        Object.keys(rule.frameworks).forEach(framework => frameworks.add(framework));
      }
      
      // Extract categories
      if (rule.category) {
        categories.add(rule.category);
      }
      
      // Extract platforms
      if (rule.platform_implementations) {
        Object.keys(rule.platform_implementations).forEach(platform => platforms.add(platform));
      }
    });
    
    setFilterOptions(prev => ({
      ...prev,
      frameworks: Array.from(frameworks).sort(),
      categories: Array.from(categories).sort(),
      platforms: Array.from(platforms).sort(),
    }));
  };

  // Load data on component mount and when filters change
  useEffect(() => {
    loadComplianceRules();
  }, [loadComplianceRules]);

  // Handle filter changes
  const handleFilterChange = (filterName: keyof ComplianceFilters, value: string) => {
    setFilters(prev => ({
      ...prev,
      [filterName]: value,
    }));
    setPagination(prev => ({ ...prev, page: 1 })); // Reset to first page
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
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  // Handle pagination
  const handlePageChange = (event: unknown, newPage: number) => {
    setPagination(prev => ({ ...prev, page: newPage }));
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return theme.palette.error.main;
      case 'medium': return theme.palette.warning.main;
      case 'low': return theme.palette.info.main;
      case 'info': return theme.palette.grey[500];
      default: return theme.palette.grey[500];
    }
  };

  // Toggle row expansion
  const toggleRowExpansion = (ruleId: string) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(ruleId)) {
        newSet.delete(ruleId);
      } else {
        newSet.add(ruleId);
      }
      return newSet;
    });
  };

  // Check if row is expanded
  const isRowExpanded = (ruleId: string) => {
    return expandedRows.has(ruleId);
  };

  // Get compliance status color
  const getComplianceStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return theme.palette.success.main;
      case 'non_compliant': return theme.palette.error.main;
      case 'not_applicable': return theme.palette.grey[500];
      default: return theme.palette.warning.main;
    }
  };

  // Count active filters
  const activeFilterCount = Object.values(filters).filter(value => value && value !== '').length;

  // Calculate pagination info
  const totalPages = Math.ceil(pagination.total / pagination.rowsPerPage);
  const startItem = (pagination.page - 1) * pagination.rowsPerPage + 1;
  const endItem = Math.min(pagination.page * pagination.rowsPerPage, pagination.total);

  // Rule Details Component
  const RuleDetailsRow: React.FC<{ rule: Rule }> = ({ rule }) => {
    return (
      <TableRow>
        <TableCell colSpan={6} sx={{ py: 0, border: 0 }}>
          <Collapse in={isRowExpanded(rule.rule_id)} timeout="auto" unmountOnExit>
            <Box sx={{ 
              p: 3, 
              bgcolor: alpha(theme.palette.primary.main, 0.02),
              borderRadius: 1,
              m: 1,
              maxHeight: 'calc(60vh - 120px)',
              overflowY: 'auto',
              overflowX: 'hidden',
              '&::-webkit-scrollbar': {
                width: 8,
              },
              '&::-webkit-scrollbar-track': {
                backgroundColor: alpha(theme.palette.grey[400], 0.1),
                borderRadius: 1,
              },
              '&::-webkit-scrollbar-thumb': {
                backgroundColor: alpha(theme.palette.primary.main, 0.3),
                borderRadius: 1,
                '&:hover': {
                  backgroundColor: alpha(theme.palette.primary.main, 0.5),
                },
              },
            }}>
              <Grid container spacing={3}>
                {/* Rule Information */}
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <InfoIcon color="primary" />
                    Rule Information
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Description
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {rule.metadata.description}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Rationale
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {rule.metadata.rationale}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      SCAP Rule ID
                    </Typography>
                    <Typography variant="body2" sx={{ 
                      fontFamily: 'monospace',
                      backgroundColor: theme.palette.mode === 'dark' 
                        ? alpha(theme.palette.common.white, 0.05)
                        : alpha(theme.palette.common.black, 0.05),
                      color: theme.palette.mode === 'dark' 
                        ? theme.palette.grey[300]
                        : theme.palette.grey[800],
                      p: 1,
                      borderRadius: 1,
                      mb: 1,
                      border: `1px solid ${theme.palette.mode === 'dark' 
                        ? alpha(theme.palette.common.white, 0.1)
                        : alpha(theme.palette.common.black, 0.1)}`
                    }}>
                      {rule.scap_rule_id}
                    </Typography>
                  </Box>
                </Grid>

                {/* Frameworks & Compliance */}
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <LinkIcon color="primary" />
                    Compliance Frameworks
                  </Typography>
                  {Object.entries(rule.frameworks).map(([framework, versions]) => (
                    <Box key={framework} sx={{ mb: 2 }}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {framework.toUpperCase()}
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 1 }}>
                        {Object.entries(versions).map(([version, controls]) => (
                          <Chip
                            key={`${framework}-${version}`}
                            label={`${version}: ${Array.isArray(controls) ? controls.join(', ') : controls}`}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.75rem' }}
                          />
                        ))}
                      </Box>
                    </Box>
                  ))}
                  
                  {/* Tags */}
                  <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mt: 2 }}>
                    Tags
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {rule.tags.map(tag => (
                      <Chip key={tag} label={tag} size="small" color="primary" variant="outlined" />
                    ))}
                  </Box>
                </Grid>

                {/* Platform Implementation */}
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <BuildIcon color="primary" />
                    Platform Implementation
                  </Typography>
                  {Object.entries(rule.platform_implementations || {}).map(([platform, impl]) => (
                    <Card key={platform} variant="outlined" sx={{ mb: 2 }}>
                      <CardContent sx={{ pb: '16px !important' }}>
                        <Typography variant="subtitle1" gutterBottom sx={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: 1,
                          textTransform: 'capitalize'
                        }}>
                          <PlatformIcon fontSize="small" />
                          {platform}
                        </Typography>
                        <Grid container spacing={2}>
                          <Grid item xs={12} sm={6}>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                              Supported Versions
                            </Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                              {Array.isArray(impl.versions) ? impl.versions.join(', ') : 'All versions'}
                            </Typography>
                          </Grid>
                          {impl.check_command && (
                            <Grid item xs={12} sm={6}>
                              <Typography variant="body2" color="text.secondary" gutterBottom>
                                Check Command
                              </Typography>
                              <Typography variant="body2" sx={{ 
                                fontFamily: 'monospace',
                                backgroundColor: theme.palette.mode === 'dark' 
                                  ? alpha(theme.palette.common.white, 0.05)
                                  : alpha(theme.palette.common.black, 0.05),
                                color: theme.palette.mode === 'dark' 
                                  ? theme.palette.grey[300]
                                  : theme.palette.grey[800],
                                p: 1,
                                borderRadius: 1,
                                overflow: 'auto',
                                border: `1px solid ${theme.palette.mode === 'dark' 
                                  ? alpha(theme.palette.common.white, 0.1)
                                  : alpha(theme.palette.common.black, 0.1)}`
                              }}>
                                {impl.check_command}
                              </Typography>
                            </Grid>
                          )}
                          {impl.enable_command && (
                            <Grid item xs={12}>
                              <Typography variant="body2" color="text.secondary" gutterBottom>
                                Remediation Command
                              </Typography>
                              <Typography variant="body2" sx={{ 
                                fontFamily: 'monospace',
                                backgroundColor: theme.palette.mode === 'dark' 
                                  ? alpha(theme.palette.common.white, 0.05)
                                  : alpha(theme.palette.common.black, 0.05),
                                color: theme.palette.mode === 'dark' 
                                  ? theme.palette.grey[300]
                                  : theme.palette.grey[800],
                                p: 1,
                                borderRadius: 1,
                                overflow: 'auto',
                                border: `1px solid ${theme.palette.mode === 'dark' 
                                  ? alpha(theme.palette.common.white, 0.1)
                                  : alpha(theme.palette.common.black, 0.1)}`
                              }}>
                                {impl.enable_command}
                              </Typography>
                            </Grid>
                          )}
                          {impl.config_files && impl.config_files.length > 0 && (
                            <Grid item xs={12}>
                              <Typography variant="body2" color="text.secondary" gutterBottom>
                                Configuration Files
                              </Typography>
                              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                {impl.config_files.map(file => (
                                  <Chip 
                                    key={file} 
                                    label={file} 
                                    size="small" 
                                    variant="outlined"
                                    sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                  />
                                ))}
                              </Box>
                            </Grid>
                          )}
                        </Grid>
                      </CardContent>
                    </Card>
                  ))}
                </Grid>

                {/* Dependencies */}
                {(rule.dependencies?.requires?.length > 0 || rule.dependencies?.conflicts?.length > 0 || rule.dependencies?.related?.length > 0) && (
                  <Grid item xs={12}>
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CodeIcon color="primary" />
                      Dependencies
                    </Typography>
                    <Grid container spacing={2}>
                      {rule.dependencies?.requires?.length > 0 && (
                        <Grid item xs={12} sm={4}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Requires
                          </Typography>
                          <List dense>
                            {rule.dependencies?.requires?.map(dep => (
                              <ListItem key={dep} sx={{ py: 0.5, px: 0 }}>
                                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                  {dep}
                                </Typography>
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                      )}
                      {rule.dependencies?.conflicts?.length > 0 && (
                        <Grid item xs={12} sm={4}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Conflicts
                          </Typography>
                          <List dense>
                            {rule.dependencies?.conflicts?.map(dep => (
                              <ListItem key={dep} sx={{ py: 0.5, px: 0 }}>
                                <Typography variant="body2" sx={{ fontFamily: 'monospace', color: theme.palette.error.main }}>
                                  {dep}
                                </Typography>
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                      )}
                      {rule.dependencies?.related?.length > 0 && (
                        <Grid item xs={12} sm={4}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Related
                          </Typography>
                          <List dense>
                            {rule.dependencies?.related?.map(dep => (
                              <ListItem key={dep} sx={{ py: 0.5, px: 0 }}>
                                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                  {dep}
                                </Typography>
                              </ListItem>
                            ))}
                          </List>
                        </Grid>
                      )}
                    </Grid>
                  </Grid>
                )}
              </Grid>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    );
  };

  return (
    <Box sx={{ height: "100%", display: "flex", flexDirection: "column", p: { xs: 2, sm: 3 }, gap: 2 }}>
      {/* Header */}
      <Box>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box>
            <Typography variant="h5" gutterBottom display="flex" alignItems="center" gap={1}>
              <ComplianceIcon color="primary" />
              Compliance Rules Database
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {loading ? '🔄 Connecting to MongoDB database...' : `✅ MongoDB Connected: ${pagination.total} compliance rules in database`}
            </Typography>
          </Box>
          
          <Stack direction="row" spacing={1}>
            <Tooltip title="Refresh rules">
              <IconButton onClick={loadComplianceRules} disabled={loading}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              disabled={filteredRules.length === 0}
            >
              Export Rules
            </Button>
          </Stack>
        </Box>

        {/* Search and Filter Bar */}
        <Paper sx={{ p: { xs: 2, sm: 3 }, borderRadius: 2, boxShadow: 1 }}>
          <Grid container spacing={{ xs: 2, sm: 3 }} alignItems="center">
            {/* Search */}
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                placeholder="Search rules by name, ID, description, or tags..."
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
                      <IconButton
                        size="small"
                        onClick={() => handleFilterChange('search', '')}
                      >
                        <ClearIcon />
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                size="small"
              />
            </Grid>

            {/* Filter Toggle */}
            <Grid item xs={12} md={6}>
              <Box display="flex" justifyContent="flex-end" gap={1}>
                <Button
                  variant="outlined"
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
                  <Button variant="outlined" onClick={clearFilters} size="small">
                    Clear All
                  </Button>
                )}
              </Box>
            </Grid>
          </Grid>

          {/* Advanced Filters */}
          {showFilters && (
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
                      {filterOptions.frameworks.map(framework => (
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
                      {filterOptions.severities.map(severity => (
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
                      {filterOptions.categories.map(category => (
                        <MenuItem key={category} value={category}>
                          {category.split('_').map(word => 
                            word.charAt(0).toUpperCase() + word.slice(1)
                          ).join(' ')}
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
                      {filterOptions.platforms.map(platform => (
                        <MenuItem key={platform} value={platform}>
                          {platform.toUpperCase()}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </Box>
          )}
        </Paper>
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

      {/* Rules Table */}
      <Paper sx={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <TableContainer sx={{ flex: 1, maxHeight: 'calc(100vh - 300px)', overflowY: 'auto', overflowX: 'auto' }}>
          <Table stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ minWidth: 350 }}>Rule Information</TableCell>
                <TableCell align="center" sx={{ minWidth: 120 }}>Severity</TableCell>
                <TableCell align="center" sx={{ minWidth: 140 }}>Category</TableCell>
                <TableCell align="center" sx={{ minWidth: 150 }}>Frameworks</TableCell>
                <TableCell align="center" sx={{ minWidth: 130 }}>Platforms</TableCell>
                <TableCell align="center" sx={{ minWidth: 100 }}>Actions</TableCell>
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
                          : 'No rules are available in the database'
                        }
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
                  <React.Fragment key={rule.rule_id}>
                    <TableRow hover>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2" fontWeight="medium">
                            {rule.metadata.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" display="block">
                            ID: {rule.rule_id}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                            {rule.metadata.description.substring(0, 150)}
                            {rule.metadata.description.length > 150 && '...'}
                          </Typography>
                        </Box>
                      </TableCell>
                      
                      <TableCell align="center">
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
                      
                      <TableCell align="center">
                        <Chip
                          label={rule.category.split('_').map(word => 
                            word.charAt(0).toUpperCase() + word.slice(1)
                          ).join(' ')}
                          size="small"
                          variant="outlined"
                          icon={<CategoryIcon fontSize="small" />}
                        />
                      </TableCell>
                      
                      <TableCell align="center">
                        <Stack direction="row" spacing={0.5} justifyContent="center">
                          {rule.frameworks && Object.keys(rule.frameworks).map(framework => (
                            <Chip
                              key={framework}
                              label={framework.toUpperCase()}
                              size="small"
                              variant="outlined"
                            />
                          ))}
                        </Stack>
                      </TableCell>
                      
                      <TableCell align="center">
                        <Stack direction="row" spacing={0.5} justifyContent="center">
                          {rule.platform_implementations && Object.keys(rule.platform_implementations).map(platform => (
                            <Chip
                              key={platform}
                              label={platform.toUpperCase()}
                              size="small"
                              variant="outlined"
                              icon={<PlatformIcon fontSize="small" />}
                            />
                          ))}
                        </Stack>
                      </TableCell>
                      
                      <TableCell align="center">
                        <Tooltip title={isRowExpanded(rule.rule_id) ? "Hide rule details" : "View rule details"}>
                          <IconButton
                            size="small"
                            onClick={() => toggleRowExpansion(rule.rule_id)}
                          >
                            {isRowExpanded(rule.rule_id) ? <ExpandLessIcon /> : <ViewIcon />}
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    
                    {/* Rule Details Dropdown */}
                    <RuleDetailsRow rule={rule} />
                  </React.Fragment>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
        {!loading && filteredRules.length > 0 && (
          <Box sx={{ 
            p: { xs: 2, sm: 3 }, 
            borderTop: `1px solid ${theme.palette.divider}`,
            bgcolor: "background.paper",
            position: "sticky",
            bottom: 0,
            zIndex: 10,
            boxShadow: theme.shadows[8]
          }}>
            <Stack 
              direction={{ xs: "column", sm: "row" }} 
              justifyContent="space-between" 
              alignItems={{ xs: "stretch", sm: "center" }}
              spacing={2}
            >
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: { xs: "center", sm: "left" } }}>
                Showing <strong>{startItem}-{endItem}</strong> of <strong>{pagination.total}</strong> rules
              </Typography>
              
              <Pagination
                count={totalPages}
                page={pagination.page}
                onChange={handlePageChange}
                color="primary"
                size="medium"
                showFirstButton
                showLastButton
                siblingCount={1}
                boundaryCount={1}
                sx={{ 
                  "& .MuiPaginationItem-root": {
                    minWidth: { xs: 32, sm: 40 },
                    height: { xs: 32, sm: 40 },
                    fontSize: { xs: "0.75rem", sm: "0.875rem" }
                  }
                }}
              />
            </Stack>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default ComplianceRulesContent;