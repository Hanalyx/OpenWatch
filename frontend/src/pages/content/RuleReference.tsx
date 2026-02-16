/**
 * Rule Reference Page
 *
 * Browse and explore Aegis compliance rules with filtering, search, and
 * detailed rule information. Replaces the MongoDB-based Content Library
 * with a clean YAML-based rule reference.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module pages/content/RuleReference
 */

import React, { useState, useMemo, useCallback } from 'react';
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
  IconButton,
  Tooltip,
  Alert,
  Pagination,
  Stack,
  InputAdornment,
  Card,
  CardContent,
  Skeleton,
  Drawer,
  Divider,
  List,
  ListItem,
  ListItemText,
  Tabs,
  Tab,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Clear as ClearIcon,
  Close as CloseIcon,
  CheckCircle as PassIcon,
  Cancel as FailIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import {
  useRules,
  useRuleDetail,
  useRuleStatistics,
  useFrameworks,
  useCategories,
  useCapabilities,
  useRefreshRuleCache,
} from '../../hooks/useRuleReference';
import type {
  RuleSummary,
  RuleDetail,
  RuleSearchParams,
  Severity,
} from '../../types/ruleReference';

// =============================================================================
// Constants
// =============================================================================

const SEVERITY_COLORS: Record<Severity, 'error' | 'warning' | 'info' | 'default'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};

const PER_PAGE = 25;

// =============================================================================
// Statistics Cards Component
// =============================================================================

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  loading?: boolean;
}

function StatCard({ title, value, subtitle, loading }: StatCardProps) {
  return (
    <Card
      sx={{
        height: '100%',
        minHeight: 120,
        bgcolor: 'background.paper',
        borderRadius: 2,
      }}
    >
      <CardContent>
        {loading ? (
          <>
            <Skeleton width="60%" height={24} />
            <Skeleton width="40%" height={40} />
          </>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 600 }}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="caption" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

// =============================================================================
// Filters Component
// =============================================================================

interface FilterBarProps {
  search: string;
  onSearchChange: (value: string) => void;
  severity: string;
  onSeverityChange: (value: string) => void;
  category: string;
  onCategoryChange: (value: string) => void;
  framework: string;
  onFrameworkChange: (value: string) => void;
  capability: string;
  onCapabilityChange: (value: string) => void;
  onClear: () => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  categories: Array<{ id: string; name: string }>;
  frameworks: Array<{ id: string; name: string }>;
  capabilities: Array<{ id: string; name: string }>;
}

function FilterBar({
  search,
  onSearchChange,
  severity,
  onSeverityChange,
  category,
  onCategoryChange,
  framework,
  onFrameworkChange,
  capability,
  onCapabilityChange,
  onClear,
  onRefresh,
  isRefreshing,
  categories,
  frameworks,
  capabilities,
}: FilterBarProps) {
  const hasFilters = search || severity || category || framework || capability;

  return (
    <Paper sx={{ p: 2, mb: 2 }}>
      <Grid container spacing={2} alignItems="center">
        <Grid size={{ xs: 12, md: 3 }}>
          <TextField
            fullWidth
            size="small"
            placeholder="Search rules..."
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" />
                  </InputAdornment>
                ),
                endAdornment: search && (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => onSearchChange('')}>
                      <ClearIcon fontSize="small" />
                    </IconButton>
                  </InputAdornment>
                ),
              },
            }}
          />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Severity</InputLabel>
            <Select
              value={severity}
              onChange={(e) => onSeverityChange(e.target.value)}
              label="Severity"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Category</InputLabel>
            <Select
              value={category}
              onChange={(e) => onCategoryChange(e.target.value)}
              label="Category"
            >
              <MenuItem value="">All</MenuItem>
              {categories.map((cat) => (
                <MenuItem key={cat.id} value={cat.id}>
                  {cat.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Framework</InputLabel>
            <Select
              value={framework}
              onChange={(e) => onFrameworkChange(e.target.value)}
              label="Framework"
            >
              <MenuItem value="">All</MenuItem>
              {frameworks.map((fw) => (
                <MenuItem key={fw.id} value={fw.id}>
                  {fw.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Capability</InputLabel>
            <Select
              value={capability}
              onChange={(e) => onCapabilityChange(e.target.value)}
              label="Capability"
            >
              <MenuItem value="">All</MenuItem>
              {capabilities.map((cap) => (
                <MenuItem key={cap.id} value={cap.id}>
                  {cap.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid size={{ xs: 12, md: 1 }}>
          <Stack direction="row" spacing={1} justifyContent="flex-end">
            {hasFilters && (
              <Tooltip title="Clear filters">
                <IconButton size="small" onClick={onClear}>
                  <ClearIcon />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Refresh rules">
              <IconButton size="small" onClick={onRefresh} disabled={isRefreshing}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        </Grid>
      </Grid>
    </Paper>
  );
}

// =============================================================================
// Rules Table Component
// =============================================================================

interface RulesTableProps {
  rules: RuleSummary[];
  loading: boolean;
  onRuleClick: (rule: RuleSummary) => void;
  selectedRuleId?: string;
}

function RulesTable({ rules, loading, onRuleClick, selectedRuleId }: RulesTableProps) {
  if (loading) {
    return (
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Rule ID</TableCell>
              <TableCell>Title</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Frameworks</TableCell>
              <TableCell>Remediation</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {[...Array(10)].map((_, i) => (
              <TableRow key={i}>
                <TableCell>
                  <Skeleton width={150} />
                </TableCell>
                <TableCell>
                  <Skeleton width="80%" />
                </TableCell>
                <TableCell>
                  <Skeleton width={80} />
                </TableCell>
                <TableCell>
                  <Skeleton width={100} />
                </TableCell>
                <TableCell>
                  <Skeleton width={60} />
                </TableCell>
                <TableCell>
                  <Skeleton width={40} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    );
  }

  if (rules.length === 0) {
    return (
      <Paper sx={{ p: 4, textAlign: 'center' }}>
        <Typography color="text.secondary">No rules found matching your criteria</Typography>
      </Paper>
    );
  }

  return (
    <TableContainer component={Paper}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Rule ID</TableCell>
            <TableCell>Title</TableCell>
            <TableCell>Severity</TableCell>
            <TableCell>Category</TableCell>
            <TableCell align="center">Frameworks</TableCell>
            <TableCell align="center">Remediation</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rules.map((rule) => (
            <TableRow
              key={rule.id}
              hover
              onClick={() => onRuleClick(rule)}
              selected={rule.id === selectedRuleId}
              sx={{ cursor: 'pointer' }}
            >
              <TableCell>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  {rule.id}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" noWrap sx={{ maxWidth: 400 }}>
                  {rule.title}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={rule.severity}
                  size="small"
                  color={SEVERITY_COLORS[rule.severity]}
                  sx={{ textTransform: 'capitalize' }}
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                  {rule.category.replace(/-/g, ' ')}
                </Typography>
              </TableCell>
              <TableCell align="center">
                <Chip label={rule.frameworkCount} size="small" variant="outlined" />
              </TableCell>
              <TableCell align="center">
                {rule.hasRemediation ? (
                  <PassIcon fontSize="small" color="success" />
                ) : (
                  <FailIcon fontSize="small" color="disabled" />
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// =============================================================================
// Rule Detail Panel Component
// =============================================================================

interface RuleDetailPanelProps {
  rule: RuleDetail | undefined;
  loading: boolean;
  open: boolean;
  onClose: () => void;
}

function RuleDetailPanel({ rule, loading, open, onClose }: RuleDetailPanelProps) {
  const [detailTab, setDetailTab] = useState(0);

  // Reset to Overview tab when a new rule is selected
  React.useEffect(() => {
    if (rule?.id) {
      setDetailTab(0);
    }
  }, [rule?.id]);

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: { width: { xs: '100%', md: 600 }, p: 0 },
      }}
    >
      {loading ? (
        <Box sx={{ p: 3 }}>
          <Skeleton height={40} width="80%" />
          <Skeleton height={24} width="40%" sx={{ mt: 1 }} />
          <Skeleton height={100} sx={{ mt: 2 }} />
          <Skeleton height={100} sx={{ mt: 2 }} />
        </Box>
      ) : rule ? (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
            <Box
              sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}
            >
              <Box sx={{ flex: 1, pr: 2 }}>
                <Typography variant="h6" gutterBottom>
                  {rule.title}
                </Typography>
                <Typography
                  variant="body2"
                  sx={{ fontFamily: 'monospace', color: 'text.secondary' }}
                >
                  {rule.id}
                </Typography>
              </Box>
              <IconButton onClick={onClose}>
                <CloseIcon />
              </IconButton>
            </Box>
            <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
              <Chip
                label={rule.severity}
                size="small"
                color={SEVERITY_COLORS[rule.severity]}
                sx={{ textTransform: 'capitalize' }}
              />
              <Chip
                label={rule.category.replace(/-/g, ' ')}
                size="small"
                variant="outlined"
                sx={{ textTransform: 'capitalize' }}
              />
              {rule.implementations.some((impl) => impl.remediation !== null) && (
                <Chip label="Has Remediation" size="small" color="success" variant="outlined" />
              )}
            </Stack>
          </Box>

          {/* Tabs */}
          <Tabs
            value={detailTab}
            onChange={(_, v) => setDetailTab(v)}
            sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}
          >
            <Tab label="Overview" />
            <Tab label="Frameworks" />
            <Tab label="Implementation" />
          </Tabs>

          {/* Tab Content */}
          <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
            {/* Overview Tab */}
            {detailTab === 0 && (
              <Stack spacing={3}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Description
                  </Typography>
                  <Typography variant="body2">{rule.description}</Typography>
                </Box>
                <Divider />
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Rationale
                  </Typography>
                  <Typography variant="body2">{rule.rationale}</Typography>
                </Box>
                {rule.tags.length > 0 && (
                  <>
                    <Divider />
                    <Box>
                      <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                        Tags
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {rule.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" />
                        ))}
                      </Stack>
                    </Box>
                  </>
                )}
                {rule.platforms.length > 0 && (
                  <>
                    <Divider />
                    <Box>
                      <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                        Platforms
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {rule.platforms.map((p, i) => (
                          <Chip
                            key={i}
                            label={p.min_version ? `${p.family} ${p.min_version}+` : p.family}
                            size="small"
                            variant="outlined"
                          />
                        ))}
                      </Stack>
                    </Box>
                  </>
                )}
              </Stack>
            )}

            {/* Frameworks Tab */}
            {detailTab === 1 && (
              <Stack spacing={2}>
                {Object.keys(rule.references.cis).length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      CIS Benchmarks
                    </Typography>
                    <List dense disablePadding>
                      {Object.entries(rule.references.cis).map(([version, ref]) => (
                        <ListItem key={version} disablePadding sx={{ py: 0.5 }}>
                          <ListItemText
                            primary={`${version}: Section ${ref.section}`}
                            secondary={`Level ${ref.level} - ${ref.type}`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}
                {Object.keys(rule.references.stig).length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      DISA STIG
                    </Typography>
                    <List dense disablePadding>
                      {Object.entries(rule.references.stig).map(([version, ref]) => (
                        <ListItem key={version} disablePadding sx={{ py: 0.5 }}>
                          <ListItemText
                            primary={`${version}: ${ref.vulnId} (${ref.stigId})`}
                            secondary={`Severity: ${ref.severity} | CCI: ${ref.cci.join(', ')}`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}
                {rule.references.nist80053.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      NIST 800-53
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {rule.references.nist80053.map((ctrl) => (
                        <Chip key={ctrl} label={ctrl} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}
                {rule.references.pciDss4.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      PCI DSS 4.0
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {rule.references.pciDss4.map((ctrl) => (
                        <Chip key={ctrl} label={ctrl} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}
                {rule.references.srg.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      SRG
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {rule.references.srg.map((srg) => (
                        <Chip key={srg} label={srg} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Stack>
            )}

            {/* Implementation Tab */}
            {detailTab === 2 && (
              <Stack spacing={3}>
                {rule.implementations.map((impl, idx) => (
                  <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                      {impl.isDefault && <Chip label="Default" size="small" color="primary" />}
                      {impl.capabilityRequired && (
                        <Chip
                          label={`Requires: ${impl.capabilityRequired}`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Stack>
                    <Box>
                      <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                        Check
                      </Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          bgcolor: 'action.hover',
                          p: 1,
                          borderRadius: 1,
                        }}
                      >
                        Method: {impl.check.method}
                        {impl.check.path && (
                          <>
                            <br />
                            Path: {impl.check.path}
                          </>
                        )}
                        {impl.check.key && (
                          <>
                            <br />
                            Key: {impl.check.key}
                          </>
                        )}
                        {impl.check.expected && (
                          <>
                            <br />
                            Expected: {impl.check.expected}
                          </>
                        )}
                        {impl.check.comparator && (
                          <>
                            <br />
                            Comparator: {impl.check.comparator}
                          </>
                        )}
                      </Typography>
                    </Box>
                    {impl.remediation && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Remediation
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            bgcolor: 'action.hover',
                            p: 1,
                            borderRadius: 1,
                          }}
                        >
                          Mechanism: {impl.remediation.mechanism}
                          {impl.remediation.path && (
                            <>
                              <br />
                              Path: {impl.remediation.path}
                            </>
                          )}
                          {impl.remediation.key && (
                            <>
                              <br />
                              Key: {impl.remediation.key}
                            </>
                          )}
                          {impl.remediation.value && (
                            <>
                              <br />
                              Value: {impl.remediation.value}
                            </>
                          )}
                          {impl.remediation.command && (
                            <>
                              <br />
                              Command: {impl.remediation.command}
                            </>
                          )}
                        </Typography>
                      </Box>
                    )}
                  </Paper>
                ))}
                {rule.dependsOn.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Depends On
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {rule.dependsOn.map((dep) => (
                        <Chip key={dep} label={dep} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Box>
                )}
                {rule.conflictsWith.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Conflicts With
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {rule.conflictsWith.map((conf) => (
                        <Chip
                          key={conf}
                          label={conf}
                          size="small"
                          color="warning"
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Stack>
            )}
          </Box>
        </Box>
      ) : (
        <Box sx={{ p: 3, textAlign: 'center' }}>
          <InfoIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
          <Typography color="text.secondary">Select a rule to view details</Typography>
        </Box>
      )}
    </Drawer>
  );
}

// =============================================================================
// Main Rule Reference Component
// =============================================================================

const RuleReference: React.FC = () => {
  // Filter state
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [framework, setFramework] = useState('');
  const [capability, setCapability] = useState('');
  const [page, setPage] = useState(1);

  // Selected rule state
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  // Build search params
  const searchParams = useMemo<RuleSearchParams>(
    () => ({
      search: search || undefined,
      severity: severity || undefined,
      category: category || undefined,
      framework: framework || undefined,
      capability: capability || undefined,
      page,
      perPage: PER_PAGE,
    }),
    [search, severity, category, framework, capability, page]
  );

  // Queries
  const { data: rulesData, isLoading: rulesLoading, error: rulesError } = useRules(searchParams);
  const { data: statsData, isLoading: statsLoading } = useRuleStatistics();
  const { data: frameworksData } = useFrameworks();
  const { data: categoriesData } = useCategories();
  const { data: capabilitiesData } = useCapabilities();
  const { data: ruleDetailData, isLoading: ruleDetailLoading } = useRuleDetail(
    selectedRuleId ?? undefined,
    !!selectedRuleId
  );
  const refreshCache = useRefreshRuleCache();

  // Handlers
  const handleClearFilters = useCallback(() => {
    setSearch('');
    setSeverity('');
    setCategory('');
    setFramework('');
    setCapability('');
    setPage(1);
  }, []);

  const handleRefresh = useCallback(() => {
    refreshCache.mutate();
  }, [refreshCache]);

  const handleRuleClick = useCallback((rule: RuleSummary) => {
    setSelectedRuleId(rule.id);
    setDetailOpen(true);
  }, []);

  const handleCloseDetail = useCallback(() => {
    setDetailOpen(false);
  }, []);

  const handlePageChange = useCallback((_: React.ChangeEvent<unknown>, newPage: number) => {
    setPage(newPage);
  }, []);

  // Reset page when filters change
  const handleSearchChange = useCallback((value: string) => {
    setSearch(value);
    setPage(1);
  }, []);

  const handleSeverityChange = useCallback((value: string) => {
    setSeverity(value);
    setPage(1);
  }, []);

  const handleCategoryChange = useCallback((value: string) => {
    setCategory(value);
    setPage(1);
  }, []);

  const handleFrameworkChange = useCallback((value: string) => {
    setFramework(value);
    setPage(1);
  }, []);

  const handleCapabilityChange = useCallback((value: string) => {
    setCapability(value);
    setPage(1);
  }, []);

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Rule Reference
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Browse Aegis compliance rules with framework mappings, implementation details, and
          remediation guidance
        </Typography>
      </Box>

      {/* Error Alert */}
      {rulesError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load rules: {rulesError instanceof Error ? rulesError.message : 'Unknown error'}
        </Alert>
      )}

      {/* Statistics Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <StatCard title="Total Rules" value={statsData?.totalRules ?? 0} loading={statsLoading} />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <StatCard
            title="With Remediation"
            value={statsData?.withRemediation ?? 0}
            subtitle={
              statsData
                ? `${Math.round((statsData.withRemediation / statsData.totalRules) * 100)}% coverage`
                : undefined
            }
            loading={statsLoading}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <StatCard
            title="Critical + High"
            value={(statsData?.bySeverity?.critical ?? 0) + (statsData?.bySeverity?.high ?? 0)}
            loading={statsLoading}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <StatCard
            title="Frameworks"
            value={frameworksData?.total ?? 0}
            loading={!frameworksData}
          />
        </Grid>
      </Grid>

      {/* Filters */}
      <FilterBar
        search={search}
        onSearchChange={handleSearchChange}
        severity={severity}
        onSeverityChange={handleSeverityChange}
        category={category}
        onCategoryChange={handleCategoryChange}
        framework={framework}
        onFrameworkChange={handleFrameworkChange}
        capability={capability}
        onCapabilityChange={handleCapabilityChange}
        onClear={handleClearFilters}
        onRefresh={handleRefresh}
        isRefreshing={refreshCache.isPending}
        categories={categoriesData?.categories ?? []}
        frameworks={frameworksData?.frameworks ?? []}
        capabilities={capabilitiesData?.capabilities ?? []}
      />

      {/* Rules Table */}
      <RulesTable
        rules={rulesData?.rules ?? []}
        loading={rulesLoading}
        onRuleClick={handleRuleClick}
        selectedRuleId={selectedRuleId ?? undefined}
      />

      {/* Pagination */}
      {rulesData && rulesData.totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
          <Pagination
            count={rulesData.totalPages}
            page={page}
            onChange={handlePageChange}
            color="primary"
          />
        </Box>
      )}

      {/* Results Count */}
      {rulesData && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: 'center' }}>
          Showing {rulesData.rules.length} of {rulesData.total} rules
        </Typography>
      )}

      {/* Rule Detail Panel */}
      <RuleDetailPanel
        rule={ruleDetailData?.rule}
        loading={ruleDetailLoading}
        open={detailOpen}
        onClose={handleCloseDetail}
      />
    </Box>
  );
};

export default RuleReference;
