/**
 * RuleConfigStep - Step 3 of the ComplianceScanWizard
 *
 * Allows users to configure rule scanning mode:
 * - Full Scan mode: Scan all rules for the selected framework
 * - Custom mode: Select specific rules to scan
 *
 * Features:
 * - Toggle between Full and Custom scan modes
 * - Rule table with search and severity filter
 * - "Select All" / "Deselect All" functionality
 * - Severity-based chip colors for visual feedback
 * - Rule count display
 *
 * @module RuleConfigStep
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for design specifications
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Checkbox,
  Chip,
  Alert,
  Button,
  CircularProgress,
  Collapse,
} from '@mui/material';
import {
  Search as SearchIcon,
  CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
} from '@mui/icons-material';
import type { SelectChangeEvent } from '@mui/material/Select';
import { api } from '../../../services/api';
import type { ScanMode, WizardRule } from '../hooks/useScanWizard';

/**
 * Props for RuleConfigStep component
 */
interface RuleConfigStepProps {
  /** Current scan mode (full or custom) */
  scanMode: ScanMode;
  /** Array of selected rule IDs */
  selectedRuleIds: string[];
  /** Selected platform (for rule filtering) */
  platform: string;
  /** Selected platform version */
  platformVersion: string;
  /** Selected framework ID */
  framework: string;
  /** Callback when scan mode changes */
  onScanModeChange: (mode: ScanMode) => void;
  /** Callback when a rule is toggled */
  onToggleRule: (ruleId: string) => void;
  /** Callback to select all rules */
  onSelectAllRules: (ruleIds: string[]) => void;
  /** Callback to clear all rules */
  onClearRules: () => void;
}

/**
 * Raw compliance rule data from API response
 * Contains backend field names before transformation
 */
interface RawApiRule {
  id: string;
  scap_rule_id: string;
  title: string;
  compliance_intent?: string;
  risk_level?: string;
  frameworks?: string[];
}

/**
 * Severity level type for type safety
 */
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Get chip color based on severity level
 * Returns MUI color variant for consistent visual feedback
 *
 * @param severity - The severity level of the rule
 * @returns MUI color variant for Chip component
 */
function getSeverityColor(severity: SeverityLevel): 'error' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'default';
  }
}

/**
 * Normalize severity string from API to SeverityLevel type
 * Handles case variations and unknown values
 *
 * @param severity - Raw severity string from API
 * @returns Normalized SeverityLevel
 */
function normalizeSeverity(severity: string | undefined): SeverityLevel {
  if (!severity) return 'medium';
  const lower = severity.toLowerCase();
  if (lower === 'critical') return 'critical';
  if (lower === 'high') return 'high';
  if (lower === 'medium') return 'medium';
  if (lower === 'low') return 'low';
  if (lower === 'info' || lower === 'informational') return 'info';
  return 'medium';
}

/**
 * RuleConfigStep Component
 *
 * Third step of the scan wizard for configuring rule selection.
 * Supports both full scan (all rules) and custom rule selection.
 */
const RuleConfigStep: React.FC<RuleConfigStepProps> = ({
  scanMode,
  selectedRuleIds,
  platform,
  platformVersion,
  framework,
  onScanModeChange,
  onToggleRule,
  onSelectAllRules,
  onClearRules,
}) => {
  // Local state for rules data and UI
  const [rules, setRules] = useState<WizardRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [showRuleTable, setShowRuleTable] = useState(false);

  /**
   * Fetch rules from API when framework changes
   * Uses semantic-rules endpoint with framework filter
   */
  const loadRules = useCallback(async () => {
    if (!framework) {
      setRules([]);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Build query params for API request
      const params: Record<string, string> = {};
      if (framework) params.framework = framework;

      const response = await api.get<{ rules: RawApiRule[] }>('/api/compliance-rules/semantic-rules', { params });

      // Transform backend format to WizardRule interface
      const transformedRules: WizardRule[] = (response.rules || []).map((rule: RawApiRule) => ({
        id: rule.id,
        title: rule.title || 'Untitled Rule',
        severity: normalizeSeverity(rule.risk_level),
        category: rule.frameworks?.[0] || framework,
        description: rule.compliance_intent || '',
      }));

      setRules(transformedRules);
    } catch (err) {
      console.error('Failed to load compliance rules:', err);
      setError('Failed to load compliance rules. Please try again.');
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, [framework]);

  /**
   * Load rules when framework changes
   */
  useEffect(() => {
    loadRules();
  }, [loadRules]);

  /**
   * Auto-expand rule table when switching to custom mode
   */
  useEffect(() => {
    if (scanMode === 'custom') {
      setShowRuleTable(true);
    }
  }, [scanMode]);

  /**
   * Filter rules based on search query and severity filter
   */
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Apply search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          rule.title.toLowerCase().includes(query) ||
          rule.id.toLowerCase().includes(query) ||
          (rule.description?.toLowerCase().includes(query) ?? false);
        if (!matchesSearch) return false;
      }

      // Apply severity filter
      if (severityFilter && rule.severity !== severityFilter) {
        return false;
      }

      return true;
    });
  }, [rules, searchQuery, severityFilter]);

  /**
   * Check if all filtered rules are selected
   */
  const allFilteredSelected = useMemo(() => {
    if (filteredRules.length === 0) return false;
    return filteredRules.every((rule) => selectedRuleIds.includes(rule.id));
  }, [filteredRules, selectedRuleIds]);

  /**
   * Handle select all toggle for filtered rules
   */
  const handleSelectAllFiltered = () => {
    if (allFilteredSelected) {
      // Deselect all filtered rules
      const filteredIds = new Set(filteredRules.map((r) => r.id));
      const remaining = selectedRuleIds.filter((id) => !filteredIds.has(id));
      if (remaining.length === 0) {
        onClearRules();
      } else {
        // Keep non-filtered selections
        onSelectAllRules(remaining);
      }
    } else {
      // Select all filtered rules (merge with existing selections)
      const allIds = new Set([...selectedRuleIds, ...filteredRules.map((r) => r.id)]);
      onSelectAllRules(Array.from(allIds));
    }
  };

  /**
   * Handle severity filter change
   */
  const handleSeverityChange = (event: SelectChangeEvent<string>) => {
    setSeverityFilter(event.target.value);
  };

  /**
   * Handle scan mode change
   */
  const handleScanModeChange = (mode: ScanMode) => {
    onScanModeChange(mode);
    if (mode === 'full') {
      onClearRules();
    }
  };

  /**
   * Get display text for rule count
   */
  const getRuleCountText = (): string => {
    if (scanMode === 'full') {
      return `All ${rules.length} rules will be scanned`;
    }
    if (selectedRuleIds.length === 0) {
      return 'No rules selected (will scan all rules)';
    }
    return `${selectedRuleIds.length} of ${rules.length} rules selected`;
  };

  return (
    <Box>
      {/* Step Header */}
      <Typography variant="h6" gutterBottom>
        Rule Configuration (Optional)
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Choose between a full scan with all rules or select specific rules for a custom scan.
      </Typography>

      {/* Scan Mode Selection Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {/* Full Scan Mode */}
        <Grid size={{ xs: 12, sm: 6 }}>
          <Card
            sx={{
              cursor: 'pointer',
              border: 2,
              borderColor: scanMode === 'full' ? 'primary.main' : 'divider',
              transition: 'all 0.2s ease-in-out',
              '&:hover': {
                borderColor: 'primary.main',
                boxShadow: 2,
              },
            }}
            onClick={() => handleScanModeChange('full')}
          >
            <CardContent sx={{ py: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CheckCircleIcon
                  sx={{
                    fontSize: 40,
                    color: scanMode === 'full' ? 'primary.main' : 'text.secondary',
                  }}
                />
                <Box>
                  <Typography
                    variant="h6"
                    sx={{
                      color: scanMode === 'full' ? 'primary.main' : 'text.primary',
                    }}
                  >
                    Full Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Scan all {rules.length} rules for{' '}
                    {framework.toUpperCase() || 'selected framework'}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Custom Rules Mode */}
        <Grid size={{ xs: 12, sm: 6 }}>
          <Card
            sx={{
              cursor: 'pointer',
              border: 2,
              borderColor: scanMode === 'custom' ? 'primary.main' : 'divider',
              transition: 'all 0.2s ease-in-out',
              '&:hover': {
                borderColor: 'primary.main',
                boxShadow: 2,
              },
            }}
            onClick={() => handleScanModeChange('custom')}
          >
            <CardContent sx={{ py: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SearchIcon
                  sx={{
                    fontSize: 40,
                    color: scanMode === 'custom' ? 'primary.main' : 'text.secondary',
                  }}
                />
                <Box>
                  <Typography
                    variant="h6"
                    sx={{
                      color: scanMode === 'custom' ? 'primary.main' : 'text.primary',
                    }}
                  >
                    Custom Rules
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Select specific rules to check
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Rule Count Summary */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          {getRuleCountText()}
        </Typography>
        {loading && <CircularProgress size={16} />}
      </Box>

      {/* Expandable Rule Selection Section */}
      <Paper variant="outlined" sx={{ mb: 2 }}>
        <Button
          fullWidth
          onClick={() => setShowRuleTable(!showRuleTable)}
          endIcon={showRuleTable ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          sx={{
            justifyContent: 'space-between',
            py: 1.5,
            px: 2,
            textTransform: 'none',
          }}
        >
          <Typography variant="subtitle2">
            {showRuleTable ? 'Hide Rule Selection' : 'Show Rule Selection'}
          </Typography>
        </Button>

        <Collapse in={showRuleTable}>
          <Box sx={{ p: 2, pt: 0 }}>
            {/* Error Display */}
            {error && (
              <Alert
                severity="error"
                sx={{ mb: 2 }}
                action={
                  <Button color="inherit" size="small" onClick={loadRules}>
                    Retry
                  </Button>
                }
              >
                {error}
              </Alert>
            )}

            {/* Search and Filter Controls */}
            <Grid container spacing={2} sx={{ alignItems: 'center', mb: 2 }}>
              <Grid size={{ xs: 12, sm: 5 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search rules by title or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon color="action" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 4 }}>
                <FormControl fullWidth size="small">
                  <InputLabel id="severity-filter-label">Severity</InputLabel>
                  <Select
                    labelId="severity-filter-label"
                    id="severity-filter"
                    value={severityFilter}
                    label="Severity"
                    onChange={handleSeverityChange}
                  >
                    <MenuItem value="">All Severities</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="info">Info</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12, sm: 3 }} sx={{ textAlign: 'right' }}>
                <Button
                  variant="text"
                  size="small"
                  onClick={handleSelectAllFiltered}
                  disabled={loading || filteredRules.length === 0}
                >
                  {allFilteredSelected ? 'Deselect All' : 'Select All'}
                </Button>
              </Grid>
            </Grid>

            {/* Loading State */}
            {loading && (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <CircularProgress />
              </Box>
            )}

            {/* Empty State */}
            {!loading && rules.length === 0 && !error && (
              <Alert severity="info">
                No compliance rules available for the selected framework.
                {!framework && ' Please select a framework in Step 2.'}
              </Alert>
            )}

            {/* Rule Table */}
            {!loading && filteredRules.length > 0 && (
              <TableContainer sx={{ maxHeight: 400 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={allFilteredSelected}
                          indeterminate={
                            selectedRuleIds.length > 0 &&
                            !allFilteredSelected &&
                            filteredRules.some((r) => selectedRuleIds.includes(r.id))
                          }
                          onChange={handleSelectAllFiltered}
                        />
                      </TableCell>
                      <TableCell>Rule ID</TableCell>
                      <TableCell>Title</TableCell>
                      <TableCell>Severity</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredRules.map((rule) => (
                      <TableRow
                        key={rule.id}
                        hover
                        onClick={() => onToggleRule(rule.id)}
                        selected={selectedRuleIds.includes(rule.id)}
                        sx={{ cursor: 'pointer' }}
                      >
                        <TableCell padding="checkbox">
                          <Checkbox
                            checked={selectedRuleIds.includes(rule.id)}
                            onClick={(e) => e.stopPropagation()}
                            onChange={() => onToggleRule(rule.id)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.75rem',
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {rule.id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              maxWidth: 300,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {rule.title}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.severity}
                            size="small"
                            color={getSeverityColor(rule.severity)}
                            sx={{ textTransform: 'capitalize' }}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            {/* No Results for Filter */}
            {!loading && rules.length > 0 && filteredRules.length === 0 && (
              <Alert severity="info" sx={{ mt: 2 }}>
                No rules match your search criteria. Try adjusting your filters.
              </Alert>
            )}
          </Box>
        </Collapse>
      </Paper>

      {/* Summary Info */}
      {scanMode === 'full' && (
        <Alert severity="info">
          Full scan will check all applicable rules for{' '}
          <strong>
            {platform.toUpperCase()} {platformVersion}
          </strong>{' '}
          using the <strong>{framework.toUpperCase()}</strong> framework.
        </Alert>
      )}

      {scanMode === 'custom' && selectedRuleIds.length > 0 && (
        <Alert severity="success">
          <strong>{selectedRuleIds.length}</strong> rules selected for custom scan.
        </Alert>
      )}

      {scanMode === 'custom' && selectedRuleIds.length === 0 && (
        <Alert severity="warning">
          No rules selected. The scan will default to checking all rules.
        </Alert>
      )}
    </Box>
  );
};

export default RuleConfigStep;
