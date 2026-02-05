/**
 * Shared rules table for ScanDetail tabs (Failed Rules / All Rules).
 *
 * When variant="failed", pre-filters to failed rules and hides the result column.
 * When variant="all", shows all rules with result icon and result filter.
 */

import React from 'react';
import {
  Box,
  Typography,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  InputAdornment,
  MenuItem,
  Tooltip,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Search as SearchIcon,
  Build as BuildIcon,
  Refresh as RefreshIcon,
  FileCopy as FileCopyIcon,
  BookmarkBorder as BookmarkBorderIcon,
  Bookmark as BookmarkIcon,
} from '@mui/icons-material';
import type { RuleResult } from './scanTypes';
import { getSeverityColor } from './scanUtils';

interface ScanRulesTableProps {
  variant: 'failed' | 'all';
  filteredRules: RuleResult[];
  searchQuery: string;
  onSearchChange: (query: string) => void;
  severityFilter: string;
  onSeverityFilterChange: (filter: string) => void;
  resultFilter: string;
  onResultFilterChange: (filter: string) => void;
  page: number;
  rowsPerPage: number;
  onPageChange: (event: unknown, newPage: number) => void;
  onRowsPerPageChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
  reviewedRules: Set<string>;
  onToggleReview: (ruleId: string) => void;
  onViewRemediation: (rule: RuleResult) => void;
  onExportRule: (rule: RuleResult) => void;
  onRescanRule: (rule: RuleResult) => void;
  isLoading: boolean;
}

function getResultIcon(result: string): React.ReactNode {
  switch (result) {
    case 'pass':
      return <CheckCircleIcon color="success" />;
    case 'fail':
      return <CancelIcon color="error" />;
    case 'error':
      return <ErrorIcon color="error" />;
    case 'notapplicable':
      return <InfoIcon color="disabled" />;
    default:
      return <WarningIcon color="warning" />;
  }
}

const ScanRulesTable: React.FC<ScanRulesTableProps> = ({
  variant,
  filteredRules,
  searchQuery,
  onSearchChange,
  severityFilter,
  onSeverityFilterChange,
  resultFilter,
  onResultFilterChange,
  page,
  rowsPerPage,
  onPageChange,
  onRowsPerPageChange,
  reviewedRules,
  onToggleReview,
  onViewRemediation,
  onExportRule,
  onRescanRule,
  isLoading,
}) => {
  const displayRules =
    variant === 'failed' ? filteredRules.filter((r) => r.result === 'fail') : filteredRules;

  const paginatedRules = displayRules.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  return (
    <>
      <Box mb={2}>
        <Grid container spacing={2} alignItems="center">
          <Grid size={{ xs: 12, md: variant === 'all' ? 4 : 6 }}>
            <TextField
              fullWidth
              variant="outlined"
              placeholder={variant === 'failed' ? 'Search failed rules...' : 'Search all rules...'}
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
          {variant === 'all' && (
            <Grid size={{ xs: 12, md: 3 }}>
              <TextField
                fullWidth
                select
                label="Result"
                value={resultFilter}
                onChange={(e) => onResultFilterChange(e.target.value)}
              >
                <MenuItem value="all">All Results</MenuItem>
                <MenuItem value="pass">Passed</MenuItem>
                <MenuItem value="fail">Failed</MenuItem>
                <MenuItem value="error">Error</MenuItem>
                <MenuItem value="notapplicable">N/A</MenuItem>
              </TextField>
            </Grid>
          )}
          <Grid size={{ xs: 12, md: 3 }}>
            <TextField
              fullWidth
              select
              label="Severity"
              value={severityFilter}
              onChange={(e) => onSeverityFilterChange(e.target.value)}
            >
              <MenuItem value="all">All Severities</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, md: variant === 'all' ? 2 : 3 }}>
            <Typography variant="body2" color="text.secondary">
              {variant === 'failed'
                ? `Showing ${displayRules.length} failed rules`
                : `${displayRules.length} rules`}
            </Typography>
          </Grid>
        </Grid>
      </Box>

      <TableContainer>
        <Table>
          <TableHead>
            <TableRow>
              {variant === 'all' && <TableCell>Result</TableCell>}
              <TableCell>Rule ID</TableCell>
              <TableCell>Title</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {paginatedRules.map((rule) => (
              <TableRow key={rule.rule_id}>
                {variant === 'all' && <TableCell>{getResultIcon(rule.result)}</TableCell>}
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {rule.rule_id}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography
                    variant="body2"
                    fontWeight={variant === 'failed' ? 'medium' : undefined}
                  >
                    {rule.title}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={rule.severity.toUpperCase()}
                    size="small"
                    sx={{
                      bgcolor: getSeverityColor(rule.severity),
                      color: rule.severity === 'low' ? 'black' : 'white',
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 0.5 }}>
                    <Tooltip title="View remediation">
                      <IconButton
                        size="small"
                        onClick={() => onViewRemediation(rule)}
                        color="primary"
                      >
                        <BuildIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Export rule details">
                      <IconButton size="small" onClick={() => onExportRule(rule)} color="info">
                        <FileCopyIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip
                      title={
                        reviewedRules.has(rule.rule_id)
                          ? 'Remove from review queue'
                          : 'Mark for review'
                      }
                    >
                      <IconButton
                        size="small"
                        onClick={() => onToggleReview(rule.rule_id)}
                        color={reviewedRules.has(rule.rule_id) ? 'warning' : 'default'}
                      >
                        {reviewedRules.has(rule.rule_id) ? (
                          <BookmarkIcon />
                        ) : (
                          <BookmarkBorderIcon />
                        )}
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Rescan this rule">
                      <IconButton
                        size="small"
                        onClick={() => onRescanRule(rule)}
                        color="secondary"
                        disabled={isLoading}
                      >
                        <RefreshIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <TablePagination
        rowsPerPageOptions={[10, 25, 50, 100]}
        component="div"
        count={displayRules.length}
        rowsPerPage={rowsPerPage}
        page={page}
        onPageChange={onPageChange}
        onRowsPerPageChange={onRowsPerPageChange}
      />
    </>
  );
};

export default ScanRulesTable;
