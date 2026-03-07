/**
 * Quick Action Bar for completed scans.
 *
 * Shows remediation/failure shortcuts when rules fail,
 * or an "All Checks Passed" banner when compliant.
 */

import React from 'react';
import { Box, Button, Paper, Stack, Tooltip, Typography } from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  GetApp as DownloadIcon,
  Build as BuildIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';

interface ScanQuickActionBarProps {
  failedRules: number;
  onViewFailures: () => void;
  onRemediate: () => void;
  onExport: (event: React.MouseEvent<HTMLElement>) => void;
  onRescan: () => void;
}

const ScanQuickActionBar: React.FC<ScanQuickActionBarProps> = ({
  failedRules,
  onViewFailures,
  onRemediate,
  onExport,
  onRescan,
}) => {
  return (
    <Paper
      sx={{
        p: 2,
        mb: 3,
        borderRadius: 2,
        boxShadow: 2,
        bgcolor: failedRules > 0 ? 'error.50' : 'success.50',
      }}
    >
      <Stack direction="row" spacing={2} justifyContent="space-between" alignItems="center">
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          {failedRules > 0 ? (
            <>
              <Button
                variant="contained"
                color="error"
                size="large"
                startIcon={<BuildIcon />}
                onClick={onRemediate}
              >
                Remediate {failedRules} Failed Rules
              </Button>
              <Button
                variant="outlined"
                color="error"
                startIcon={<FilterIcon />}
                onClick={onViewFailures}
              >
                View Failures
              </Button>
            </>
          ) : (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <CheckCircleIcon color="success" sx={{ fontSize: 40 }} />
              <Box>
                <Typography variant="h6" color="success.main" fontWeight="bold">
                  All Checks Passed!
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  System is compliant with the selected profile
                </Typography>
              </Box>
            </Box>
          )}
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Export report">
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={onExport}
              size="medium"
            >
              Export
            </Button>
          </Tooltip>
          <Tooltip title="Run new scan with same configuration">
            <Button variant="outlined" startIcon={<RefreshIcon />} onClick={onRescan} size="medium">
              Rescan
            </Button>
          </Tooltip>
        </Box>
      </Stack>
    </Paper>
  );
};

export default ScanQuickActionBar;
