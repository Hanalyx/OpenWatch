/**
 * Dialog components for ScanDetail:
 * - ScanRemediationDialog: stepper showing remediation steps
 * - ScanExportRuleDialog: format chooser for exporting rule details
 */

import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Button,
  IconButton,
  Paper,
  Link,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogContentText,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import {
  Build as BuildIcon,
  GetApp as DownloadIcon,
  FileCopy as FileCopyIcon,
  Terminal as TerminalIcon,
  Code as CodeIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import type { RuleResult, RemediationStep } from './scanTypes';
import { generateRemediationSteps } from './scanUtils';

// ---------------------------------------------------------------------------
// Remediation Dialog
// ---------------------------------------------------------------------------

interface ScanRemediationDialogProps {
  open: boolean;
  rule: RuleResult | null;
  onClose: () => void;
  onCopySteps: () => void;
  showSnackbar: (message: string, severity: 'success' | 'error' | 'warning' | 'info') => void;
}

export const ScanRemediationDialog: React.FC<ScanRemediationDialogProps> = ({
  open,
  rule,
  onClose,
  onCopySteps,
  showSnackbar,
}) => {
  const steps: RemediationStep[] = rule ? generateRemediationSteps(rule) : [];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <BuildIcon color="primary" />
          <Typography variant="h6">Remediation Steps</Typography>
        </Box>
      </DialogTitle>
      <DialogContent>
        {rule && (
          <>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                {rule.title}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ fontFamily: 'monospace', mb: 1 }}
              >
                {rule.rule_id}
              </Typography>
              <Chip
                label={rule.severity.toUpperCase()}
                size="small"
                color={
                  rule.severity === 'high'
                    ? 'error'
                    : rule.severity === 'medium'
                      ? 'warning'
                      : 'info'
                }
                sx={{ mb: 2 }}
              />
              <Typography variant="body2">{rule.description}</Typography>
            </Box>

            <Stepper orientation="vertical">
              {steps.map((step, index) => (
                <Step key={index} active>
                  <StepLabel>
                    <Typography variant="subtitle1" fontWeight="bold">
                      {step.title}
                    </Typography>
                  </StepLabel>
                  <StepContent>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ mb: 1, whiteSpace: 'pre-wrap' }}>
                        {step.description}
                      </Typography>

                      {(step.title.includes('SCAP Compliance Fix Text') ||
                        step.title.includes('OpenSCAP Evaluation Remediation')) && (
                        <Chip
                          size="small"
                          color="success"
                          label={
                            step.title.includes('Fix Text')
                              ? 'SCAP Compliance Checker'
                              : 'OpenSCAP Evaluation Report'
                          }
                          sx={{ mb: 2 }}
                        />
                      )}
                    </Box>

                    {step.command && (
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 0,
                          mb: 2,
                          bgcolor: '#f8f9fa',
                          border: '1px solid #e9ecef',
                          borderRadius: 2,
                          overflow: 'hidden',
                        }}
                      >
                        <Box
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                            p: 1.5,
                            bgcolor: '#e9ecef',
                            borderBottom: '1px solid #dee2e6',
                          }}
                        >
                          {step.type === 'command' ? (
                            <TerminalIcon color="primary" />
                          ) : (
                            <CodeIcon color="info" />
                          )}
                          <Typography variant="caption" fontWeight="bold" sx={{ color: '#495057' }}>
                            {step.type === 'command' ? 'Command:' : 'Configuration:'}
                          </Typography>
                          <IconButton
                            size="small"
                            onClick={() => {
                              navigator.clipboard.writeText(step.command || '');
                              showSnackbar('Command copied to clipboard', 'success');
                            }}
                            sx={{ ml: 'auto' }}
                          >
                            <FileCopyIcon fontSize="small" />
                          </IconButton>
                        </Box>
                        <Box
                          component="pre"
                          sx={{
                            p: 2,
                            m: 0,
                            fontFamily: '"Monaco", "Menlo", "Ubuntu Mono", monospace',
                            fontSize: '0.85rem',
                            lineHeight: 1.5,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                            bgcolor: '#f8f9fa',
                            color: '#212529',
                            overflow: 'auto',
                            '&::-webkit-scrollbar': {
                              height: 6,
                              width: 6,
                            },
                            '&::-webkit-scrollbar-thumb': {
                              backgroundColor: 'rgba(0,0,0,0.2)',
                              borderRadius: 3,
                            },
                          }}
                        >
                          {step.command}
                        </Box>
                      </Paper>
                    )}

                    {step.documentation && (
                      <Box sx={{ mt: 2 }}>
                        {step.documentation.startsWith('http') ? (
                          <Link
                            href={step.documentation}
                            target="_blank"
                            rel="noopener noreferrer"
                            sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
                          >
                            <OpenInNewIcon fontSize="small" />
                            <Typography variant="caption">View Documentation</Typography>
                          </Link>
                        ) : (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontStyle: 'italic' }}
                          >
                            Source: {step.documentation}
                          </Typography>
                        )}
                      </Box>
                    )}
                  </StepContent>
                </Step>
              ))}
            </Stepper>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        <Button variant="contained" startIcon={<FileCopyIcon />} onClick={onCopySteps}>
          Copy All Steps
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// ---------------------------------------------------------------------------
// Export Rule Dialog
// ---------------------------------------------------------------------------

interface ScanExportRuleDialogProps {
  open: boolean;
  rule: RuleResult | null;
  onClose: () => void;
  onExport: (format: 'json' | 'csv') => void;
}

export const ScanExportRuleDialog: React.FC<ScanExportRuleDialogProps> = ({
  open,
  rule,
  onClose,
  onExport,
}) => {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <FileCopyIcon color="info" />
          <Typography variant="h6">Export Rule Details</Typography>
        </Box>
      </DialogTitle>
      <DialogContent>
        {rule && (
          <>
            <DialogContentText sx={{ mb: 2 }}>
              Export detailed information for the following rule:
            </DialogContentText>
            <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
              <Typography variant="subtitle1" fontWeight="bold">
                {rule.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                {rule.rule_id}
              </Typography>
            </Box>
            <DialogContentText>
              Choose the export format for the rule details including remediation steps:
            </DialogContentText>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => onExport('csv')}>
          Export CSV
        </Button>
        <Button variant="contained" startIcon={<DownloadIcon />} onClick={() => onExport('json')}>
          Export JSON
        </Button>
      </DialogActions>
    </Dialog>
  );
};
