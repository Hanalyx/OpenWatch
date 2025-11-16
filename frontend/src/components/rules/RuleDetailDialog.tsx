import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  IconButton,
  Tabs,
  Tab,
  Chip,
  Stack,
  Divider,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  Tooltip,
  useTheme,
  alpha,
  TextField,
  MenuItem,
} from '@mui/material';
import {
  Close as CloseIcon,
  ContentCopy as CopyIcon,
  Launch as LaunchIcon,
  Code as CodeIcon,
  Description as DescriptionIcon,
  Security as SecurityIcon,
  Build as BuildIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { type Rule } from '../../store/slices/ruleSlice';
// Note: react-syntax-highlighter would be used in production
// import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
// import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface RuleDetailDialogProps {
  open: boolean;
  onClose: () => void;
  rule: Rule;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`rule-tabpanel-${index}`}
      aria-labelledby={`rule-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

const RuleDetailDialog: React.FC<RuleDetailDialogProps> = ({ open, onClose, rule }) => {
  const theme = useTheme();
  const [currentTab, setCurrentTab] = useState(0);
  const [selectedPlatform, setSelectedPlatform] = useState<string>(
    Object.keys(rule.platform_implementations || {})[0] || ''
  );
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <ErrorIcon />;
      case 'medium':
        return <WarningIcon />;
      case 'low':
        return <InfoIcon />;
      default:
        return <SecurityIcon />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return theme.palette.error.main;
      case 'medium':
        return theme.palette.warning.main;
      case 'low':
        return theme.palette.info.main;
      default:
        return theme.palette.grey[500];
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          minHeight: '80vh',
          maxHeight: '90vh',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box>
            <Typography variant="h5" component="div">
              {rule.metadata.name}
            </Typography>
            <Stack direction="row" spacing={1} mt={1} alignItems="center">
              <Chip
                label={rule.severity}
                size="small"
                icon={getSeverityIcon(rule.severity)}
                sx={{
                  backgroundColor: alpha(getSeverityColor(rule.severity), 0.1),
                  color: getSeverityColor(rule.severity),
                  fontWeight: 'medium',
                }}
              />
              <Chip
                label={rule.category}
                size="small"
                icon={<SecurityIcon fontSize="small" />}
                variant="outlined"
              />
              {rule.abstract && (
                <Chip label="Abstract" size="small" color="secondary" variant="outlined" />
              )}
            </Stack>
          </Box>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <Divider />

      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={currentTab} onChange={handleTabChange} aria-label="rule detail tabs">
          <Tab label="Overview" icon={<DescriptionIcon />} iconPosition="start" />
          <Tab label="Implementation" icon={<CodeIcon />} iconPosition="start" />
          <Tab label="Compliance" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Technical" icon={<BuildIcon />} iconPosition="start" />
        </Tabs>
      </Box>

      <DialogContent>
        {/* Overview Tab */}
        <TabPanel value={currentTab} index={0}>
          <Stack spacing={3}>
            {/* IDs */}
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Identifiers
              </Typography>
              <Stack spacing={1}>
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="body2" color="text.secondary" sx={{ minWidth: 120 }}>
                    Rule ID:
                  </Typography>
                  <Typography variant="body2" fontFamily="monospace">
                    {rule.rule_id}
                  </Typography>
                  <Tooltip title={copiedField === 'rule_id' ? 'Copied!' : 'Copy'}>
                    <IconButton size="small" onClick={() => handleCopy(rule.rule_id, 'rule_id')}>
                      <CopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="body2" color="text.secondary" sx={{ minWidth: 120 }}>
                    SCAP Rule ID:
                  </Typography>
                  <Typography variant="body2" fontFamily="monospace">
                    {rule.scap_rule_id}
                  </Typography>
                  <Tooltip title={copiedField === 'scap_id' ? 'Copied!' : 'Copy'}>
                    <IconButton
                      size="small"
                      onClick={() => handleCopy(rule.scap_rule_id, 'scap_id')}
                    >
                      <CopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Stack>
            </Paper>

            {/* Description */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Description
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {rule.metadata.description}
              </Typography>
            </Box>

            {/* Rationale */}
            {rule.metadata.rationale && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Rationale
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {rule.metadata.rationale}
                </Typography>
              </Box>
            )}

            {/* Tags */}
            {rule.tags && rule.tags.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                  {rule.tags.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      sx={{ backgroundColor: alpha(theme.palette.primary.main, 0.1) }}
                    />
                  ))}
                </Stack>
              </Box>
            )}

            {/* Dependencies */}
            {rule.dependencies &&
              (rule.dependencies.requires.length > 0 ||
                rule.dependencies.conflicts.length > 0 ||
                rule.dependencies.related.length > 0) && (
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Dependencies & Relationships
                  </Typography>
                  <Stack spacing={2}>
                    {rule.dependencies.requires.length > 0 && (
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          <strong>Requires:</strong>
                        </Typography>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {rule.dependencies.requires.map((dep) => (
                            <Chip
                              key={dep}
                              label={dep}
                              size="small"
                              variant="outlined"
                              icon={<CheckIcon fontSize="small" />}
                              color="success"
                            />
                          ))}
                        </Stack>
                      </Box>
                    )}

                    {rule.dependencies.conflicts.length > 0 && (
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          <strong>Conflicts with:</strong>
                        </Typography>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {rule.dependencies.conflicts.map((dep) => (
                            <Chip
                              key={dep}
                              label={dep}
                              size="small"
                              variant="outlined"
                              icon={<ErrorIcon fontSize="small" />}
                              color="error"
                            />
                          ))}
                        </Stack>
                      </Box>
                    )}

                    {rule.dependencies.related.length > 0 && (
                      <Box>
                        <Typography variant="body2" color="text.secondary" gutterBottom>
                          <strong>Related rules:</strong>
                        </Typography>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                          {rule.dependencies.related.map((dep) => (
                            <Chip key={dep} label={dep} size="small" variant="outlined" />
                          ))}
                        </Stack>
                      </Box>
                    )}
                  </Stack>
                </Paper>
              )}
          </Stack>
        </TabPanel>

        {/* Implementation Tab */}
        <TabPanel value={currentTab} index={1}>
          <Stack spacing={3}>
            {/* Platform Selector */}
            {Object.keys(rule.platform_implementations || {}).length > 1 && (
              <TextField
                select
                label="Select Platform"
                value={selectedPlatform}
                onChange={(e) => setSelectedPlatform(e.target.value)}
                size="small"
                sx={{ maxWidth: 300 }}
              >
                {Object.keys(rule.platform_implementations || {}).map((platform) => (
                  <MenuItem key={platform} value={platform}>
                    {platform}
                  </MenuItem>
                ))}
              </TextField>
            )}

            {/* Platform Implementation */}
            {selectedPlatform && rule.platform_implementations?.[selectedPlatform] && (
              <>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Platform Information
                  </Typography>
                  <Stack spacing={1}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Platform: <strong>{selectedPlatform}</strong>
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Supported Versions:{' '}
                        <strong>
                          {rule.platform_implementations[selectedPlatform].versions.join(', ')}
                        </strong>
                      </Typography>
                    </Box>
                    {rule.platform_implementations[selectedPlatform].config_files && (
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          Configuration Files:
                        </Typography>
                        <Stack direction="row" spacing={0.5} mt={0.5}>
                          {rule.platform_implementations[selectedPlatform].config_files!.map(
                            (file) => (
                              <Chip key={file} label={file} size="small" variant="outlined" />
                            )
                          )}
                        </Stack>
                      </Box>
                    )}
                  </Stack>
                </Paper>

                {/* Check Command */}
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Check Command
                  </Typography>
                  <Paper
                    sx={{
                      p: 2,
                      backgroundColor: theme.palette.grey[900],
                      color: theme.palette.common.white,
                      overflow: 'auto',
                    }}
                  >
                    <Typography
                      variant="body2"
                      component="code"
                      sx={{
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {rule.platform_implementations[selectedPlatform].check_command}
                    </Typography>
                  </Paper>
                </Box>

                {/* Enable Command */}
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Enable/Fix Command
                  </Typography>
                  <Paper
                    sx={{
                      p: 2,
                      backgroundColor: theme.palette.grey[900],
                      color: theme.palette.common.white,
                      overflow: 'auto',
                    }}
                  >
                    <Typography
                      variant="body2"
                      component="code"
                      sx={{
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {rule.platform_implementations[selectedPlatform].enable_command}
                    </Typography>
                  </Paper>
                  <Alert severity="warning" sx={{ mt: 1 }}>
                    Always test commands in a non-production environment before applying to
                    production systems.
                  </Alert>
                </Box>
              </>
            )}

            {/* Inheritance Information */}
            {rule.inheritance && (
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Inheritance Information
                </Typography>
                <Stack spacing={1}>
                  {rule.inheritance.parent_rule && (
                    <Typography variant="body2" color="text.secondary">
                      Inherits from: <Chip label={rule.inheritance.parent_rule} size="small" />
                    </Typography>
                  )}
                  {rule.inheritance.overridden_parameters.length > 0 && (
                    <Box>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        Overridden parameters:
                      </Typography>
                      <Stack direction="row" spacing={0.5}>
                        {rule.inheritance.overridden_parameters.map((param) => (
                          <Chip key={param} label={param} size="small" variant="outlined" />
                        ))}
                      </Stack>
                    </Box>
                  )}
                </Stack>
              </Paper>
            )}
          </Stack>
        </TabPanel>

        {/* Compliance Tab */}
        <TabPanel value={currentTab} index={2}>
          <Stack spacing={3}>
            {/* Frameworks */}
            {Object.keys(rule.frameworks || {}).length > 0 ? (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Framework</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Controls</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(rule.frameworks).map(([framework, versions]) =>
                      Object.entries(versions).map(([version, controls]) => (
                        <TableRow key={`${framework}-${version}`}>
                          <TableCell>
                            <Typography variant="body2" fontWeight="medium">
                              {framework.toUpperCase()}
                            </Typography>
                          </TableCell>
                          <TableCell>{version}</TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                              {controls.map((control) => (
                                <Chip
                                  key={control}
                                  label={control}
                                  size="small"
                                  variant="outlined"
                                />
                              ))}
                            </Stack>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Alert severity="info">
                No compliance framework mappings available for this rule.
              </Alert>
            )}

            {/* Security Function */}
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Security Classification
              </Typography>
              <Stack spacing={1}>
                <Typography variant="body2" color="text.secondary">
                  Security Function: <strong>{rule.security_function}</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Category:{' '}
                  <strong>
                    {rule.category
                      .split('_')
                      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
                      .join(' ')}
                  </strong>
                </Typography>
              </Stack>
            </Paper>
          </Stack>
        </TabPanel>

        {/* Technical Tab */}
        <TabPanel value={currentTab} index={3}>
          <Stack spacing={3}>
            {/* Metadata */}
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Metadata
              </Typography>
              <Stack spacing={1}>
                <Typography variant="body2" color="text.secondary">
                  Source: <strong>{rule.metadata.source}</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Created: <strong>{new Date(rule.created_at).toLocaleString()}</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Last Updated: <strong>{new Date(rule.updated_at).toLocaleString()}</strong>
                </Typography>
              </Stack>
            </Paper>

            {/* Parameter Overrides */}
            {rule.parameter_overrides && Object.keys(rule.parameter_overrides).length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Parameter Overrides
                </Typography>
                <Paper
                  sx={{
                    p: 2,
                    backgroundColor: theme.palette.grey[900],
                    color: theme.palette.common.white,
                    overflow: 'auto',
                  }}
                >
                  <Typography
                    variant="body2"
                    component="pre"
                    sx={{
                      fontFamily: 'monospace',
                      whiteSpace: 'pre',
                      margin: 0,
                    }}
                  >
                    {JSON.stringify(rule.parameter_overrides, null, 2)}
                  </Typography>
                </Paper>
              </Box>
            )}

            {/* Raw Rule Data */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Raw Rule Data
              </Typography>
              <Paper
                sx={{
                  p: 2,
                  backgroundColor: theme.palette.grey[900],
                  color: theme.palette.common.white,
                  overflow: 'auto',
                  maxHeight: 400,
                }}
              >
                <Typography
                  variant="body2"
                  component="pre"
                  sx={{
                    fontFamily: 'monospace',
                    whiteSpace: 'pre',
                    margin: 0,
                    fontSize: '0.75rem',
                  }}
                >
                  {JSON.stringify(rule, null, 2)}
                </Typography>
              </Paper>
            </Box>
          </Stack>
        </TabPanel>
      </DialogContent>

      <DialogActions sx={{ p: 2 }}>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default RuleDetailDialog;
