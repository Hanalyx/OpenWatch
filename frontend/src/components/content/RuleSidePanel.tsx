import React from 'react';
import {
  Drawer,
  Box,
  Typography,
  IconButton,
  Card,
  CardContent,
  Chip,
  Grid,
  Divider,
  useTheme,
  alpha,
  Stack,
  Alert,
} from '@mui/material';
import {
  Close as CloseIcon,
  Info as InfoIcon,
  Link as LinkIcon,
  Build as BuildIcon,
  Computer as PlatformIcon,
  Security as SecurityIcon,
  Assessment as ComplianceIcon,
} from '@mui/icons-material';
import { type Rule } from '../../store/slices/ruleSlice';
import SafeHTMLRenderer from '../common/SafeHTMLRenderer';

interface RuleSidePanelProps {
  open: boolean;
  rule: Rule | null;
  onClose: () => void;
}

const RuleSidePanel: React.FC<RuleSidePanelProps> = ({ open, rule, onClose }) => {
  const theme = useTheme();

  if (!rule) return null;

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return theme.palette.error.main;
      case 'high':
        return theme.palette.error.light;
      case 'medium':
        return theme.palette.warning.main;
      case 'low':
        return theme.palette.info.main;
      default:
        return theme.palette.grey[500];
    }
  };

  // Helper to check if frameworks have data
  const hasFrameworkData = () => {
    if (!rule.frameworks) return false;
    return Object.keys(rule.frameworks).some((fw) => {
      const fwData = rule.frameworks[fw];
      return fwData && typeof fwData === 'object' && Object.keys(fwData).length > 0;
    });
  };

  // Helper to check if platform implementations have data
  const hasPlatformData = () => {
    if (!rule.platform_implementations) return false;
    return Object.keys(rule.platform_implementations).some((platform) => {
      const impl = rule.platform_implementations[platform];
      return (
        impl &&
        typeof impl === 'object' &&
        Object.keys(impl).length > 0 &&
        (impl.versions?.length > 0 || impl.check_command || impl.enable_command)
      );
    });
  };

  // Helper to check if dependencies have data
  const hasDependencies = () => {
    return (
      rule.dependencies &&
      ((rule.dependencies.requires && rule.dependencies.requires.length > 0) ||
        (rule.dependencies.conflicts && rule.dependencies.conflicts.length > 0) ||
        (rule.dependencies.related && rule.dependencies.related.length > 0))
    );
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      variant="temporary"
      sx={{
        '& .MuiDrawer-paper': {
          width: { xs: '100%', sm: 480, md: 520 },
          borderLeft: `1px solid ${theme.palette.divider}`,
        },
      }}
    >
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box
          sx={{
            p: 2,
            borderBottom: `1px solid ${theme.palette.divider}`,
            backgroundColor: alpha(theme.palette.primary.main, 0.02),
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <Box sx={{ flex: 1, mr: 2 }}>
              <Typography variant="h6" sx={{ mb: 1, lineHeight: 1.3 }}>
                {rule.metadata?.name || 'Unnamed Rule'}
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
                <Chip
                  label={rule.severity || 'unknown'}
                  size="small"
                  sx={{
                    backgroundColor: alpha(getSeverityColor(rule.severity || 'unknown'), 0.1),
                    color: getSeverityColor(rule.severity || 'unknown'),
                    fontWeight: 'medium',
                  }}
                />
                <Chip
                  label={rule.category || 'uncategorized'}
                  size="small"
                  variant="outlined"
                  sx={{ textTransform: 'capitalize' }}
                />
              </Stack>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
              >
                {rule.rule_id}
              </Typography>
            </Box>
            <IconButton onClick={onClose} sx={{ alignSelf: 'flex-start' }}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>

        {/* Content */}
        <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
          <Stack spacing={3}>
            {/* Description */}
            <Card variant="outlined">
              <CardContent>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                >
                  <InfoIcon color="primary" fontSize="small" />
                  Description
                </Typography>
                <Box sx={{ mb: rule.metadata?.rationale ? 2 : 0 }}>
                  {rule.metadata?.description ? (
                    <SafeHTMLRenderer html={rule.metadata.description} variant="body2" />
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      No description available
                    </Typography>
                  )}
                </Box>
                {rule.metadata?.rationale && (
                  <>
                    <Typography
                      variant="subtitle2"
                      color="text.secondary"
                      gutterBottom
                      sx={{ mt: 2 }}
                    >
                      Rationale
                    </Typography>
                    <SafeHTMLRenderer html={rule.metadata.rationale} variant="body2" />
                  </>
                )}
              </CardContent>
            </Card>

            {/* SCAP Reference */}
            {rule.scap_rule_id && (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <SecurityIcon color="primary" fontSize="small" />
                    SCAP Reference
                  </Typography>
                  <Typography
                    variant="body2"
                    sx={{
                      fontFamily: 'monospace',
                      backgroundColor: alpha(theme.palette.common.black, 0.05),
                      p: 1.5,
                      borderRadius: 1,
                      border: `1px solid ${alpha(theme.palette.common.black, 0.1)}`,
                      wordBreak: 'break-all',
                    }}
                  >
                    {rule.scap_rule_id}
                  </Typography>
                </CardContent>
              </Card>
            )}

            {/* Compliance Frameworks */}
            {hasFrameworkData() ? (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <LinkIcon color="primary" fontSize="small" />
                    Compliance Frameworks
                  </Typography>
                  <Stack spacing={2}>
                    {Object.entries(rule.frameworks || {})
                      .filter(
                        ([_, versions]) =>
                          versions &&
                          typeof versions === 'object' &&
                          Object.keys(versions).length > 0
                      )
                      .map(([framework, versions]) => (
                        <Box key={framework}>
                          <Typography
                            variant="subtitle2"
                            color="primary"
                            gutterBottom
                            sx={{ textTransform: 'uppercase' }}
                          >
                            {framework}
                          </Typography>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
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
                  </Stack>
                </CardContent>
              </Card>
            ) : (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <LinkIcon color="primary" fontSize="small" />
                    Compliance Frameworks
                  </Typography>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    No compliance framework mappings available for this rule.
                  </Alert>
                </CardContent>
              </Card>
            )}

            {/* Tags */}
            {rule.tags && rule.tags.length > 0 && (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <ComplianceIcon color="primary" fontSize="small" />
                    Tags
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {rule.tags.map((tag) => (
                      <Chip key={tag} label={tag} size="small" color="primary" variant="outlined" />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            )}

            {/* Platform Implementation */}
            {hasPlatformData() ? (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <BuildIcon color="primary" fontSize="small" />
                    Platform Implementation
                  </Typography>
                  <Stack spacing={2}>
                    {Object.entries(rule.platform_implementations || {})
                      .filter(
                        ([_, impl]) =>
                          impl &&
                          typeof impl === 'object' &&
                          Object.keys(impl).length > 0 &&
                          (impl.versions?.length > 0 || impl.check_command || impl.enable_command)
                      )
                      .map(([platform, impl]) => (
                        <Card
                          key={platform}
                          variant="outlined"
                          sx={{ backgroundColor: alpha(theme.palette.common.black, 0.02) }}
                        >
                          <CardContent sx={{ pb: '16px !important' }}>
                            <Typography
                              variant="subtitle1"
                              gutterBottom
                              sx={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 1,
                                textTransform: 'capitalize',
                                color: theme.palette.primary.main,
                              }}
                            >
                              <PlatformIcon fontSize="small" />
                              {platform}
                            </Typography>

                            <Grid container spacing={2}>
                              {impl.versions && impl.versions.length > 0 && (
                                <Grid item xs={12}>
                                  <Typography variant="body2" color="text.secondary" gutterBottom>
                                    Supported Versions
                                  </Typography>
                                  <Typography
                                    variant="body2"
                                    sx={{ fontFamily: 'monospace', mb: 2 }}
                                  >
                                    {impl.versions.join(', ')}
                                  </Typography>
                                </Grid>
                              )}

                              {impl.check_command && (
                                <Grid item xs={12}>
                                  <Typography variant="body2" color="text.secondary" gutterBottom>
                                    Check Command
                                  </Typography>
                                  <Typography
                                    variant="body2"
                                    sx={{
                                      fontFamily: 'monospace',
                                      backgroundColor: alpha(theme.palette.common.black, 0.05),
                                      p: 1,
                                      borderRadius: 1,
                                      border: `1px solid ${alpha(theme.palette.common.black, 0.1)}`,
                                      fontSize: '0.75rem',
                                      mb: 2,
                                    }}
                                  >
                                    {impl.check_command}
                                  </Typography>
                                </Grid>
                              )}

                              {impl.enable_command && (
                                <Grid item xs={12}>
                                  <Typography variant="body2" color="text.secondary" gutterBottom>
                                    Enable Command
                                  </Typography>
                                  <Typography
                                    variant="body2"
                                    sx={{
                                      fontFamily: 'monospace',
                                      backgroundColor: alpha(theme.palette.common.black, 0.05),
                                      p: 1,
                                      borderRadius: 1,
                                      border: `1px solid ${alpha(theme.palette.common.black, 0.1)}`,
                                      fontSize: '0.75rem',
                                    }}
                                  >
                                    {impl.enable_command}
                                  </Typography>
                                </Grid>
                              )}
                            </Grid>
                          </CardContent>
                        </Card>
                      ))}
                  </Stack>
                </CardContent>
              </Card>
            ) : (
              <Card variant="outlined">
                <CardContent>
                  <Typography
                    variant="h6"
                    gutterBottom
                    sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <BuildIcon color="primary" fontSize="small" />
                    Platform Implementation
                  </Typography>
                  <Alert severity="info" sx={{ mt: 1 }}>
                    No platform implementation details available for this rule.
                  </Alert>
                </CardContent>
              </Card>
            )}

            {/* Dependencies */}
            {hasDependencies() && (
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Dependencies
                  </Typography>
                  <Stack spacing={2}>
                    {rule.dependencies.requires && rule.dependencies.requires.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Requires
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.requires.map((dep) => (
                            <Chip
                              key={dep}
                              label={dep}
                              size="small"
                              color="success"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}

                    {rule.dependencies.conflicts && rule.dependencies.conflicts.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Conflicts
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.conflicts.map((dep) => (
                            <Chip
                              key={dep}
                              label={dep}
                              size="small"
                              color="error"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}

                    {rule.dependencies.related && rule.dependencies.related.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Related
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.related.map((dep) => (
                            <Chip
                              key={dep}
                              label={dep}
                              size="small"
                              color="info"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                  </Stack>
                </CardContent>
              </Card>
            )}
          </Stack>
        </Box>
      </Box>
    </Drawer>
  );
};

export default RuleSidePanel;
