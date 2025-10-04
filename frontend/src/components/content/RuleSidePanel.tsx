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
import { Rule } from '../../store/slices/ruleSlice';

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
      case 'critical': return theme.palette.error.main;
      case 'high': return theme.palette.error.light;
      case 'medium': return theme.palette.warning.main;
      case 'low': return theme.palette.info.main;
      default: return theme.palette.grey[500];
    }
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
                {rule.metadata.name}
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
                <Chip
                  label={rule.severity}
                  size="small"
                  sx={{
                    backgroundColor: alpha(getSeverityColor(rule.severity), 0.1),
                    color: getSeverityColor(rule.severity),
                    fontWeight: 'medium',
                  }}
                />
                <Chip
                  label={rule.category}
                  size="small"
                  variant="outlined"
                  sx={{ textTransform: 'capitalize' }}
                />
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
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
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <InfoIcon color="primary" fontSize="small" />
                  Description
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.6 }}>
                  {rule.metadata.description}
                </Typography>
                {rule.metadata.rationale && (
                  <>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Rationale
                    </Typography>
                    <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                      {rule.metadata.rationale}
                    </Typography>
                  </>
                )}
              </CardContent>
            </Card>

            {/* SCAP Reference */}
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
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

            {/* Compliance Frameworks */}
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <LinkIcon color="primary" fontSize="small" />
                  Compliance Frameworks
                </Typography>
                <Stack spacing={2}>
                  {Object.entries(rule.frameworks).map(([framework, versions]) => (
                    <Box key={framework}>
                      <Typography variant="subtitle2" color="primary" gutterBottom sx={{ textTransform: 'uppercase' }}>
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

            {/* Tags */}
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ComplianceIcon color="primary" fontSize="small" />
                  Tags
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {rule.tags.map(tag => (
                    <Chip key={tag} label={tag} size="small" color="primary" variant="outlined" />
                  ))}
                </Box>
              </CardContent>
            </Card>

            {/* Platform Implementation */}
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <BuildIcon color="primary" fontSize="small" />
                  Platform Implementation
                </Typography>
                <Stack spacing={2}>
                  {Object.entries(rule.platform_implementations || {}).map(([platform, impl]) => (
                    <Card key={platform} variant="outlined" sx={{ backgroundColor: alpha(theme.palette.common.black, 0.02) }}>
                      <CardContent sx={{ pb: '16px !important' }}>
                        <Typography variant="subtitle1" gutterBottom sx={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: 1,
                          textTransform: 'capitalize',
                          color: theme.palette.primary.main,
                        }}>
                          <PlatformIcon fontSize="small" />
                          {platform}
                        </Typography>
                        
                        <Grid container spacing={2}>
                          <Grid item xs={12}>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                              Supported Versions
                            </Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', mb: 2 }}>
                              {Array.isArray(impl.versions) ? impl.versions.join(', ') : 'All versions'}
                            </Typography>
                          </Grid>
                          
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

            {/* Dependencies */}
            {(rule.dependencies?.requires?.length || rule.dependencies?.conflicts?.length || rule.dependencies?.related?.length) && (
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Dependencies
                  </Typography>
                  <Stack spacing={2}>
                    {rule.dependencies.requires?.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Requires
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.requires.map(dep => (
                            <Chip key={dep} label={dep} size="small" color="success" variant="outlined" />
                          ))}
                        </Box>
                      </Box>
                    )}
                    
                    {rule.dependencies.conflicts?.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Conflicts
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.conflicts.map(dep => (
                            <Chip key={dep} label={dep} size="small" color="error" variant="outlined" />
                          ))}
                        </Box>
                      </Box>
                    )}
                    
                    {rule.dependencies.related?.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                          Related
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {rule.dependencies.related.map(dep => (
                            <Chip key={dep} label={dep} size="small" color="info" variant="outlined" />
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