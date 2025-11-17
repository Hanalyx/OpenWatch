import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Container,
  Typography,
  Grid,
  Chip,
  IconButton,
  LinearProgress,
  Alert,
  Snackbar,
  useTheme,
  alpha,
  CircularProgress,
  Paper,
  Tab,
  Tabs,
} from '@mui/material';
import {
  Psychology,
  Hub,
  AutoFixHigh,
  Visibility,
  Launch,
  Security,
  Assessment,
  Shield,
  Policy,
  Speed,
  TrendingUp,
  AccountTree,
} from '@mui/icons-material';

// Types for the Universal Compliance Intelligence Platform
interface SemanticRule {
  id: string;
  semantic_name: string;
  scap_rule_id: string;
  title: string;
  compliance_intent: string;
  business_impact: 'high' | 'medium' | 'low';
  risk_level: 'high' | 'medium' | 'low';
  frameworks: string[];
  remediation_complexity: 'simple' | 'moderate' | 'complex';
  estimated_fix_time: number;
  remediation_available: boolean;
  confidence_score: number;
}

interface FrameworkIntelligence {
  framework: string;
  displayName: string;
  semanticRulesCount: number;
  crossFrameworkMappings: number;
  remediationCoverage: number;
  businessImpactBreakdown: {
    high: number;
    medium: number;
    low: number;
  };
  topSemanticRules: SemanticRule[];
  estimatedRemediationTime: number;
  compatibleDistributions: string[];
  complianceScore?: number;
}

interface ComplianceIntelligenceOverview {
  totalFrameworks: number;
  semanticRulesCount: number;
  universalCoverage: number;
  remediationReadiness: number;
  lastIntelligenceUpdate: string;
}

// Framework configuration with colors and icons
const frameworkConfig = {
  stig: {
    displayName: 'DISA STIG',
    color: '#D32F2F',
    icon: Security,
  },
  cis: {
    displayName: 'CIS Controls',
    color: '#388E3C',
    icon: Shield,
  },
  nist: {
    displayName: 'NIST Cybersecurity',
    color: '#7B1FA2',
    icon: Assessment,
  },
  pci_dss: {
    displayName: 'PCI DSS',
    color: '#F57C00',
    icon: Policy,
  },
};

const ComplianceIntelligence: React.FC = () => {
  const theme = useTheme();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTab, setSelectedTab] = useState(0);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({ open: false, message: '', severity: 'info' });

  // State for intelligence overview
  const [overview, _setOverview] = useState<ComplianceIntelligenceOverview>({
    totalFrameworks: 4,
    semanticRulesCount: 14,
    universalCoverage: 94,
    remediationReadiness: 87,
    lastIntelligenceUpdate: new Date().toLocaleTimeString(),
  });

  // State for framework intelligence
  const [frameworkData, setFrameworkData] = useState<FrameworkIntelligence[]>([]);
  // Semantic rules state - setter declared for future use in intelligence filtering features
  const [_semanticRules, _setSemanticRules] = useState<SemanticRule[]>([]);

  // Load compliance intelligence data
  useEffect(() => {
    loadComplianceIntelligence();
  }, []);

  const loadComplianceIntelligence = async () => {
    try {
      setLoading(true);
      setError(null);

      // Mock data for demonstration - replace with actual API calls
      const mockFrameworkData = Object.entries(frameworkConfig).map(([key, config]) => ({
        framework: key,
        displayName: config.displayName,
        semanticRulesCount: Math.floor(Math.random() * 10) + 5,
        crossFrameworkMappings: Math.floor(Math.random() * 5) + 2,
        remediationCoverage: Math.floor(Math.random() * 30) + 70,
        businessImpactBreakdown: {
          high: Math.floor(Math.random() * 3) + 1,
          medium: Math.floor(Math.random() * 5) + 2,
          low: Math.floor(Math.random() * 4) + 1,
        },
        topSemanticRules: [],
        estimatedRemediationTime: Math.floor(Math.random() * 60) + 30,
        compatibleDistributions: ['RHEL 9', 'Ubuntu 22.04', 'Oracle Linux 8'],
        complianceScore: Math.floor(Math.random() * 20) + 80,
      }));

      setFrameworkData(mockFrameworkData);
    } catch (err: any) {
      console.error('Failed to load compliance intelligence:', err);
      setError('Failed to load compliance intelligence data');
    } finally {
      setLoading(false);
    }
  };

  const handleExploreFramework = (framework: FrameworkIntelligence) => {
    setSnackbar({
      open: true,
      message: `Exploring ${framework.displayName} intelligence - full implementation coming soon!`,
      severity: 'info',
    });
  };

  // Rule name formatter - utility for future semantic rule display features
  const _formatRuleName = (name: string) => {
    return name.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
  };

  if (loading) {
    return (
      <Container maxWidth={false} sx={{ py: 4 }}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress size={60} />
        </Box>
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth={false} sx={{ py: 4 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Button variant="contained" onClick={loadComplianceIntelligence}>
          Retry Loading
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth={false} sx={{ py: 4 }}>
      {/* Intelligence Overview Header */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12}>
          <Card className="intelligence-overview" elevation={3}>
            <CardHeader
              title={
                <Box display="flex" alignItems="center" gap={2}>
                  <Psychology sx={{ color: theme.palette.primary.main, fontSize: 32 }} />
                  <Box>
                    <Typography variant="h4" fontWeight="bold" color="primary">
                      Universal Compliance Intelligence Platform
                    </Typography>
                    <Typography variant="subtitle1" color="text.secondary">
                      Semantic understanding across {overview.totalFrameworks} compliance frameworks
                    </Typography>
                  </Box>
                </Box>
              }
            />
            <CardContent>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6} md={3}>
                  <Paper
                    sx={{
                      p: 3,
                      textAlign: 'center',
                      background: alpha(theme.palette.primary.main, 0.1),
                    }}
                  >
                    <Psychology sx={{ fontSize: 40, color: theme.palette.primary.main, mb: 1 }} />
                    <Typography variant="h4" fontWeight="bold" color="primary">
                      {overview.semanticRulesCount.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Semantic Rules
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      +156 this month
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Paper
                    sx={{
                      p: 3,
                      textAlign: 'center',
                      background: alpha(theme.palette.success.main, 0.1),
                    }}
                  >
                    <AccountTree sx={{ fontSize: 40, color: theme.palette.success.main, mb: 1 }} />
                    <Typography variant="h4" fontWeight="bold" color="success.main">
                      {overview.universalCoverage}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Framework Coverage
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      Universal mapping
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Paper
                    sx={{
                      p: 3,
                      textAlign: 'center',
                      background: alpha(theme.palette.warning.main, 0.1),
                    }}
                  >
                    <AutoFixHigh sx={{ fontSize: 40, color: theme.palette.warning.main, mb: 1 }} />
                    <Typography variant="h4" fontWeight="bold" color="warning.main">
                      {overview.remediationReadiness}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Remediation Ready
                    </Typography>
                    <Typography variant="caption" color="success.main">
                      AEGIS integrated
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Paper
                    sx={{
                      p: 3,
                      textAlign: 'center',
                      background: alpha(theme.palette.info.main, 0.1),
                    }}
                  >
                    <TrendingUp sx={{ fontSize: 40, color: theme.palette.info.main, mb: 1 }} />
                    <Typography variant="h4" fontWeight="bold" color="info.main">
                      {overview.totalFrameworks}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Active Frameworks
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Updated {overview.lastIntelligenceUpdate}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for different views */}
      <Card sx={{ mb: 4 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, newValue) => setSelectedTab(newValue)}
          variant="fullWidth"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab
            label={
              <Box display="flex" alignItems="center" gap={1}>
                <AccountTree />
                Framework Intelligence
              </Box>
            }
          />
          <Tab
            label={
              <Box display="flex" alignItems="center" gap={1}>
                <Psychology />
                Semantic Rule Explorer
              </Box>
            }
          />
          <Tab
            label={
              <Box display="flex" alignItems="center" gap={1}>
                <Speed />
                Compliance Analytics
              </Box>
            }
          />
        </Tabs>
      </Card>

      {/* Tab Content */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {frameworkData.map((framework) => {
            const config = frameworkConfig[framework.framework as keyof typeof frameworkConfig];
            const IconComponent = config.icon;

            return (
              <Grid item xs={12} md={6} key={framework.framework}>
                <Card elevation={3} sx={{ height: '100%' }}>
                  <CardHeader
                    title={
                      <Box display="flex" alignItems="center" gap={1}>
                        <IconComponent sx={{ color: config.color }} />
                        <Typography variant="h6">{framework.displayName}</Typography>
                        <Chip
                          label={`${framework.remediationCoverage}% Remediation Ready`}
                          color={framework.remediationCoverage > 80 ? 'success' : 'warning'}
                          size="small"
                        />
                      </Box>
                    }
                    action={
                      <IconButton onClick={() => handleExploreFramework(framework)}>
                        <Launch />
                      </IconButton>
                    }
                  />

                  <CardContent>
                    {/* Intelligence Metrics */}
                    <Grid container spacing={2} sx={{ mb: 3 }}>
                      <Grid item xs={6}>
                        <Box
                          textAlign="center"
                          p={2}
                          bgcolor={alpha(config.color, 0.1)}
                          borderRadius={1}
                        >
                          <Psychology sx={{ color: config.color, mb: 1 }} />
                          <Typography variant="h6" fontWeight="bold">
                            {framework.semanticRulesCount}
                          </Typography>
                          <Typography variant="caption">Semantic Rules</Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6}>
                        <Box
                          textAlign="center"
                          p={2}
                          bgcolor={alpha(config.color, 0.1)}
                          borderRadius={1}
                        >
                          <Hub sx={{ color: config.color, mb: 1 }} />
                          <Typography variant="h6" fontWeight="bold">
                            {framework.crossFrameworkMappings}
                          </Typography>
                          <Typography variant="caption">Cross-Framework</Typography>
                        </Box>
                      </Grid>
                    </Grid>

                    {/* Business Impact Visualization */}
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Business Impact Distribution
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={framework.businessImpactBreakdown.high * 10}
                        sx={{
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: alpha(theme.palette.success.main, 0.3),
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: theme.palette.error.main,
                          },
                        }}
                      />
                      <Box display="flex" justifyContent="space-between" mt={1}>
                        <Chip
                          size="small"
                          label={`${framework.businessImpactBreakdown.high} High`}
                          color="error"
                          variant="outlined"
                        />
                        <Chip
                          size="small"
                          label={`${framework.businessImpactBreakdown.medium} Medium`}
                          color="warning"
                          variant="outlined"
                        />
                        <Chip
                          size="small"
                          label={`${framework.businessImpactBreakdown.low} Low`}
                          color="success"
                          variant="outlined"
                        />
                      </Box>
                    </Box>

                    {/* Quick Actions */}
                    <Button
                      variant="contained"
                      startIcon={<Visibility />}
                      onClick={() => handleExploreFramework(framework)}
                      fullWidth
                      sx={{
                        backgroundColor: config.color,
                        '&:hover': { backgroundColor: alpha(config.color, 0.8) },
                      }}
                    >
                      Explore {framework.displayName} Intelligence
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {selectedTab === 1 && (
        <Card>
          <CardHeader
            title="Semantic Rule Intelligence Explorer"
            subheader="Advanced rule exploration and natural language search"
          />
          <CardContent>
            <Alert severity="info">
              The Semantic Rule Explorer is being enhanced with:
              <ul>
                <li>Natural language search across universal compliance rules</li>
                <li>Interactive rule details with AEGIS integration</li>
                <li>Cross-framework rule mapping visualization</li>
                <li>Real-time remediation orchestration</li>
              </ul>
              Full implementation coming in the next development phase!
            </Alert>
          </CardContent>
        </Card>
      )}

      {selectedTab === 2 && (
        <Card>
          <CardHeader
            title="Universal Compliance Analytics Dashboard"
            subheader="Advanced compliance metrics and trend analysis"
          />
          <CardContent>
            <Alert severity="info">
              The Compliance Analytics dashboard will include:
              <ul>
                <li>Cross-Framework Compliance Matrix Heatmap</li>
                <li>Remediation Intelligence Statistics</li>
                <li>Compliance Trend Prediction Models</li>
                <li>Risk-Based Prioritization Charts</li>
                <li>Automated Compliance Reporting</li>
              </ul>
              Advanced analytics implementation coming soon!
            </Alert>
          </CardContent>
        </Card>
      )}

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ComplianceIntelligence;
