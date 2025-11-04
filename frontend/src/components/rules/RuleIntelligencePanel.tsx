import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Stack,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress,
  Alert,
  Tooltip,
  Badge,
  useTheme,
  alpha,
  LinearProgress,
} from '@mui/material';
import {
  Psychology as IntelligenceIcon,
  ExpandMore as ExpandMoreIcon,
  TrendingUp as TrendingUpIcon,
  Security as SecurityIcon,
  Computer as PlatformIcon,
  Assessment as AnalyticsIcon,
  Lightbulb as InsightIcon,
  Star as RecommendationIcon,
  Add as AddIcon,
  Refresh as RefreshIcon,
  Speed as PerformanceIcon,
} from '@mui/icons-material';
import { Rule } from '../../store/slices/ruleSlice';
import {
  ruleIntelligenceService,
  RuleIntelligenceAnalysis,
  RuleRecommendation,
} from '../../services/ruleIntelligenceService';

interface RuleIntelligencePanelProps {
  availableRules: Rule[];
  currentPlatform?: string;
  onRuleSelect: (rule: Rule) => void;
  onRuleAdd: (rule: Rule) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

const RuleIntelligencePanel: React.FC<RuleIntelligencePanelProps> = ({
  availableRules,
  currentPlatform,
  onRuleSelect,
  onRuleAdd,
  collapsed = false,
  onToggleCollapse,
}) => {
  const theme = useTheme();
  const [analysis, setAnalysis] = useState<RuleIntelligenceAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['recommendations', 'insights'])
  );

  // Load intelligence analysis
  useEffect(() => {
    if (availableRules.length > 0) {
      loadIntelligence();
    }
  }, [availableRules, currentPlatform]);

  const loadIntelligence = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await ruleIntelligenceService.generateRecommendations({
        availableRules,
        currentPlatform,
        targetEnvironment: 'production',
        securityBaseline: 'nist',
        userPreferences: {
          prioritySeverities: ['high', 'medium'],
          preferredFrameworks: ['nist', 'cis'],
        },
      });

      setAnalysis(result);
    } catch (err) {
      setError('Failed to generate rule intelligence analysis');
      console.error('Intelligence analysis error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Toggle section expansion
  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  // Get recommendation color based on category and score
  const getRecommendationColor = (recommendation: RuleRecommendation) => {
    if (recommendation.score > 0.8) return theme.palette.success.main;
    if (recommendation.score > 0.6) return theme.palette.warning.main;
    return theme.palette.info.main;
  };

  // Get confidence color
  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high':
        return theme.palette.success.main;
      case 'medium':
        return theme.palette.warning.main;
      case 'low':
        return theme.palette.error.main;
      default:
        return theme.palette.grey[500];
    }
  };

  // Render statistics overview
  const renderStatistics = () => {
    if (!analysis) return null;

    const { statistics } = analysis;

    return (
      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <Card sx={{ flex: 1, textAlign: 'center' }}>
          <CardContent sx={{ p: 1.5 }}>
            <Typography variant="h6" color="primary">
              {statistics.total_rules_analyzed}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Rules Analyzed
            </Typography>
          </CardContent>
        </Card>

        <Card sx={{ flex: 1, textAlign: 'center' }}>
          <CardContent sx={{ p: 1.5 }}>
            <Typography variant="h6" color="error">
              {statistics.high_priority_count}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              High Priority
            </Typography>
          </CardContent>
        </Card>

        <Card sx={{ flex: 1, textAlign: 'center' }}>
          <CardContent sx={{ p: 1.5 }}>
            <Typography variant="h6" color="info">
              {statistics.platform_coverage}%
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Platform Coverage
            </Typography>
          </CardContent>
        </Card>

        <Card sx={{ flex: 1, textAlign: 'center' }}>
          <CardContent sx={{ p: 1.5 }}>
            <Typography variant="h6" color="success">
              {statistics.baseline_compliance}%
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Baseline Compliance
            </Typography>
          </CardContent>
        </Card>
      </Stack>
    );
  };

  // Render recommendations
  const renderRecommendations = () => {
    if (!analysis?.recommendations.length) return null;

    return (
      <Accordion
        expanded={expandedSections.has('recommendations')}
        onChange={() => toggleSection('recommendations')}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box display="flex" alignItems="center" gap={1}>
            <RecommendationIcon color="primary" />
            <Typography variant="subtitle1" fontWeight="medium">
              Smart Recommendations
            </Typography>
            <Badge badgeContent={analysis.recommendations.length} color="primary" />
          </Box>
        </AccordionSummary>

        <AccordionDetails>
          <List dense>
            {analysis.recommendations.slice(0, 10).map((recommendation, index) => (
              <ListItem
                key={recommendation.rule.rule_id}
                sx={{
                  border: `1px solid ${alpha(getRecommendationColor(recommendation), 0.3)}`,
                  borderRadius: 1,
                  mb: 1,
                  backgroundColor: alpha(getRecommendationColor(recommendation), 0.05),
                }}
                secondaryAction={
                  <Stack direction="row" spacing={1}>
                    <Tooltip title="View details">
                      <IconButton size="small" onClick={() => onRuleSelect(recommendation.rule)}>
                        <SecurityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Add to scan">
                      <IconButton
                        size="small"
                        onClick={() => onRuleAdd(recommendation.rule)}
                        sx={{ color: theme.palette.success.main }}
                      >
                        <AddIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                }
              >
                <ListItemIcon>
                  <Box
                    sx={{
                      width: 24,
                      height: 24,
                      borderRadius: '50%',
                      backgroundColor: getRecommendationColor(recommendation),
                      color: 'white',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                    }}
                  >
                    {index + 1}
                  </Box>
                </ListItemIcon>

                <ListItemText
                  primary={
                    <Box display="flex" alignItems="center" gap={1}>
                      <Typography variant="body2" fontWeight="medium">
                        {recommendation.rule.metadata.name}
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={recommendation.score * 100}
                        sx={{
                          width: 60,
                          height: 4,
                          borderRadius: 2,
                          backgroundColor: alpha(getRecommendationColor(recommendation), 0.2),
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: getRecommendationColor(recommendation),
                          },
                        }}
                      />
                      <Typography variant="caption" color="text.secondary">
                        {Math.round(recommendation.score * 100)}%
                      </Typography>
                    </Box>
                  }
                  secondary={
                    <Box mt={0.5}>
                      <Typography variant="caption" color="text.secondary">
                        {recommendation.reasons.join(' • ')}
                      </Typography>
                      <Box display="flex" gap={0.5} mt={0.5}>
                        <Chip
                          label={recommendation.rule.severity}
                          size="small"
                          color={
                            recommendation.rule.severity === 'high'
                              ? 'error'
                              : recommendation.rule.severity === 'medium'
                                ? 'warning'
                                : 'info'
                          }
                        />
                        <Chip
                          label={recommendation.confidence}
                          size="small"
                          sx={{
                            backgroundColor: alpha(
                              getConfidenceColor(recommendation.confidence),
                              0.1
                            ),
                            color: getConfidenceColor(recommendation.confidence),
                          }}
                        />
                      </Box>
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>

          {analysis.recommendations.length > 10 && (
            <Alert severity="info" sx={{ mt: 2 }}>
              Showing top 10 recommendations. {analysis.recommendations.length - 10} more available.
            </Alert>
          )}
        </AccordionDetails>
      </Accordion>
    );
  };

  // Render insights
  const renderInsights = () => {
    if (!analysis?.insights) return null;

    const { insights } = analysis;
    const hasInsights =
      [
        ...insights.coverage_gaps,
        ...insights.priority_areas,
        ...insights.platform_specific_suggestions,
        ...insights.dependency_chains,
      ].length > 0;

    if (!hasInsights) return null;

    return (
      <Accordion
        expanded={expandedSections.has('insights')}
        onChange={() => toggleSection('insights')}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box display="flex" alignItems="center" gap={1}>
            <InsightIcon color="secondary" />
            <Typography variant="subtitle1" fontWeight="medium">
              Intelligence Insights
            </Typography>
          </Box>
        </AccordionSummary>

        <AccordionDetails>
          <Stack spacing={2}>
            {/* Coverage Gaps */}
            {insights.coverage_gaps.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom color="error">
                  Coverage Gaps
                </Typography>
                <Stack spacing={0.5}>
                  {insights.coverage_gaps.map((gap, index) => (
                    <Alert key={index} severity="warning" sx={{ py: 0.5 }}>
                      <Typography variant="body2">{gap}</Typography>
                    </Alert>
                  ))}
                </Stack>
              </Box>
            )}

            {/* Priority Areas */}
            {insights.priority_areas.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom color="primary">
                  Priority Areas
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                  {insights.priority_areas.map((area, index) => (
                    <Chip
                      key={index}
                      label={area}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Box>
            )}

            {/* Platform Suggestions */}
            {insights.platform_specific_suggestions.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom color="info">
                  Platform Suggestions
                </Typography>
                <Stack spacing={0.5}>
                  {insights.platform_specific_suggestions.map((suggestion, index) => (
                    <Alert key={index} severity="info" sx={{ py: 0.5 }}>
                      <Typography variant="body2">{suggestion}</Typography>
                    </Alert>
                  ))}
                </Stack>
              </Box>
            )}

            {/* Dependency Chains */}
            {insights.dependency_chains.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Dependency Insights
                </Typography>
                <List dense>
                  {insights.dependency_chains.map((chain, index) => (
                    <ListItem key={index} sx={{ py: 0 }}>
                      <ListItemIcon>
                        <TrendingUpIcon fontSize="small" color="action" />
                      </ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{chain}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}
          </Stack>
        </AccordionDetails>
      </Accordion>
    );
  };

  if (collapsed) {
    return (
      <Card sx={{ mb: 2 }}>
        <CardContent sx={{ p: 2 }}>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <IntelligenceIcon color="primary" />
              <Typography variant="subtitle1">Rule Intelligence</Typography>
              {analysis && (
                <Chip
                  label={`${analysis.recommendations.length} recommendations`}
                  size="small"
                  color="primary"
                />
              )}
            </Box>
            <Button size="small" onClick={onToggleCollapse}>
              Expand
            </Button>
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        {/* Header */}
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <IntelligenceIcon color="primary" />
            <Typography variant="h6">Rule Intelligence</Typography>
            {analysis && (
              <Chip
                label={`Updated ${new Date(analysis.timestamp).toLocaleTimeString()}`}
                size="small"
                variant="outlined"
              />
            )}
          </Box>

          <Box display="flex" gap={1}>
            <Tooltip title="Refresh analysis">
              <IconButton size="small" onClick={loadIntelligence} disabled={isLoading}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            {onToggleCollapse && (
              <Button size="small" onClick={onToggleCollapse}>
                Collapse
              </Button>
            )}
          </Box>
        </Box>

        {/* Loading */}
        {isLoading && (
          <Box display="flex" alignItems="center" justifyContent="center" py={4}>
            <CircularProgress />
            <Typography variant="body2" sx={{ ml: 2 }}>
              Analyzing rules with AI intelligence...
            </Typography>
          </Box>
        )}

        {/* Error */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
            <Button size="small" onClick={loadIntelligence} sx={{ ml: 1 }}>
              Retry
            </Button>
          </Alert>
        )}

        {/* Content */}
        {analysis && !isLoading && (
          <Stack spacing={2}>
            {renderStatistics()}
            {renderRecommendations()}
            {renderInsights()}

            {/* Cache Performance Info */}
            <Box sx={{ pt: 1, borderTop: `1px solid ${theme.palette.divider}` }}>
              <Box display="flex" alignItems="center" gap={1}>
                <PerformanceIcon fontSize="small" color="action" />
                <Typography variant="caption" color="text.secondary">
                  Intelligence powered by smart caching • Analysis cached for 5 minutes
                </Typography>
              </Box>
            </Box>
          </Stack>
        )}
      </CardContent>
    </Card>
  );
};

export default RuleIntelligencePanel;
