import React, { useState } from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Box,
  IconButton,
  Collapse,
  Tooltip,
  Stack,
  Divider,
  Button,
  useTheme,
  alpha,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  Category as CategoryIcon,
  AccountTree as DependencyIcon,
  Extension as ExtensionIcon,
  ContentCopy as CopyIcon,
  Launch as LaunchIcon,
} from '@mui/icons-material';
import { Rule } from '../../store/slices/ruleSlice';

interface RuleCardProps {
  rule: Rule;
  viewMode: 'grid' | 'list';
  onSelect: (rule: Rule) => void;
  onViewDependencies?: (ruleId: string) => void;
  selected?: boolean;
  showRelevance?: boolean;
}

const RuleCard: React.FC<RuleCardProps> = ({
  rule,
  viewMode,
  onSelect,
  onViewDependencies,
  selected = false,
  showRelevance = false,
}) => {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <ErrorIcon fontSize="small" />;
      case 'medium':
        return <WarningIcon fontSize="small" />;
      case 'low':
        return <InfoIcon fontSize="small" />;
      default:
        return <SecurityIcon fontSize="small" />;
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

  const handleCopyRuleId = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(rule.rule_id);
  };

  const handleExpandClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded(!expanded);
  };

  const cardStyles = {
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    backgroundColor: selected ? alpha(theme.palette.primary.main, 0.08) : 'background.paper',
    border: `1px solid ${selected ? theme.palette.primary.main : theme.palette.divider}`,
    '&:hover': {
      boxShadow: theme.shadows[4],
      borderColor: theme.palette.primary.main,
    },
  };

  const listStyles = viewMode === 'list' ? {
    borderRadius: 0,
    borderLeft: 'none',
    borderRight: 'none',
    borderTop: 'none',
    '&:first-of-type': {
      borderTop: `1px solid ${theme.palette.divider}`,
    },
  } : {};

  return (
    <Card
      sx={{ ...cardStyles, ...listStyles }}
      onClick={() => onSelect(rule)}
    >
      <CardContent>
        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="flex-start">
          <Box flex={1}>
            <Typography variant={viewMode === 'list' ? 'body1' : 'h6'} gutterBottom>
              {rule.metadata.name}
            </Typography>
            
            <Box display="flex" alignItems="center" gap={1} mb={1}>
              <Tooltip title="Rule ID - Click to copy">
                <Chip
                  label={rule.rule_id}
                  size="small"
                  variant="outlined"
                  icon={<CopyIcon fontSize="small" />}
                  onClick={handleCopyRuleId}
                />
              </Tooltip>
              
              {rule.abstract && (
                <Chip
                  label="Abstract"
                  size="small"
                  color="secondary"
                  variant="outlined"
                />
              )}
              
              {rule.inheritance?.parent_rule && (
                <Chip
                  label="Inherited"
                  size="small"
                  icon={<ExtensionIcon fontSize="small" />}
                  variant="outlined"
                />
              )}
            </Box>
          </Box>

          <Box display="flex" alignItems="center" gap={1}>
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
            
            {showRelevance && rule.relevance_score && (
              <Tooltip title="Search relevance score">
                <Chip
                  label={`${Math.round(rule.relevance_score * 100)}%`}
                  size="small"
                  color="primary"
                />
              </Tooltip>
            )}
          </Box>
        </Box>

        {/* Description */}
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: '-webkit-box',
            WebkitLineClamp: expanded ? 'none' : 2,
            WebkitBoxOrient: 'vertical',
          }}
        >
          {rule.metadata.description}
        </Typography>

        {/* Quick Info */}
        {viewMode === 'list' && !expanded && (
          <Box display="flex" gap={2} mt={1} alignItems="center">
            <Box display="flex" alignItems="center" gap={0.5}>
              <CategoryIcon fontSize="small" color="action" />
              <Typography variant="caption" color="text.secondary">
                {rule.category}
              </Typography>
            </Box>
            
            {Object.keys(rule.platform_implementations || {}).length > 0 && (
              <Box display="flex" gap={0.5}>
                {Object.keys(rule.platform_implementations).slice(0, 3).map(platform => (
                  <Chip
                    key={platform}
                    label={platform}
                    size="small"
                    variant="outlined"
                    sx={{ height: 20 }}
                  />
                ))}
                {Object.keys(rule.platform_implementations).length > 3 && (
                  <Typography variant="caption" color="text.secondary">
                    +{Object.keys(rule.platform_implementations).length - 3}
                  </Typography>
                )}
              </Box>
            )}
            
            {rule.dependencies && (rule.dependencies.requires.length > 0 || rule.dependencies.conflicts.length > 0) && (
              <Tooltip title={`${rule.dependencies.requires.length} dependencies, ${rule.dependencies.conflicts.length} conflicts`}>
                <Box display="flex" alignItems="center" gap={0.5}>
                  <DependencyIcon fontSize="small" color="action" />
                  <Typography variant="caption" color="text.secondary">
                    {rule.dependencies.requires.length + rule.dependencies.conflicts.length}
                  </Typography>
                </Box>
              </Tooltip>
            )}
          </Box>
        )}

        {/* Expanded Content */}
        <Collapse in={expanded}>
          <Box mt={2}>
            <Divider sx={{ my: 1 }} />
            
            {/* Rationale */}
            {rule.metadata.rationale && (
              <Box mb={2}>
                <Typography variant="subtitle2" gutterBottom>
                  Rationale
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {rule.metadata.rationale}
                </Typography>
              </Box>
            )}

            {/* Platforms */}
            <Box mb={2}>
              <Typography variant="subtitle2" gutterBottom>
                Supported Platforms
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {Object.entries(rule.platform_implementations || {}).map(([platform, impl]) => (
                  <Chip
                    key={platform}
                    label={`${platform} (${impl.versions.join(', ')})`}
                    size="small"
                    variant="outlined"
                  />
                ))}
              </Stack>
            </Box>

            {/* Frameworks */}
            {Object.keys(rule.frameworks || {}).length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle2" gutterBottom>
                  Compliance Frameworks
                </Typography>
                <Stack spacing={1}>
                  {Object.entries(rule.frameworks).map(([framework, versions]) => (
                    <Box key={framework}>
                      {Object.entries(versions).map(([version, controls]) => (
                        <Typography key={version} variant="body2" color="text.secondary">
                          <strong>{framework.toUpperCase()} {version}:</strong> {controls.join(', ')}
                        </Typography>
                      ))}
                    </Box>
                  ))}
                </Stack>
              </Box>
            )}

            {/* Tags */}
            {rule.tags && rule.tags.length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                  {rule.tags.map(tag => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      variant="filled"
                      sx={{ backgroundColor: alpha(theme.palette.primary.main, 0.1) }}
                    />
                  ))}
                </Stack>
              </Box>
            )}

            {/* Dependencies Summary */}
            {rule.dependencies && (rule.dependencies.requires.length > 0 || rule.dependencies.conflicts.length > 0) && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Dependencies & Conflicts
                </Typography>
                <Stack spacing={1}>
                  {rule.dependencies.requires.length > 0 && (
                    <Typography variant="body2" color="text.secondary">
                      <strong>Requires:</strong> {rule.dependencies.requires.join(', ')}
                    </Typography>
                  )}
                  {rule.dependencies.conflicts.length > 0 && (
                    <Typography variant="body2" color="error">
                      <strong>Conflicts:</strong> {rule.dependencies.conflicts.join(', ')}
                    </Typography>
                  )}
                </Stack>
              </Box>
            )}
          </Box>
        </Collapse>
      </CardContent>

      <CardActions sx={{ px: 2, pb: 2 }}>
        <Button
          size="small"
          onClick={handleExpandClick}
          startIcon={expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {expanded ? 'Less' : 'More'}
        </Button>
        
        {onViewDependencies && rule.dependencies && (rule.dependencies.requires.length > 0 || rule.dependencies.conflicts.length > 0) && (
          <Button
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              onViewDependencies(rule.rule_id);
            }}
            startIcon={<DependencyIcon />}
          >
            Dependencies
          </Button>
        )}
        
        <Button
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            onSelect(rule);
          }}
          endIcon={<LaunchIcon />}
        >
          Details
        </Button>
      </CardActions>
    </Card>
  );
};

export default RuleCard;