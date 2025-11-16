import React, { useEffect, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  IconButton,
  Paper,
  Chip,
  Stack,
  Alert,
  CircularProgress,
  useTheme,
  alpha,
  Divider,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
  Badge,
} from '@mui/material';
import {
  Close as CloseIcon,
  AccountTree as TreeIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Launch as LaunchIcon,
  Visibility as ViewIcon,
} from '@mui/icons-material';
import { ruleService } from '../../services/ruleService';
import { type RuleDependencyGraph } from '../../store/slices/ruleSlice';

interface EnhancedDependencyDialogProps {
  open: boolean;
  onClose: () => void;
  ruleId: string;
  ruleName?: string;
  onRuleSelect?: (ruleId: string) => void;
}

interface DependencyNode {
  id: string;
  name: string;
  type: 'requires' | 'conflicts' | 'related';
  depth: number;
  children: DependencyNode[];
  exists: boolean;
}

interface DependencyStats {
  totalRequires: number;
  totalConflicts: number;
  totalRelated: number;
  maxDepth: number;
  circularDependencies: string[];
}

const EnhancedDependencyDialog: React.FC<EnhancedDependencyDialogProps> = ({
  open,
  onClose,
  ruleId,
  ruleName,
  onRuleSelect,
}) => {
  const theme = useTheme();
  const [dependencies, setDependencies] = useState<RuleDependencyGraph | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set(['root']));
  const [selectedView, setSelectedView] = useState<'tree' | 'list'>('tree');

  // Load dependency data
  useEffect(() => {
    if (open && ruleId) {
      loadDependencies();
    }
  }, [open, ruleId]);

  const loadDependencies = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await ruleService.getRuleDependencies([ruleId], true, 5);
      if (response.success) {
        setDependencies(response.data);
        // Auto-expand first level
        setExpandedNodes(
          new Set(['root', ...response.data.dependency_graph.direct_dependencies.requires])
        );
      } else {
        setError('Failed to load dependencies');
      }
    } catch (err) {
      setError('Error loading rule dependencies');
      console.error('Dependency loading error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Toggle node expansion
  const toggleNode = (nodeId: string) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId);
    } else {
      newExpanded.add(nodeId);
    }
    setExpandedNodes(newExpanded);
  };

  // Get icon and color for dependency type
  const getDependencyTypeInfo = (type: 'requires' | 'conflicts' | 'related') => {
    switch (type) {
      case 'requires':
        return {
          icon: <CheckIcon fontSize="small" />,
          color: theme.palette.success.main,
          bgColor: alpha(theme.palette.success.main, 0.1),
          label: 'Required',
        };
      case 'conflicts':
        return {
          icon: <ErrorIcon fontSize="small" />,
          color: theme.palette.error.main,
          bgColor: alpha(theme.palette.error.main, 0.1),
          label: 'Conflicts',
        };
      case 'related':
        return {
          icon: <InfoIcon fontSize="small" />,
          color: theme.palette.info.main,
          bgColor: alpha(theme.palette.info.main, 0.1),
          label: 'Related',
        };
    }
  };

  // Build dependency tree structure
  const buildDependencyTree = (): DependencyNode[] => {
    if (!dependencies) return [];

    const nodes: DependencyNode[] = [];
    const { direct_dependencies, transitive_dependencies } = dependencies.dependency_graph;

    // Add direct dependencies with their transitive children
    const addDependencyNodes = (deps: string[], type: 'requires' | 'conflicts' | 'related') => {
      deps.forEach((dep) => {
        const node: DependencyNode = {
          id: dep,
          name: dep, // In real implementation, would resolve rule name
          type,
          depth: 1,
          children: [],
          exists: true,
        };

        // Add transitive dependencies if available
        if (type === 'requires' && transitive_dependencies && transitive_dependencies[dep]) {
          const transDep = transitive_dependencies[dep];
          node.children = transDep.requires.map((childDep) => ({
            id: childDep,
            name: childDep,
            type: 'requires' as const,
            depth: transDep.depth,
            children: [],
            exists: true,
          }));
        }

        nodes.push(node);
      });
    };

    addDependencyNodes(direct_dependencies.requires, 'requires');
    addDependencyNodes(direct_dependencies.conflicts, 'conflicts');
    addDependencyNodes(direct_dependencies.related, 'related');

    return nodes;
  };

  // Calculate dependency statistics
  const calculateStats = (): DependencyStats => {
    if (!dependencies) {
      return {
        totalRequires: 0,
        totalConflicts: 0,
        totalRelated: 0,
        maxDepth: 0,
        circularDependencies: [],
      };
    }

    const { direct_dependencies, transitive_dependencies } = dependencies.dependency_graph;

    const maxDepth = transitive_dependencies
      ? Math.max(...Object.values(transitive_dependencies).map((dep) => dep.depth), 1)
      : 1;

    return {
      totalRequires: direct_dependencies.requires.length,
      totalConflicts: direct_dependencies.conflicts.length,
      totalRelated: direct_dependencies.related.length,
      maxDepth,
      circularDependencies: [], // Would be calculated from dependency analysis
    };
  };

  // Render dependency node in tree view
  const renderTreeNode = (node: DependencyNode, level: number = 0) => {
    const hasChildren = node.children.length > 0;
    const isExpanded = expandedNodes.has(node.id);
    const typeInfo = getDependencyTypeInfo(node.type);

    return (
      <Box key={node.id} sx={{ ml: level * 2 }}>
        <Card
          variant="outlined"
          sx={{
            mb: 1,
            backgroundColor: level > 0 ? alpha(typeInfo.bgColor, 0.3) : undefined,
            border: `1px solid ${alpha(typeInfo.color, 0.3)}`,
          }}
        >
          <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
            <Box display="flex" alignItems="center" justifyContent="space-between">
              <Box display="flex" alignItems="center" gap={1}>
                {hasChildren && (
                  <IconButton
                    size="small"
                    onClick={() => toggleNode(node.id)}
                    sx={{ color: typeInfo.color }}
                  >
                    {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  </IconButton>
                )}

                <Box sx={{ color: typeInfo.color }}>{typeInfo.icon}</Box>

                <Box>
                  <Typography variant="body2" fontWeight="medium">
                    {node.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {node.id}
                  </Typography>
                </Box>
              </Box>

              <Box display="flex" alignItems="center" gap={1}>
                {node.depth > 1 && (
                  <Chip
                    label={`Level ${node.depth}`}
                    size="small"
                    sx={{
                      backgroundColor: alpha(theme.palette.primary.main, 0.1),
                      color: theme.palette.primary.main,
                    }}
                  />
                )}

                <Chip
                  label={typeInfo.label}
                  size="small"
                  sx={{
                    backgroundColor: typeInfo.bgColor,
                    color: typeInfo.color,
                  }}
                />

                {onRuleSelect && (
                  <IconButton
                    size="small"
                    onClick={() => onRuleSelect(node.id)}
                    title="View rule details"
                  >
                    <LaunchIcon fontSize="small" />
                  </IconButton>
                )}
              </Box>
            </Box>
          </CardContent>
        </Card>

        <Collapse in={isExpanded} timeout="auto">
          <Box>{node.children.map((child) => renderTreeNode(child, level + 1))}</Box>
        </Collapse>
      </Box>
    );
  };

  // Render dependency in list view
  const renderListView = () => {
    if (!dependencies) return null;

    const { direct_dependencies } = dependencies.dependency_graph;

    return (
      <Stack spacing={2}>
        {/* Requirements */}
        {direct_dependencies.requires.length > 0 && (
          <Box>
            <Typography variant="subtitle2" gutterBottom display="flex" alignItems="center" gap={1}>
              <CheckIcon fontSize="small" color="success" />
              Requirements ({direct_dependencies.requires.length})
            </Typography>
            <List dense>
              {direct_dependencies.requires.map((ruleId) => (
                <ListItem key={ruleId} sx={{ py: 0.5 }}>
                  <ListItemIcon>
                    <CheckIcon fontSize="small" color="success" />
                  </ListItemIcon>
                  <ListItemText primary={ruleId} secondary="This rule must be enabled" />
                  {onRuleSelect && (
                    <IconButton size="small" onClick={() => onRuleSelect(ruleId)}>
                      <ViewIcon fontSize="small" />
                    </IconButton>
                  )}
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {/* Conflicts */}
        {direct_dependencies.conflicts.length > 0 && (
          <Box>
            <Typography variant="subtitle2" gutterBottom display="flex" alignItems="center" gap={1}>
              <ErrorIcon fontSize="small" color="error" />
              Conflicts ({direct_dependencies.conflicts.length})
            </Typography>
            <List dense>
              {direct_dependencies.conflicts.map((ruleId) => (
                <ListItem key={ruleId} sx={{ py: 0.5 }}>
                  <ListItemIcon>
                    <ErrorIcon fontSize="small" color="error" />
                  </ListItemIcon>
                  <ListItemText primary={ruleId} secondary="Cannot be enabled with this rule" />
                  {onRuleSelect && (
                    <IconButton size="small" onClick={() => onRuleSelect(ruleId)}>
                      <ViewIcon fontSize="small" />
                    </IconButton>
                  )}
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {/* Related */}
        {direct_dependencies.related.length > 0 && (
          <Box>
            <Typography variant="subtitle2" gutterBottom display="flex" alignItems="center" gap={1}>
              <InfoIcon fontSize="small" color="info" />
              Related Rules ({direct_dependencies.related.length})
            </Typography>
            <List dense>
              {direct_dependencies.related.map((ruleId) => (
                <ListItem key={ruleId} sx={{ py: 0.5 }}>
                  <ListItemIcon>
                    <InfoIcon fontSize="small" color="info" />
                  </ListItemIcon>
                  <ListItemText
                    primary={ruleId}
                    secondary="Consider enabling for better coverage"
                  />
                  {onRuleSelect && (
                    <IconButton size="small" onClick={() => onRuleSelect(ruleId)}>
                      <ViewIcon fontSize="small" />
                    </IconButton>
                  )}
                </ListItem>
              ))}
            </List>
          </Box>
        )}
      </Stack>
    );
  };

  const dependencyTree = buildDependencyTree();
  const stats = calculateStats();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          minHeight: '70vh',
          maxHeight: '90vh',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={1}>
            <TreeIcon color="primary" />
            <Box>
              <Typography variant="h6">Rule Dependencies</Typography>
              <Typography variant="caption" color="text.secondary">
                {ruleName || ruleId}
              </Typography>
            </Box>
          </Box>

          <Box display="flex" alignItems="center" gap={1}>
            <Button
              size="small"
              variant={selectedView === 'tree' ? 'contained' : 'outlined'}
              onClick={() => setSelectedView('tree')}
            >
              Tree
            </Button>
            <Button
              size="small"
              variant={selectedView === 'list' ? 'contained' : 'outlined'}
              onClick={() => setSelectedView('list')}
            >
              List
            </Button>
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
      </DialogTitle>

      <Divider />

      <DialogContent sx={{ p: 3 }}>
        {isLoading ? (
          <Box display="flex" justifyContent="center" alignItems="center" minHeight={300}>
            <CircularProgress />
            <Typography variant="body2" sx={{ ml: 2 }}>
              Loading dependencies...
            </Typography>
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
            <Button size="small" onClick={loadDependencies} sx={{ ml: 1 }}>
              Retry
            </Button>
          </Alert>
        ) : dependencies ? (
          <Stack spacing={3}>
            {/* Statistics Overview */}
            <Paper sx={{ p: 2, backgroundColor: alpha(theme.palette.primary.main, 0.05) }}>
              <Typography variant="subtitle2" gutterBottom>
                Dependency Summary
              </Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                <Badge badgeContent={stats.totalRequires} color="success">
                  <Chip
                    label="Requirements"
                    icon={<CheckIcon />}
                    color="success"
                    variant="outlined"
                  />
                </Badge>
                <Badge badgeContent={stats.totalConflicts} color="error">
                  <Chip label="Conflicts" icon={<ErrorIcon />} color="error" variant="outlined" />
                </Badge>
                <Badge badgeContent={stats.totalRelated} color="info">
                  <Chip label="Related" icon={<InfoIcon />} color="info" variant="outlined" />
                </Badge>
                <Chip label={`Max Depth: ${stats.maxDepth}`} icon={<TreeIcon />} color="primary" />
              </Stack>
            </Paper>

            {/* Conflict Warning */}
            {dependencies.conflict_analysis.has_conflicts && (
              <Alert severity="error">
                <Typography variant="subtitle2" gutterBottom>
                  ⚠️ Dependency Conflicts Detected
                </Typography>
                <Typography variant="body2">
                  This rule has conflicting dependencies that may prevent proper operation. Review
                  the conflicts below and resolve them before enabling this rule.
                </Typography>
              </Alert>
            )}

            {/* Main Content */}
            {selectedView === 'tree' ? (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Dependency Tree
                </Typography>
                {dependencyTree.length > 0 ? (
                  <Box>{dependencyTree.map((node) => renderTreeNode(node))}</Box>
                ) : (
                  <Alert severity="info">This rule has no dependencies.</Alert>
                )}
              </Box>
            ) : (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Dependencies List
                </Typography>
                {renderListView()}
              </Box>
            )}
          </Stack>
        ) : (
          <Alert severity="info">No dependency information available for this rule.</Alert>
        )}
      </DialogContent>

      <DialogActions sx={{ p: 2, justifyContent: 'space-between' }}>
        <Typography variant="caption" color="text.secondary">
          {dependencies && `Total dependencies: ${dependencies.dependency_count}`}
        </Typography>
        <Button onClick={onClose} variant="contained">
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EnhancedDependencyDialog;
