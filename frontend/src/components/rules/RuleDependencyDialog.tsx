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
} from '@mui/material';
import {
  Close as CloseIcon,
  AccountTree as TreeIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';

interface RuleDependencyDialogProps {
  open: boolean;
  onClose: () => void;
  ruleId: string;
}

interface DependencyNode {
  id: string;
  name: string;
  type: 'requires' | 'conflicts' | 'related';
  depth: number;
  children: DependencyNode[];
}

const RuleDependencyDialog: React.FC<RuleDependencyDialogProps> = ({
  open,
  onClose,
  ruleId,
}) => {
  const theme = useTheme();
  const ruleDependencies = useSelector((state: RootState) => state.rules.ruleDependencies);
  const rules = useSelector((state: RootState) => state.rules.rules);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());

  // Find the rule name
  const getRuleName = (id: string): string => {
    const rule = rules.find(r => r.rule_id === id);
    return rule?.metadata.name || id;
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

  // Get icon for dependency type
  const getTypeIcon = (type: 'requires' | 'conflicts' | 'related') => {
    switch (type) {
      case 'requires':
        return <CheckIcon fontSize="small" color="success" />;
      case 'conflicts':
        return <ErrorIcon fontSize="small" color="error" />;
      case 'related':
        return <InfoIcon fontSize="small" color="info" />;
    }
  };

  // Get color for dependency type
  const getTypeColor = (type: 'requires' | 'conflicts' | 'related') => {
    switch (type) {
      case 'requires':
        return theme.palette.success.main;
      case 'conflicts':
        return theme.palette.error.main;
      case 'related':
        return theme.palette.info.main;
    }
  };

  // Build dependency tree
  const buildDependencyTree = (): DependencyNode[] => {
    if (!ruleDependencies) return [];

    const nodes: DependencyNode[] = [];
    const { direct_dependencies, transitive_dependencies } = ruleDependencies.dependency_graph;

    // Add direct dependencies
    direct_dependencies.requires.forEach(dep => {
      const node: DependencyNode = {
        id: dep,
        name: getRuleName(dep),
        type: 'requires',
        depth: 1,
        children: [],
      };

      // Add transitive dependencies if available
      if (transitive_dependencies && transitive_dependencies[dep]) {
        const transDep = transitive_dependencies[dep];
        node.children = transDep.requires.map(childDep => ({
          id: childDep,
          name: getRuleName(childDep),
          type: 'requires',
          depth: transDep.depth,
          children: [],
        }));
      }

      nodes.push(node);
    });

    // Add conflicts
    direct_dependencies.conflicts.forEach(dep => {
      nodes.push({
        id: dep,
        name: getRuleName(dep),
        type: 'conflicts',
        depth: 1,
        children: [],
      });
    });

    // Add related
    direct_dependencies.related.forEach(dep => {
      nodes.push({
        id: dep,
        name: getRuleName(dep),
        type: 'related',
        depth: 1,
        children: [],
      });
    });

    return nodes;
  };

  // Render dependency node
  const renderNode = (node: DependencyNode, level: number = 0) => {
    const hasChildren = node.children.length > 0;
    const isExpanded = expandedNodes.has(node.id);

    return (
      <Box key={node.id} sx={{ ml: level * 3 }}>
        <Box
          display="flex"
          alignItems="center"
          gap={1}
          sx={{
            p: 1,
            borderRadius: 1,
            cursor: hasChildren ? 'pointer' : 'default',
            '&:hover': {
              backgroundColor: alpha(theme.palette.action.hover, 0.04),
            },
          }}
          onClick={() => hasChildren && toggleNode(node.id)}
        >
          {hasChildren && (
            <IconButton size="small">
              {isExpanded ? '−' : '+'}
            </IconButton>
          )}
          {!hasChildren && <Box sx={{ width: 32 }} />}
          
          {getTypeIcon(node.type)}
          
          <Typography variant="body2">
            {node.name}
          </Typography>
          
          <Chip
            label={node.id}
            size="small"
            variant="outlined"
            sx={{ ml: 'auto' }}
          />
          
          {node.depth > 1 && (
            <Chip
              label={`Depth: ${node.depth}`}
              size="small"
              sx={{
                backgroundColor: alpha(theme.palette.primary.main, 0.1),
                color: theme.palette.primary.main,
              }}
            />
          )}
        </Box>
        
        {hasChildren && isExpanded && (
          <Box>
            {node.children.map(child => renderNode(child, level + 1))}
          </Box>
        )}
      </Box>
    );
  };

  const dependencyTree = buildDependencyTree();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          minHeight: '60vh',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={1}>
            <TreeIcon />
            <Typography variant="h6">
              Rule Dependencies
            </Typography>
          </Box>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent>
        {!ruleDependencies ? (
          <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
            <CircularProgress />
          </Box>
        ) : (
          <Stack spacing={3}>
            {/* Rule Info */}
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Rule: {getRuleName(ruleId)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                ID: {ruleId}
              </Typography>
            </Paper>

            {/* Summary */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Dependency Summary
              </Typography>
              <Stack direction="row" spacing={2}>
                <Chip
                  label={`${ruleDependencies.dependency_graph.direct_dependencies.requires.length} Requirements`}
                  icon={<CheckIcon />}
                  color="success"
                  variant="outlined"
                />
                <Chip
                  label={`${ruleDependencies.dependency_graph.direct_dependencies.conflicts.length} Conflicts`}
                  icon={<ErrorIcon />}
                  color="error"
                  variant="outlined"
                />
                <Chip
                  label={`${ruleDependencies.dependency_graph.direct_dependencies.related.length} Related`}
                  icon={<InfoIcon />}
                  variant="outlined"
                />
                <Chip
                  label={`${ruleDependencies.dependency_count} Total`}
                  icon={<TreeIcon />}
                  color="primary"
                />
              </Stack>
            </Box>

            {/* Conflict Analysis */}
            {ruleDependencies.conflict_analysis.has_conflicts && (
              <Alert severity="error">
                <Typography variant="subtitle2" gutterBottom>
                  Conflicts Detected
                </Typography>
                {ruleDependencies.conflict_analysis.conflict_details.map((conflict, index) => (
                  <Typography key={index} variant="body2">
                    • {conflict.conflicting_rule}: {conflict.reason}
                  </Typography>
                ))}
              </Alert>
            )}

            {/* Dependency Tree */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Dependency Tree
              </Typography>
              
              {dependencyTree.length > 0 ? (
                <Paper sx={{ p: 2 }}>
                  {dependencyTree.map(node => renderNode(node))}
                </Paper>
              ) : (
                <Alert severity="info">
                  This rule has no dependencies.
                </Alert>
              )}
            </Box>

            {/* Legend */}
            <Paper sx={{ p: 2, backgroundColor: alpha(theme.palette.background.default, 0.5) }}>
              <Typography variant="subtitle2" gutterBottom>
                Legend
              </Typography>
              <Stack spacing={1}>
                <Box display="flex" alignItems="center" gap={1}>
                  <CheckIcon fontSize="small" color="success" />
                  <Typography variant="caption">
                    Required dependency - must be enabled for this rule to work
                  </Typography>
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <ErrorIcon fontSize="small" color="error" />
                  <Typography variant="caption">
                    Conflicting rule - cannot be enabled simultaneously
                  </Typography>
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <InfoIcon fontSize="small" color="info" />
                  <Typography variant="caption">
                    Related rule - consider enabling together for better coverage
                  </Typography>
                </Box>
              </Stack>
            </Paper>
          </Stack>
        )}
      </DialogContent>

      <DialogActions sx={{ p: 2 }}>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default RuleDependencyDialog;