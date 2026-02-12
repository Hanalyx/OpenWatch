/**
 * Saved Queries Widget
 *
 * Displays saved audit queries summary:
 * - Query stats (total/my/shared)
 * - Top 3 recent queries
 * - Quick execute button
 * - Expand button to /audit/queries
 * - Create query button
 *
 * Part of Command Center Dashboard.
 *
 * @module pages/Dashboard/widgets/SavedQueriesWidget
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  IconButton,
  Button,
  List,
  ListItem,
  ListItemText,
  Skeleton,
  Alert,
  Tooltip,
  Divider,
  useTheme,
  alpha,
} from '@mui/material';
import {
  OpenInFull as OpenInFullIcon,
  Storage as StorageIcon,
  Add as AddIcon,
  PlayArrow as PlayArrowIcon,
  Share as ShareIcon,
  Lock as LockIcon,
} from '@mui/icons-material';
import { useSavedQueries, useQueryStats } from '../../../hooks/useAuditQueries';

const SavedQueriesWidget: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();

  // Fetch query stats
  const { data: stats, isLoading: statsLoading, error: statsError } = useQueryStats();

  // Fetch recent queries (top 3)
  const {
    data: queriesData,
    isLoading: queriesLoading,
    error: queriesError,
  } = useSavedQueries({ page: 1, per_page: 3, include_shared: true });

  const handleExpand = () => {
    navigate('/audit/queries');
  };

  const handleCreateQuery = () => {
    navigate('/audit/queries/new');
  };

  const handleExecuteQuery = (queryId: string) => {
    navigate(`/audit/queries/${queryId}/execute`);
  };

  const isLoading = statsLoading || queriesLoading;
  const hasError = statsError || queriesError;

  // Loading state
  if (isLoading) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Skeleton variant="text" width="50%" />
            <Skeleton variant="circular" width={32} height={32} />
          </Box>
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <Skeleton variant="rounded" width={60} height={40} />
            <Skeleton variant="rounded" width={60} height={40} />
            <Skeleton variant="rounded" width={60} height={40} />
          </Box>
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} variant="text" sx={{ my: 1 }} />
          ))}
        </CardContent>
      </Card>
    );
  }

  // Error state
  if (hasError) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <StorageIcon color="primary" />
              <Typography variant="h6">Saved Queries</Typography>
            </Box>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Alert severity="warning" variant="outlined">
            Unable to load saved queries
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const queries = queriesData?.items || [];
  const totalQueries = stats?.total_queries || 0;
  const myQueries = stats?.my_queries || 0;
  const sharedQueries = stats?.shared_queries || 0;

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <StorageIcon color="primary" />
            <Typography variant="h6">Saved Queries</Typography>
          </Box>
          <Tooltip title="View All Queries">
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>

        {/* Stats Row */}
        <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
          <Box
            sx={{
              px: 2,
              py: 1,
              borderRadius: 1,
              bgcolor: alpha(theme.palette.primary.main, 0.1),
              textAlign: 'center',
            }}
          >
            <Typography
              variant="h6"
              color="primary.main"
              sx={{ lineHeight: 1.2, fontWeight: 'bold' }}
            >
              {totalQueries}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Total
            </Typography>
          </Box>

          <Box
            sx={{
              px: 2,
              py: 1,
              borderRadius: 1,
              bgcolor: alpha(theme.palette.info.main, 0.1),
              textAlign: 'center',
            }}
          >
            <Typography variant="h6" color="info.main" sx={{ lineHeight: 1.2, fontWeight: 'bold' }}>
              {myQueries}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Mine
            </Typography>
          </Box>

          <Box
            sx={{
              px: 2,
              py: 1,
              borderRadius: 1,
              bgcolor: alpha(theme.palette.secondary.main, 0.1),
              textAlign: 'center',
            }}
          >
            <Typography
              variant="h6"
              color="secondary.main"
              sx={{ lineHeight: 1.2, fontWeight: 'bold' }}
            >
              {sharedQueries}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Shared
            </Typography>
          </Box>
        </Box>

        {/* Recent Queries List */}
        {queries.length > 0 ? (
          <>
            <Divider sx={{ my: 1.5 }} />
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Recent Queries
            </Typography>
            <List dense disablePadding>
              {queries.map((query) => (
                <ListItem
                  key={query.id}
                  disablePadding
                  sx={{
                    py: 0.5,
                    '&:hover': { bgcolor: 'action.hover' },
                    borderRadius: 1,
                  }}
                  secondaryAction={
                    <Tooltip title="Execute Query">
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleExecuteQuery(query.id);
                        }}
                      >
                        <PlayArrowIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  }
                >
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 150 }}>
                          {query.name}
                        </Typography>
                        {query.visibility === 'shared' ? (
                          <ShareIcon fontSize="small" color="action" sx={{ fontSize: 14 }} />
                        ) : (
                          <LockIcon fontSize="small" color="action" sx={{ fontSize: 14 }} />
                        )}
                      </Box>
                    }
                    secondary={
                      <Typography variant="caption" color="text.secondary" noWrap>
                        {query.execution_count} executions
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </>
        ) : (
          <Box sx={{ py: 2, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              No saved queries yet
            </Typography>
          </Box>
        )}

        {/* Create Query Button */}
        <Box sx={{ mt: 2 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<AddIcon />}
            onClick={handleCreateQuery}
            fullWidth
          >
            Create Query
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

export default SavedQueriesWidget;
