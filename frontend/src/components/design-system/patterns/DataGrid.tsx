import React from 'react';
import {
  Box,
  Grid,
  Typography,
  Collapse,
  IconButton,
  Chip,
  useTheme,
  Stack,
  List,
  ListItem,
} from '@mui/material';
import { ExpandMore, ChevronRight } from '@mui/icons-material';

export type ViewMode = 'grid' | 'list' | 'compact';

export interface DataGridItem {
  id: string;
  [key: string]: any;
}

export interface DataGridGroup {
  name: string;
  items: DataGridItem[];
  collapsed?: boolean;
}

interface DataGridProps<T extends DataGridItem> {
  items?: T[];
  groups?: DataGridGroup[];
  renderItem: (item: T, viewMode?: ViewMode) => React.ReactNode;
  columns?: {
    xs?: number;
    sm?: number;
    md?: number;
    lg?: number;
    xl?: number;
  };
  spacing?: number;
  showGroupHeaders?: boolean;
  onGroupToggle?: (groupName: string, collapsed: boolean) => void;
  emptyState?: React.ReactNode;
  loading?: boolean;
  loadingComponent?: React.ReactNode;
  viewMode?: ViewMode;
}

const DataGrid = <T extends DataGridItem>({
  items = [],
  groups = [],
  renderItem,
  columns = { xs: 12, sm: 6, md: 4, lg: 3, xl: 3 },
  spacing = 2,
  showGroupHeaders = true,
  onGroupToggle,
  emptyState,
  loading = false,
  loadingComponent,
  viewMode = 'grid',
}: DataGridProps<T>) => {
  const theme = useTheme();

  if (loading && loadingComponent) {
    return <>{loadingComponent}</>;
  }

  // Handle ungrouped items
  const dataToRender = groups.length > 0 ? groups : [{ name: '', items, collapsed: false }];

  if (dataToRender.every((group) => group.items.length === 0) && emptyState) {
    return <>{emptyState}</>;
  }

  const renderGroupItems = (items: T[]) => {
    switch (viewMode) {
      case 'list':
        return (
          <Stack spacing={1}>
            {items.map((item) => (
              <Box key={item.id} sx={{ width: '100%' }}>
                {renderItem(item as T, viewMode)}
              </Box>
            ))}
          </Stack>
        );

      case 'compact':
        return (
          <Grid container spacing={1}>
            {items.map((item) => (
              <Grid item xs={12} sm={6} md={4} lg={3} xl={2} key={item.id}>
                {renderItem(item as T, viewMode)}
              </Grid>
            ))}
          </Grid>
        );

      case 'grid':
      default:
        return (
          <Grid container spacing={spacing}>
            {items.map((item) => (
              <Grid item {...columns} key={item.id}>
                {renderItem(item as T, viewMode)}
              </Grid>
            ))}
          </Grid>
        );
    }
  };

  return (
    <Box>
      {dataToRender.map((group, groupIndex) => (
        <Box key={group.name || groupIndex} sx={{ mb: 3 }}>
          {/* Group Header */}
          {showGroupHeaders && group.name && (
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                mb: 2,
                cursor: onGroupToggle ? 'pointer' : 'default',
              }}
              onClick={() => onGroupToggle?.(group.name, !group.collapsed)}
            >
              {onGroupToggle && (
                <IconButton size="small">
                  {group.collapsed ? <ChevronRight /> : <ExpandMore />}
                </IconButton>
              )}
              <Typography variant="h6" sx={{ ml: onGroupToggle ? 1 : 0, mr: 2 }}>
                {group.name}
              </Typography>
              <Chip
                label={group.items.length}
                size="small"
                sx={{
                  bgcolor: theme.palette.action.hover,
                  color: theme.palette.text.secondary,
                }}
              />
            </Box>
          )}

          {/* Group Items */}
          <Collapse in={!group.collapsed}>{renderGroupItems(group.items as T[])}</Collapse>
        </Box>
      ))}
    </Box>
  );
};

export default DataGrid;
