/**
 * Host grid/list/compact view with optional grouping.
 *
 * Renders hosts as HostCards in the selected view mode (grid, list, compact).
 * When groupBy is active, hosts are shown under collapsible group headers.
 */

import React from 'react';
import { Box, Collapse, IconButton, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import { ExpandMore, ChevronRight } from '@mui/icons-material';
import type { Host } from '../../../types/host';
import type { ViewMode } from '../../../components/design-system';
import HostCard from './HostCard';

interface HostGridProps {
  processedHosts: Record<string, Host[]>;
  groupBy: string;
  viewMode: ViewMode;
  expandedGroups: string[];
  setExpandedGroups: React.Dispatch<React.SetStateAction<string[]>>;
  selectedHosts: string[];
  navigate: (path: string) => void;
  handleSelectHost: (id: string) => void;
  handleQuickScanWithValidation: (host: Host) => Promise<void>;
  handleEditHost: (host: Host) => void;
  handleDeleteHost: (host: Host) => void;
  checkHostStatus: (hostId: string) => Promise<void>;
  setQuickScanDialog: (val: { open: boolean; host: Host | null }) => void;
}

function getGridSize(viewMode: ViewMode) {
  if (viewMode === 'list') return { xs: 12 as const };
  if (viewMode === 'compact') return { xs: 6 as const, sm: 4 as const, md: 2 as const };
  return { xs: 12 as const, sm: 6 as const, md: 3 as const };
}

const HostGrid: React.FC<HostGridProps> = ({
  processedHosts,
  groupBy,
  viewMode,
  expandedGroups,
  setExpandedGroups,
  selectedHosts,
  navigate,
  handleSelectHost,
  handleQuickScanWithValidation,
  handleEditHost,
  handleDeleteHost,
  checkHostStatus,
  setQuickScanDialog,
}) => {
  const gridSize = getGridSize(viewMode);

  const toggleGroup = (groupName: string) => {
    setExpandedGroups((prev) =>
      prev.includes(groupName) ? prev.filter((g) => g !== groupName) : [...prev, groupName]
    );
  };

  const renderHostCard = (host: Host) => (
    <Grid size={gridSize} key={host.id}>
      <HostCard
        host={host}
        viewMode={viewMode}
        selectedHosts={selectedHosts}
        navigate={navigate}
        handleSelectHost={handleSelectHost}
        handleQuickScanWithValidation={handleQuickScanWithValidation}
        handleEditHost={handleEditHost}
        handleDeleteHost={handleDeleteHost}
        checkHostStatus={checkHostStatus}
        setQuickScanDialog={setQuickScanDialog}
      />
    </Grid>
  );

  if (groupBy !== 'none' && Object.keys(processedHosts).length > 0) {
    return (
      <Box>
        {Object.entries(processedHosts).map(([groupName, groupHosts]) => (
          <Box key={groupName} sx={{ mb: 4 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                {groupName} ({groupHosts.length})
              </Typography>
              <IconButton size="small" onClick={() => toggleGroup(groupName)}>
                {expandedGroups.includes(groupName) ? <ExpandMore /> : <ChevronRight />}
              </IconButton>
            </Box>

            <Collapse in={expandedGroups.includes(groupName)}>
              <Grid container spacing={viewMode === 'compact' ? 2 : 3}>
                {groupHosts.map(renderHostCard)}
              </Grid>
            </Collapse>
          </Box>
        ))}
      </Box>
    );
  }

  return (
    <Grid container spacing={viewMode === 'compact' ? 2 : 3}>
      {Object.values(processedHosts).flat().map(renderHostCard)}
    </Grid>
  );
};

export default HostGrid;
