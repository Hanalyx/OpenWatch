import React from 'react';
import EnhancedBulkImportDialog from '../../components/hosts/EnhancedBulkImportDialog';
import { BulkScanDialog, BulkScanProgress } from '../../components/scans';
import {
  Box,
  Typography,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
  Collapse,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Paper,
  SpeedDial,
  SpeedDialAction,
  SpeedDialIcon,
  Skeleton,
  Toolbar,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Add,
  FilterList,
  Computer,
  Error as ErrorIcon,
  Groups,
  Download,
  Security,
  ExpandMore,
  ChevronRight,
  Scanner,
  CloudUpload,
} from '@mui/icons-material';
import { StatCard, FilterToolbar } from '../../components/design-system';
import { useHostsPage } from './hooks/useHostsPage';
import HostCard from './components/HostCard';
import EditHostDialog from './components/EditHostDialog';

const Hosts: React.FC = () => {
  const {
    navigate,
    // Core state
    hosts,
    loading,
    selectedHosts,
    setSelectedHosts,
    searchQuery,
    setSearchQuery,
    viewMode,
    setViewMode,
    filterMenuAnchor,
    setFilterMenuAnchor,
    groupBy,
    setGroupBy,
    bulkActionDialog,
    setBulkActionDialog,
    selectedBulkAction,
    expandedGroups,
    setExpandedGroups,
    deleteDialog,
    setDeleteDialog,
    editDialog,
    setEditDialog,
    quickScanDialog,
    setQuickScanDialog,
    enhancedImportDialogOpen,
    setEnhancedImportDialogOpen,

    // Auto-refresh state
    autoRefreshEnabled,

    // Edit form state
    editFormData,
    setEditFormData,
    sshKeyValidated,
    systemCredentialInfo,
    editingAuthMethod,
    setEditingAuthMethod,
    deletingHost,
    showPassword,
    setShowPassword,

    // Filter states
    statusFilter,
    tagFilter,

    // Bulk scan states
    bulkScanDialog,
    setBulkScanDialog,
    bulkScanProgress,
    setBulkScanProgress,

    // Computed data
    stats,
    processedHosts,

    // Data fetching
    fetchHosts,

    // Handlers
    handleSelectHost,
    handleBulkAction,
    executeBulkAction,
    handleBulkScanStarted,
    handleQuickScanWithValidation,
    handleEditHost,
    handleDeleteHost,
    confirmDelete,
    confirmEdit,
    checkHostStatus,
    handleAuthMethodChange,
    validateSshKeyForEdit,
  } = useHostsPage();

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Host Management
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor and manage your infrastructure hosts and compliance status
        </Typography>
      </Box>

      {/* Header Statistics */}
      <Box sx={{ mb: 4 }}>
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, sm: 6, md: 2.4 }}>
            <StatCard
              title={autoRefreshEnabled ? 'Hosts Online (Auto)' : 'Hosts Online'}
              value={`${stats.online}/${stats.total}`}
              color="primary"
              icon={<Computer />}
              trend={stats.online === stats.total ? 'up' : 'flat'}
              trendValue={`${Math.round((stats.online / stats.total) * 100)}%`}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.4 }}>
            <StatCard
              title="Avg Compliance"
              value={`${stats.avgCompliance}%`}
              color={
                stats.avgCompliance >= 90
                  ? 'success'
                  : stats.avgCompliance >= 75
                    ? 'warning'
                    : 'error'
              }
              icon={<Security />}
              trend={stats.avgCompliance >= 85 ? 'up' : 'flat'}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.4 }}>
            <StatCard
              title="Critical Issues"
              value={stats.criticalHosts}
              color="error"
              icon={<ErrorIcon />}
              trend={stats.criticalHosts === 0 ? 'up' : 'down'}
              subtitle={stats.criticalHosts === 0 ? 'All clear' : 'Needs attention'}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.4 }}>
            <StatCard
              title="Need Scanning"
              value={stats.needsScanning}
              color="warning"
              icon={<Scanner />}
              trend={stats.needsScanning === 0 ? 'up' : 'down'}
              subtitle={stats.needsScanning === 0 ? 'Up to date' : 'Behind schedule'}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.4 }}>
            <StatCard
              title="Quick Actions"
              value="Add Host"
              color="primary"
              icon={<Add />}
              onClick={() => navigate('/hosts/add-host')}
              subtitle="Register new system"
            />
          </Grid>
        </Grid>
      </Box>

      {/* Toolbar */}
      <Paper sx={{ mb: 3 }}>
        <Toolbar sx={{ gap: 2 }}>
          <FilterToolbar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            searchPlaceholder="Search hosts by name, IP, or OS..."
            viewMode={viewMode}
            onViewModeChange={setViewMode}
            showViewMode={true}
            groupBy={groupBy}
            onGroupByChange={(group) =>
              setGroupBy(group as 'all' | 'none' | 'group' | 'status' | 'compliance')
            }
            groupOptions={[
              { value: 'all', label: 'All' },
              { value: 'group', label: 'By Team' },
              { value: 'status', label: 'By Status' },
              { value: 'compliance', label: 'By Compliance' },
            ]}
            selectedCount={selectedHosts.length}
            onClearSelection={() => setSelectedHosts([])}
            filterCount={statusFilter.length + tagFilter.length}
            onFilterClick={(event) => setFilterMenuAnchor(event.currentTarget)}
            bulkActions={
              <>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => handleBulkAction('scan')}
                  disabled={selectedHosts.length === 0}
                  startIcon={<Scanner />}
                >
                  Scan Selected
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => handleBulkAction('group')}
                  disabled={selectedHosts.length === 0}
                  startIcon={<Groups />}
                >
                  Assign Group
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => handleBulkAction('export')}
                  disabled={selectedHosts.length === 0}
                  startIcon={<Download />}
                >
                  Export
                </Button>
              </>
            }
          />
        </Toolbar>
      </Paper>

      {/* Content */}
      {loading ? (
        <Box>
          <LinearProgress sx={{ mb: 3 }} />
          <Grid container spacing={3}>
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <Grid size={{ xs: 12, sm: 6, md: 3 }} key={i}>
                <Skeleton variant="rectangular" height={200} />
              </Grid>
            ))}
          </Grid>
        </Box>
      ) : (
        <Box>
          {/* Grouped View */}
          {groupBy !== 'none' && Object.keys(processedHosts).length > 0 ? (
            <Box>
              {Object.entries(processedHosts).map(([groupName, groupHosts]) => (
                <Box key={groupName} sx={{ mb: 4 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6" sx={{ flexGrow: 1 }}>
                      {groupName} ({groupHosts.length})
                    </Typography>
                    <IconButton
                      size="small"
                      onClick={() =>
                        setExpandedGroups((prev) =>
                          prev.includes(groupName)
                            ? prev.filter((g) => g !== groupName)
                            : [...prev, groupName]
                        )
                      }
                    >
                      {expandedGroups.includes(groupName) ? <ExpandMore /> : <ChevronRight />}
                    </IconButton>
                  </Box>

                  <Collapse in={expandedGroups.includes(groupName)}>
                    <Grid container spacing={3}>
                      {groupHosts.map((host) => (
                        <Grid size={{ xs: 12, sm: 6, md: 3 }} key={host.id}>
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
                      ))}
                    </Grid>
                  </Collapse>
                </Box>
              ))}
            </Box>
          ) : (
            /* Grid/List View */
            <Grid container spacing={3}>
              {Object.values(processedHosts)
                .flat()
                .map((host) => (
                  <Grid size={{ xs: 12, sm: 6, md: 3 }} key={host.id}>
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
                ))}
            </Grid>
          )}
        </Box>
      )}

      {/* Dialogs */}
      <EnhancedBulkImportDialog
        open={enhancedImportDialogOpen}
        onClose={() => setEnhancedImportDialogOpen(false)}
        onImportComplete={() => {
          setEnhancedImportDialogOpen(false);
          fetchHosts();
        }}
      />

      <Dialog
        open={deleteDialog.open}
        onClose={() => setDeleteDialog({ open: false, host: null })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Delete Host</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete <strong>{deleteDialog.host?.displayName}</strong>? This
            action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setDeleteDialog({ open: false, host: null })}
            disabled={deletingHost}
          >
            Cancel
          </Button>
          <Button onClick={confirmDelete} color="error" variant="contained" disabled={deletingHost}>
            {deletingHost ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      <EditHostDialog
        open={editDialog.open}
        host={editDialog.host}
        onClose={() => setEditDialog({ open: false, host: null })}
        onConfirm={confirmEdit}
        editFormData={editFormData}
        onFormChange={setEditFormData}
        sshKeyValidated={sshKeyValidated}
        systemCredentialInfo={systemCredentialInfo}
        editingAuthMethod={editingAuthMethod}
        setEditingAuthMethod={setEditingAuthMethod}
        showPassword={showPassword}
        setShowPassword={setShowPassword}
        onAuthMethodChange={handleAuthMethodChange}
        onValidateSshKey={validateSshKeyForEdit}
      />

      <Dialog
        open={bulkActionDialog}
        onClose={() => setBulkActionDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Confirm Bulk Action</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to perform <strong>{selectedBulkAction}</strong> on{' '}
            {selectedHosts.length} selected hosts?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBulkActionDialog(false)}>Cancel</Button>
          <Button onClick={executeBulkAction} variant="contained">
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={quickScanDialog.open}
        onClose={() => setQuickScanDialog({ open: false, host: null })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Quick Scan</DialogTitle>
        <DialogContent>
          <Typography>
            Start a compliance scan for <strong>{quickScanDialog.host?.displayName}</strong>?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQuickScanDialog({ open: false, host: null })}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() =>
              quickScanDialog.host && handleQuickScanWithValidation(quickScanDialog.host)
            }
          >
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>

      {/* Filter Menu */}
      <Menu
        anchorEl={filterMenuAnchor}
        open={Boolean(filterMenuAnchor)}
        onClose={() => setFilterMenuAnchor(null)}
      >
        <MenuItem>
          <ListItemIcon>
            <FilterList />
          </ListItemIcon>
          <ListItemText>Advanced Filters</ListItemText>
        </MenuItem>
        <MenuItem>
          <ListItemIcon>
            <Download />
          </ListItemIcon>
          <ListItemText>Export Results</ListItemText>
        </MenuItem>
      </Menu>

      {/* Phase 2: Bulk Scan Dialog */}
      <BulkScanDialog
        open={bulkScanDialog}
        onClose={() => setBulkScanDialog(false)}
        selectedHosts={selectedHosts
          .map((hostId) => {
            const host = hosts.find((h) => h.id === hostId);
            return host
              ? {
                  id: host.id,
                  hostname: host.hostname,
                  display_name: host.displayName,
                  ip_address: host.ipAddress,
                  operating_system: host.operatingSystem,
                  environment: host.group || 'production',
                  last_scan: host.lastScan ?? undefined,
                }
              : null;
          })
          // Type-safe filter removes null values - result matches BulkScanDialog Host interface
          .filter((host): host is NonNullable<typeof host> => host !== null)}
        onScanStarted={handleBulkScanStarted}
        onError={(error) => console.error('Bulk scan error:', error)}
      />

      {/* Phase 2: Bulk Scan Progress Dialog */}
      <BulkScanProgress
        open={bulkScanProgress.open}
        onClose={() => setBulkScanProgress((prev) => ({ ...prev, open: false }))}
        sessionId={bulkScanProgress.sessionId}
        sessionName={bulkScanProgress.sessionName}
        onCancel={(sessionId) => {
          // Cancel bulk scan session via API
          void sessionId; // Session ID for cancellation request
          // API call to cancel would go here
          setBulkScanProgress((prev) => ({ ...prev, open: false }));
        }}
      />

      {/* Floating Action Button with Multiple Options */}
      <SpeedDial
        ariaLabel="Host actions"
        sx={{ position: 'fixed', bottom: 24, right: 24 }}
        icon={<SpeedDialIcon />}
      >
        <SpeedDialAction
          icon={<Add />}
          tooltipTitle="Add Single Host"
          onClick={() => navigate('/hosts/add-host')}
        />
        <SpeedDialAction
          icon={<CloudUpload />}
          tooltipTitle="Bulk Import"
          onClick={() => setEnhancedImportDialogOpen(true)}
        />
      </SpeedDial>
    </Box>
  );
};

export default Hosts;
