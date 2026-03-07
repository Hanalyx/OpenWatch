import React from 'react';
import EnhancedBulkImportDialog from '../../components/hosts/EnhancedBulkImportDialog';
import { BulkScanDialog, BulkScanProgress } from '../../components/scans';
import {
  Box,
  Typography,
  Button,
  LinearProgress,
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
  Snackbar,
  Alert,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import { Add, FilterList, Groups, Download, Scanner, CloudUpload } from '@mui/icons-material';
import { FilterToolbar } from '../../components/design-system';
import { useHostsPage } from './hooks/useHostsPage';
import HostStatCards from './components/HostStatCards';
import HostGrid from './components/HostGrid';
import HostConfirmDialogs from './components/HostConfirmDialogs';
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

    // Notification state
    notification,
    setNotification,

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
      <HostStatCards
        stats={stats}
        autoRefreshEnabled={autoRefreshEnabled}
        onAddHost={() => navigate('/hosts/add-host')}
      />

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
        <HostGrid
          processedHosts={processedHosts}
          groupBy={groupBy}
          viewMode={viewMode}
          expandedGroups={expandedGroups}
          setExpandedGroups={setExpandedGroups}
          selectedHosts={selectedHosts}
          navigate={navigate}
          handleSelectHost={handleSelectHost}
          handleQuickScanWithValidation={handleQuickScanWithValidation}
          handleEditHost={handleEditHost}
          handleDeleteHost={handleDeleteHost}
          checkHostStatus={checkHostStatus}
          setQuickScanDialog={setQuickScanDialog}
        />
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

      <HostConfirmDialogs
        deleteDialog={deleteDialog}
        setDeleteDialog={setDeleteDialog}
        deletingHost={deletingHost}
        confirmDelete={confirmDelete}
        bulkActionDialog={bulkActionDialog}
        setBulkActionDialog={setBulkActionDialog}
        selectedBulkAction={selectedBulkAction}
        selectedHostCount={selectedHosts.length}
        executeBulkAction={executeBulkAction}
        quickScanDialog={quickScanDialog}
        setQuickScanDialog={setQuickScanDialog}
        handleQuickScanWithValidation={handleQuickScanWithValidation}
      />

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

      {/* Quick Scan Notification Snackbar */}
      <Snackbar
        open={notification.open}
        autoHideDuration={4000}
        onClose={() => setNotification((prev) => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setNotification((prev) => ({ ...prev, open: false }))}
          severity={notification.severity}
          variant="filled"
          sx={{ width: '100%' }}
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Hosts;
