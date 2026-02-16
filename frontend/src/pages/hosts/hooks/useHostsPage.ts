import type React from 'react';
import { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTheme, type Theme } from '@mui/material';
import { api } from '../../../services/api';
import { adaptHosts, toUpdateHostRequest, type ApiHostResponse } from '../../../services/adapters';
import type { Host } from '../../../types/host';
import { REFRESH_INTERVALS } from '../../../constants/refresh';
import { validateSshKey } from '../../../utils/hostValidation';
import type { ViewMode } from '../../../components/design-system';

/**
 * Return type for the useHostsPage hook.
 *
 * Contains all state, computed data, and handler functions
 * extracted from the Hosts page component.
 */
export interface UseHostsPageReturn {
  // Navigation and theme
  navigate: ReturnType<typeof useNavigate>;
  theme: Theme;

  // Core state
  hosts: Host[];
  setHosts: React.Dispatch<React.SetStateAction<Host[]>>;
  loading: boolean;
  selectedHosts: string[];
  setSelectedHosts: React.Dispatch<React.SetStateAction<string[]>>;
  searchQuery: string;
  setSearchQuery: React.Dispatch<React.SetStateAction<string>>;
  viewMode: ViewMode;
  setViewMode: React.Dispatch<React.SetStateAction<ViewMode>>;
  filterMenuAnchor: null | HTMLElement;
  setFilterMenuAnchor: React.Dispatch<React.SetStateAction<null | HTMLElement>>;
  groupBy: 'all' | 'none' | 'group' | 'status' | 'compliance';
  setGroupBy: React.Dispatch<
    React.SetStateAction<'all' | 'none' | 'group' | 'status' | 'compliance'>
  >;
  bulkActionDialog: boolean;
  setBulkActionDialog: React.Dispatch<React.SetStateAction<boolean>>;
  selectedBulkAction: string;
  setSelectedBulkAction: React.Dispatch<React.SetStateAction<string>>;
  expandedGroups: string[];
  setExpandedGroups: React.Dispatch<React.SetStateAction<string[]>>;
  deleteDialog: { open: boolean; host: Host | null };
  setDeleteDialog: React.Dispatch<React.SetStateAction<{ open: boolean; host: Host | null }>>;
  editDialog: { open: boolean; host: Host | null };
  setEditDialog: React.Dispatch<React.SetStateAction<{ open: boolean; host: Host | null }>>;
  quickScanDialog: { open: boolean; host: Host | null };
  setQuickScanDialog: React.Dispatch<React.SetStateAction<{ open: boolean; host: Host | null }>>;
  enhancedImportDialogOpen: boolean;
  setEnhancedImportDialogOpen: React.Dispatch<React.SetStateAction<boolean>>;

  // Auto-refresh state
  autoRefreshEnabled: boolean;
  refreshInterval: number;

  // Edit form state
  editFormData: {
    hostname: string;
    displayName: string;
    ipAddress: string;
    operatingSystem: string;
    port: number;
    username: string;
    authMethod: 'password' | 'ssh_key' | 'none' | 'default' | 'system_default';
    sshKey: string;
    password: string;
  };
  setEditFormData: React.Dispatch<
    React.SetStateAction<{
      hostname: string;
      displayName: string;
      ipAddress: string;
      operatingSystem: string;
      port: number;
      username: string;
      authMethod: 'password' | 'ssh_key' | 'none' | 'default' | 'system_default';
      sshKey: string;
      password: string;
    }>
  >;
  sshKeyValidated: boolean;
  setSshKeyValidated: React.Dispatch<React.SetStateAction<boolean>>;
  systemCredentialInfo: {
    name: string;
    username: string;
    authMethod: string;
    sshKeyType?: string;
    sshKeyBits?: number;
    sshKeyComment?: string;
  } | null;
  setSystemCredentialInfo: React.Dispatch<
    React.SetStateAction<{
      name: string;
      username: string;
      authMethod: string;
      sshKeyType?: string;
      sshKeyBits?: number;
      sshKeyComment?: string;
    } | null>
  >;
  editingAuthMethod: boolean;
  setEditingAuthMethod: React.Dispatch<React.SetStateAction<boolean>>;
  deletingHost: boolean;
  showPassword: boolean;
  setShowPassword: React.Dispatch<React.SetStateAction<boolean>>;

  // Filter states
  statusFilter: string[];
  complianceFilter: [number, number];
  tagFilter: string[];

  // Bulk scan states
  bulkScanDialog: boolean;
  setBulkScanDialog: React.Dispatch<React.SetStateAction<boolean>>;
  bulkScanProgress: { open: boolean; sessionId: string; sessionName: string };
  setBulkScanProgress: React.Dispatch<
    React.SetStateAction<{ open: boolean; sessionId: string; sessionName: string }>
  >;

  // Notification state for snackbar
  notification: { open: boolean; message: string; severity: 'success' | 'error' | 'info' };
  setNotification: React.Dispatch<
    React.SetStateAction<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>
  >;

  // Computed data
  stats: {
    online: number;
    total: number;
    avgCompliance: number;
    criticalHosts: number;
    needsScanning: number;
  };
  processedHosts: { [key: string]: Host[] };

  // Data fetching
  fetchHosts: (silent?: boolean) => Promise<void>;

  // Handlers
  handleSelectHost: (hostId: string) => void;
  handleBulkAction: (action: string) => void;
  executeBulkAction: () => void;
  handleBulkScanStarted: (sessionId: string, sessionName: string) => void;
  handleQuickScanWithValidation: (host: Host) => Promise<void>;
  handleEditHost: (host: Host) => void;
  handleDeleteHost: (host: Host) => void;
  confirmDelete: () => Promise<void>;
  confirmEdit: () => Promise<void>;
  checkHostStatus: (hostId: string) => Promise<void>;
  handleAuthMethodChange: (newMethod: string) => void;
  validateSshKeyForEdit: (keyContent: string) => void;
}

/**
 * Custom hook that encapsulates all state, data fetching, effects,
 * computed data, and handlers for the Hosts page.
 *
 * Extracted from Hosts.tsx to reduce component complexity and
 * improve testability and maintainability.
 */
export function useHostsPage(): UseHostsPageReturn {
  const theme = useTheme();
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [filterMenuAnchor, setFilterMenuAnchor] = useState<null | HTMLElement>(null);
  const [groupBy, setGroupBy] = useState<'all' | 'none' | 'group' | 'status' | 'compliance'>('all');
  const [bulkActionDialog, setBulkActionDialog] = useState(false);
  const [selectedBulkAction, setSelectedBulkAction] = useState('');
  const [expandedGroups, setExpandedGroups] = useState<string[]>([]);
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; host: Host | null }>({
    open: false,
    host: null,
  });
  const [editDialog, setEditDialog] = useState<{ open: boolean; host: Host | null }>({
    open: false,
    host: null,
  });
  const [quickScanDialog, setQuickScanDialog] = useState<{ open: boolean; host: Host | null }>({
    open: false,
    host: null,
  });
  const [enhancedImportDialogOpen, setEnhancedImportDialogOpen] = useState(false);

  // Auto-refresh state - configuration for future automatic host list refreshing
  const [autoRefreshEnabled] = useState(true);
  const [refreshInterval] = useState(REFRESH_INTERVALS.NORMAL);
  const [, setLastRefresh] = useState<Date | null>(null);
  const [editFormData, setEditFormData] = useState({
    hostname: '',
    displayName: '',
    ipAddress: '',
    operatingSystem: '',
    port: 22,
    username: '',
    authMethod: 'ssh_key' as 'password' | 'ssh_key' | 'none' | 'default' | 'system_default',
    sshKey: '',
    password: '',
  });
  const [sshKeyValidated, setSshKeyValidated] = useState(false);
  const [systemCredentialInfo, setSystemCredentialInfo] = useState<{
    name: string;
    username: string;
    authMethod: string;
    sshKeyType?: string;
    sshKeyBits?: number;
    sshKeyComment?: string;
  } | null>(null);
  const [editingAuthMethod, setEditingAuthMethod] = useState(false);
  const [deletingHost, setDeletingHost] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Filter states - reserved for future advanced filtering features
  const [statusFilter] = useState<string[]>([]);
  const [complianceFilter] = useState<[number, number]>([0, 100]);
  const [tagFilter] = useState<string[]>([]);

  // Phase 2: Bulk scan states
  const [bulkScanDialog, setBulkScanDialog] = useState(false);
  const [bulkScanProgress, setBulkScanProgress] = useState<{
    open: boolean;
    sessionId: string;
    sessionName: string;
  }>({ open: false, sessionId: '', sessionName: '' });

  // Notification state for snackbar
  const [notification, setNotification] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info';
  }>({ open: false, message: '', severity: 'info' });

  // Fetch hosts from API
  const fetchHosts = async (silent: boolean = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }

      const apiHosts = await api.get<ApiHostResponse[]>('/api/hosts/');

      // Transform API response to match our Host interface via adapter
      setHosts(adaptHosts(apiHosts));
      setLastRefresh(new Date());
    } catch (error) {
      console.error('Error fetching hosts:', error);
      // Keep hosts empty or show existing data
      if (!silent) {
        // You could set an error state here if needed
        // setError('Failed to load hosts');
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  // Fetch hosts on component mount
  useEffect(() => {
    fetchHosts();
  }, []);

  // Auto-refresh effect with dynamic interval based on running scans
  useEffect(() => {
    if (!autoRefreshEnabled) {
      return;
    }

    // Check if any hosts have running scans
    const hasRunningScan = hosts.some(
      (host) => host.scanStatus === 'running' || host.scanStatus === 'pending'
    );

    // Use shorter interval if there are running scans (adaptive polling)
    const dynamicInterval = hasRunningScan ? REFRESH_INTERVALS.ACTIVE_SCAN : refreshInterval;

    const intervalId = setInterval(() => {
      // Only refresh if the page is visible (performance optimization)
      if (!document.hidden) {
        fetchHosts(true); // Silent refresh
      }
    }, dynamicInterval);

    // Cleanup interval on component unmount or when dependencies change
    return () => clearInterval(intervalId);
  }, [autoRefreshEnabled, refreshInterval, hosts]);

  // Pause auto-refresh when page becomes hidden, resume when visible
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden && autoRefreshEnabled) {
        // Page became visible, do an immediate refresh
        fetchHosts(true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [autoRefreshEnabled]);

  // Calculate statistics
  const stats = useMemo(() => {
    const online = hosts.filter((h) => h.status === 'online').length;
    const total = hosts.length;

    // Only calculate average compliance for hosts that have been scanned
    const hostsWithCompliance = hosts.filter((h) => h.complianceScore !== null);
    const avgCompliance =
      hostsWithCompliance.length > 0
        ? Math.round(
            hostsWithCompliance.reduce((sum, h) => sum + (h.complianceScore || 0), 0) /
              hostsWithCompliance.length
          )
        : 0;

    const criticalHosts = hosts.filter((h) => h.criticalIssues > 0).length;

    // Only count hosts that need scanning if they have been scanned before
    const needsScanning = hosts.filter((h) => {
      if (!h.lastScan) return true; // Never scanned hosts need scanning
      const lastScan = new Date(h.lastScan);
      const daysSince = (Date.now() - lastScan.getTime()) / (1000 * 60 * 60 * 24);
      return daysSince > 7;
    }).length;

    return { online, total, avgCompliance, criticalHosts, needsScanning };
  }, [hosts]);

  // Filter and group hosts
  const processedHosts = useMemo(() => {
    const filtered = hosts.filter((host) => {
      const matchesSearch =
        !searchQuery ||
        host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
        host.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        host.ipAddress.includes(searchQuery) ||
        host.operatingSystem.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus = statusFilter.length === 0 || statusFilter.includes(host.status);
      const matchesCompliance =
        (host.complianceScore ?? 0) >= complianceFilter[0] &&
        (host.complianceScore ?? 0) <= complianceFilter[1];
      const matchesTags =
        tagFilter.length === 0 || host.tags.some((tag) => tagFilter.includes(tag));

      return matchesSearch && matchesStatus && matchesCompliance && matchesTags;
    });

    // Group hosts
    if (groupBy === 'all' || groupBy === 'none') {
      // For 'all' grouping, return all hosts without grouping
      return { 'All Hosts': filtered };
    } else {
      const groups: { [key: string]: Host[] } = {};
      filtered.forEach((host) => {
        let key = '';
        switch (groupBy) {
          case 'group':
            key = host.group;
            break;
          case 'status':
            key = host.status.charAt(0).toUpperCase() + host.status.slice(1);
            break;
          case 'compliance': {
            const score = host.complianceScore ?? 0;
            if (score >= 90) key = 'Excellent (90-100%)';
            else if (score >= 75) key = 'Good (75-89%)';
            else if (score >= 60) key = 'Fair (60-74%)';
            else key = 'Poor (<60%)';
            break;
          }
        }
        if (!groups[key]) groups[key] = [];
        groups[key].push(host);
      });
      return groups;
    }
  }, [hosts, searchQuery, statusFilter, complianceFilter, tagFilter, groupBy]);

  // Automatically expand all groups when processedHosts changes
  useEffect(() => {
    const allGroupNames = Object.keys(processedHosts);
    setExpandedGroups(allGroupNames);
  }, [processedHosts]);

  const handleSelectHost = (hostId: string) => {
    setSelectedHosts((prev) =>
      prev.includes(hostId) ? prev.filter((id) => id !== hostId) : [...prev, hostId]
    );
  };

  const handleBulkAction = (action: string) => {
    if (action === 'scan') {
      // Trigger bulk quick scan directly (one-click)
      handleBulkQuickScan();
    } else {
      setSelectedBulkAction(action);
      setBulkActionDialog(true);
    }
  };

  // Bulk quick scan using Aegis one-click scan API
  const handleBulkQuickScan = async () => {
    if (selectedHosts.length === 0) return;

    try {
      // Call quick scan API endpoint with host_ids array
      interface QuickScanResponse {
        message: string;
        scan_count: number;
        scans: Array<{
          host_id: string;
          hostname: string;
          scan_id: string;
          status: string;
        }>;
        queued_at: string;
      }

      const response = await api.post<QuickScanResponse>('/api/scans/quick', {
        host_ids: selectedHosts,
      });

      // Check if scans were queued successfully
      const successCount = response.scans.filter((s) => s.status === 'queued').length;
      if (successCount > 0) {
        // Show success notification
        setNotification({
          open: true,
          message: `Started ${successCount} scan(s) for ${selectedHosts.length} host(s)`,
          severity: 'success',
        });

        // Clear selection
        setSelectedHosts([]);

        // Refresh hosts list to show running scan status after brief delay
        setTimeout(() => fetchHosts(true), 1500);
      } else {
        console.error('Bulk quick scan failed:', response);
        setNotification({
          open: true,
          message: 'Failed to start bulk scans',
          severity: 'error',
        });
      }
    } catch (error) {
      console.error('Bulk quick scan error:', error);

      // Type-safe error message extraction
      const errorMessage =
        error &&
        typeof error === 'object' &&
        'response' in error &&
        error.response &&
        typeof error.response === 'object' &&
        'data' in error.response &&
        error.response.data &&
        typeof error.response.data === 'object' &&
        'detail' in error.response.data &&
        typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : error instanceof Error
            ? error.message
            : 'Failed to start bulk scans';

      setNotification({
        open: true,
        message: `Bulk scan failed: ${errorMessage}`,
        severity: 'error',
      });
    }
  };

  const executeBulkAction = () => {
    // Execute bulk action on selected hosts (for non-scan actions)
    void selectedBulkAction; // Action type for backend API call
    void selectedHosts; // Host IDs for bulk operation
    setBulkActionDialog(false);
    setSelectedHosts([]);
  };

  // Phase 2: Handle bulk scan start (legacy - kept for BulkScanDialog compatibility)
  const handleBulkScanStarted = (sessionId: string, sessionName: string) => {
    // Bulk scan session initiated for multiple hosts
    setBulkScanProgress({
      open: true,
      sessionId,
      sessionName,
    });
    setBulkScanDialog(false);
    setSelectedHosts([]); // Clear selection
  };

  // Quick scan using Aegis one-click scan API
  const handleQuickScanWithValidation = async (host: Host) => {
    try {
      // Close dialog immediately
      setQuickScanDialog({ open: false, host: null });

      // Call quick scan API endpoint
      interface QuickScanResponse {
        message: string;
        scan_count: number;
        scans: Array<{
          host_id: string;
          hostname: string;
          scan_id: string;
          status: string;
        }>;
        queued_at: string;
      }

      const response = await api.post<QuickScanResponse>('/api/scans/quick', {
        host_id: host.id,
      });

      // Check if scan was queued successfully
      if (response.scan_count > 0 && response.scans[0]?.status === 'queued') {
        // Show success notification
        setNotification({
          open: true,
          message: `Scan started for ${host.displayName}`,
          severity: 'success',
        });

        // Refresh hosts list to show running scan status after brief delay
        setTimeout(() => fetchHosts(true), 1500);
      } else {
        console.error('Quick scan failed:', response);
        setNotification({
          open: true,
          message: `Failed to start scan for ${host.displayName}`,
          severity: 'error',
        });
      }
    } catch (error) {
      console.error('Quick scan error:', error);

      // Type-safe error message extraction
      const errorMessage =
        error &&
        typeof error === 'object' &&
        'response' in error &&
        error.response &&
        typeof error.response === 'object' &&
        'data' in error.response &&
        error.response.data &&
        typeof error.response.data === 'object' &&
        'detail' in error.response.data &&
        typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : error instanceof Error
            ? error.message
            : 'Failed to start scan';

      setNotification({
        open: true,
        message: `Scan failed: ${errorMessage}`,
        severity: 'error',
      });
    }
  };

  const handleEditHost = (host: Host) => {
    const initialFormData = {
      hostname: host.hostname,
      displayName: host.displayName,
      ipAddress: host.ipAddress,
      operatingSystem: host.operatingSystem,
      port: host.port || 22,
      username: host.username || '',
      authMethod: host.authMethod || 'ssh_key',
      sshKey: '',
      password: '',
    };

    // Initialize edit form with current host configuration for modification
    setEditFormData(initialFormData);
    setSshKeyValidated(false);
    setEditingAuthMethod(false);
    setSystemCredentialInfo(null);

    // Fetch system credentials if using system default
    if (host.authMethod === 'system_default') {
      fetchSystemCredentialsForEdit();
    }

    setEditDialog({ open: true, host });
  };

  const handleDeleteHost = (host: Host) => {
    setDeleteDialog({ open: true, host });
  };

  const confirmDelete = async () => {
    if (!deleteDialog.host) return;

    setDeletingHost(true);

    try {
      await api.delete(`/api/hosts/${deleteDialog.host.id}`);

      // Remove host from local state
      setHosts((prev) => prev.filter((h) => h.id !== deleteDialog.host!.id));
      setDeleteDialog({ open: false, host: null });
    } catch (error: unknown) {
      console.error('Error deleting host:', error);

      // Type-safe error message extraction for axios errors
      const errorMessage =
        error &&
        typeof error === 'object' &&
        'response' in error &&
        error.response &&
        typeof error.response === 'object' &&
        'data' in error.response &&
        error.response.data &&
        typeof error.response.data === 'object' &&
        'detail' in error.response.data &&
        typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : error instanceof Error
            ? error.message
            : 'Failed to delete host';
      alert(`Failed to delete host: ${errorMessage}`);
    } finally {
      setDeletingHost(false);
    }
  };

  const confirmEdit = async () => {
    if (!editDialog.host) return;

    try {
      // Submit updated host configuration to API
      await api.put(`/api/hosts/${editDialog.host.id}`, toUpdateHostRequest(editFormData));

      // Refresh hosts list to get latest data including SSH key metadata
      await fetchHosts();
      setEditDialog({ open: false, host: null });
    } catch (error) {
      console.error('Error updating host:', error);
    }
  };

  const checkHostStatus = async (hostId: string) => {
    try {
      // Define response type for connectivity check
      interface ConnectivityCheckResult {
        current_status: string;
        diagnostics?: {
          ping_success?: boolean;
          port_open?: boolean;
          ssh_accessible?: boolean;
          ssh_credentials_source?: string;
        };
        response_time_ms?: number;
        last_check?: string;
        error_message?: string;
      }

      // Perform IMMEDIATE comprehensive connectivity check (ping -> port -> SSH)
      const result = await api.post<ConnectivityCheckResult>(
        `/api/monitoring/hosts/${hostId}/check-connectivity`
      );

      // Get host details
      const host = hosts.find((h) => h.id === hostId);

      // Compliance-focused status messages with accurate diagnostics
      const statusMessages = {
        online: 'Host is online and ready for scans',
        reachable: 'Host is reachable but SSH authentication failed',
        ping_only: 'Host responds to ping but SSH port is closed',
        offline: 'Host is completely unreachable',
        error: 'Error occurred while checking host status',
        maintenance: 'Host is in maintenance mode',
      };

      const baseMessage =
        statusMessages[result.current_status as keyof typeof statusMessages] ||
        'Status check completed';

      // Build detailed diagnostic message
      let detailedMessage = `${host?.hostname || 'Host'}: ${baseMessage}\n\n`;

      // Show granular diagnostics
      if (result.diagnostics) {
        detailedMessage += `Diagnostic Results:\n`;
        detailedMessage += `• Ping: ${result.diagnostics.ping_success ? 'Success' : 'Failed'}\n`;
        detailedMessage += `• Port 22: ${result.diagnostics.port_open ? 'Open' : 'Closed'}\n`;
        detailedMessage += `• SSH Auth: ${result.diagnostics.ssh_accessible ? 'Success' : 'Failed'}\n`;
        if (result.diagnostics.ssh_credentials_source) {
          detailedMessage += `• Credentials: ${result.diagnostics.ssh_credentials_source}\n`;
        }
        detailedMessage += `\n`;
      }

      detailedMessage += `Connectivity Details:\n`;
      detailedMessage += `• Status: ${result.current_status}\n`;
      detailedMessage += `• Response Time: ${result.response_time_ms || 'N/A'}ms\n`;
      detailedMessage += `• Last Check: ${result.last_check ? new Date(result.last_check).toLocaleString() : 'Just now'}\n\n`;

      // Add specific troubleshooting guidance based on diagnostic results
      const isReady = result.current_status === 'online';
      if (isReady) {
        detailedMessage += `Status: Host is ready for compliance scans!`;
      } else if (result.current_status === 'ping_only') {
        detailedMessage += `Troubleshooting: Host responds to ping but SSH port 22 is closed.\n`;
        detailedMessage += `• Check if SSH service is running\n`;
        detailedMessage += `• Verify firewall rules allow port 22\n`;
        detailedMessage += `• Confirm SSH is listening on port 22`;
      } else if (result.current_status === 'reachable') {
        detailedMessage += `Troubleshooting: SSH port is open but authentication failed.\n`;
        detailedMessage += `• Verify SSH credentials are correct\n`;
        detailedMessage += `• Check SSH key permissions and format\n`;
        detailedMessage += `• Review host's /var/log/auth.log for details`;
      } else if (result.current_status === 'offline') {
        detailedMessage += `Troubleshooting: Host is completely unreachable.\n`;
        detailedMessage += `• Verify host is powered on\n`;
        detailedMessage += `• Check network connectivity\n`;
        detailedMessage += `• Confirm IP address is correct`;
      } else {
        detailedMessage += `Host is not ready for scans.\n`;
        if (result.error_message) {
          detailedMessage += `Error: ${result.error_message}`;
        }
      }

      // Host comprehensive readiness check completed
      // Show detailed popup
      alert(detailedMessage);

      // Refresh hosts list to show updated status
      setTimeout(() => fetchHosts(true), 1000);
    } catch (error) {
      console.error('Error checking host status:', error);
      alert('Failed to check host status. Please try again.');
    }
  };

  const fetchSystemCredentialsForEdit = async () => {
    try {
      // Type-safe credential lookup - find default system credential
      interface SystemCredential {
        is_default: boolean;
        name: string;
        username: string;
        auth_method: string;
        ssh_key_type?: string;
        ssh_key_bits?: number;
        ssh_key_comment?: string;
      }
      // Use unified credentials API with scope filter
      const response = await api.get<SystemCredential[]>('/api/system/credentials?scope=system');
      const defaultCredential = response.find((cred: SystemCredential) => cred.is_default);

      if (defaultCredential) {
        setSystemCredentialInfo({
          name: defaultCredential.name,
          username: defaultCredential.username,
          authMethod: defaultCredential.auth_method,
          sshKeyType: defaultCredential.ssh_key_type,
          sshKeyBits: defaultCredential.ssh_key_bits,
          sshKeyComment: defaultCredential.ssh_key_comment,
        });
      }
    } catch (error) {
      console.error('Failed to fetch system credentials for edit:', error);
    }
  };

  const handleAuthMethodChange = (newMethod: string) => {
    // Type-safe auth method - newMethod validated by Select component to be one of the allowed values
    setEditFormData((prev) => ({
      ...prev,
      authMethod: newMethod as 'password' | 'ssh_key' | 'none' | 'default' | 'system_default',
    }));
    setSshKeyValidated(false);

    // Fetch system credentials when system_default is selected
    if (newMethod === 'system_default') {
      fetchSystemCredentialsForEdit();
    } else {
      setSystemCredentialInfo(null);
    }
  };

  /**
   * Validate SSH key format for edit dialog.
   *
   * Uses imported validateSshKey utility from utils/hostValidation.ts.
   * Sets validation state for SSH key input field.
   *
   * @param keyContent - SSH private key content to validate
   */
  const validateSshKeyForEditHandler = (keyContent: string) => {
    if (!keyContent.trim()) {
      setSshKeyValidated(false);
      return;
    }

    const isValid = validateSshKey(keyContent);
    setSshKeyValidated(isValid);
  };

  return {
    // Navigation and theme
    navigate,
    theme,

    // Core state
    hosts,
    setHosts,
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
    setSelectedBulkAction,
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
    refreshInterval,

    // Edit form state
    editFormData,
    setEditFormData,
    sshKeyValidated,
    setSshKeyValidated,
    systemCredentialInfo,
    setSystemCredentialInfo,
    editingAuthMethod,
    setEditingAuthMethod,
    deletingHost,
    showPassword,
    setShowPassword,

    // Filter states
    statusFilter,
    complianceFilter,
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
    validateSshKeyForEdit: validateSshKeyForEditHandler,
  };
}
