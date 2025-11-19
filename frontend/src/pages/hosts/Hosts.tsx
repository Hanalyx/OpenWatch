import React, { useState, useMemo, useEffect } from 'react';
import EnhancedBulkImportDialog from '../../components/hosts/EnhancedBulkImportDialog';
import { BulkScanDialog, BulkScanProgress } from '../../components/scans';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Button,
  IconButton,
  Chip,
  TextField,
  InputAdornment,
  Avatar,
  Menu,
  MenuItem,
  Checkbox,
  Toolbar,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
  Collapse,
  Divider,
  ListItemIcon,
  ListItemText,
  Paper,
  SpeedDial,
  SpeedDialAction,
  SpeedDialIcon,
  Skeleton,
  useTheme,
  alpha,
  FormControl,
  InputLabel,
  Select,
} from '@mui/material';
import {
  Add,
  FilterList,
  MoreVert,
  Computer,
  CheckCircle,
  Error as ErrorIcon,
  PlayArrow,
  Delete,
  Edit,
  Groups,
  NetworkCheck,
  Download,
  Security,
  VpnKey,
  Timeline,
  Assessment,
  ExpandMore,
  ChevronRight,
  Memory,
  Storage as StorageIcon,
  Scanner,
  CloudUpload,
  CheckCircleOutline,
  Info,
  Visibility,
  VisibilityOff,
} from '@mui/icons-material';
// Recharts imports removed - no longer used in current implementation
import { useNavigate } from 'react-router-dom';
import {
  StatCard,
  StatusChip,
  ComplianceRing,
  FilterToolbar,
  type ViewMode,
} from '../../components/design-system';
import { api } from '../../services/api';
import type { Host } from '../../types/host';
import { REFRESH_INTERVALS } from '../../constants/refresh';
import { validateSshKey } from '../../utils/hostValidation';
import { getComplianceScoreColor } from '../../utils/hostStatus';

/**
 * API host response structure from backend
 * Maps snake_case backend fields to frontend Host interface
 * Backend uses PostgreSQL naming conventions (snake_case)
 */
interface ApiHostResponse {
  id: string;
  hostname: string;
  display_name?: string;
  ip_address: string;
  operating_system: string;
  os_version?: string;
  status?: string;
  scan_status?: string;
  compliance_score?: number;
  last_scan?: string;
  last_check?: string;
  critical_issues?: number;
  high_issues?: number;
  medium_issues?: number;
  low_issues?: number;
  tags?: string[];
  group?: string;
  group_id?: number;
  group_name?: string;
  group_description?: string;
  group_color?: string;
  owner?: string;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  uptime?: string;
  last_backup?: string;
  ssh_key?: boolean;
  agent_status?: string;
  scan_profile?: string;
  port?: number;
  username?: string;
  auth_method?: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  latest_scan_id?: string;
  latest_scan_name?: string;
  scan_progress?: number;
  failed_rules?: number;
  passed_rules?: number;
  total_rules?: number;
}

const Hosts: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [filterMenuAnchor, setFilterMenuAnchor] = useState<null | HTMLElement>(null);
  const [groupBy, setGroupBy] = useState<'all' | 'none' | 'group' | 'status' | 'compliance'>('all');
  // Filter panel visibility state - reserved for future advanced filtering features
  const [_showFilters, _setShowFilters] = useState(false);
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
  // Host group management dialog states - reserved for future group management features
  const [_hostGroupsDialogOpen, _setHostGroupsDialogOpen] = useState(false);
  const [_assignGroupDialogOpen, _setAssignGroupDialogOpen] = useState(false);
  const [quickScanDialog, setQuickScanDialog] = useState<{ open: boolean; host: Host | null }>({
    open: false,
    host: null,
  });
  const [enhancedImportDialogOpen, setEnhancedImportDialogOpen] = useState(false);

  // Auto-refresh state - configuration for future automatic host list refreshing
  const [autoRefreshEnabled, _setAutoRefreshEnabled] = useState(true);
  const [refreshInterval, _setRefreshInterval] = useState(REFRESH_INTERVALS.NORMAL);
  const [_lastRefresh, setLastRefresh] = useState<Date | null>(null);
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
  // SSH key deletion state - reserved for future host credential management features
  const [_deletingSSHKey, setDeletingSSHKey] = useState(false);
  const [deletingHost, setDeletingHost] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Filter states - reserved for future advanced filtering features
  const [statusFilter, _setStatusFilter] = useState<string[]>([]);
  const [complianceFilter, _setComplianceFilter] = useState<[number, number]>([0, 100]);
  const [tagFilter, _setTagFilter] = useState<string[]>([]);

  // Phase 2: Bulk scan states
  const [bulkScanDialog, setBulkScanDialog] = useState(false);
  const [bulkScanProgress, setBulkScanProgress] = useState<{
    open: boolean;
    sessionId: string;
    sessionName: string;
  }>({ open: false, sessionId: '', sessionName: '' });

  // Fetch hosts from API
  const fetchHosts = async (silent: boolean = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }

      const apiHosts = await api.get('/api/hosts/');

      // Auto-refresh completed successfully

      // Transform API response to match our Host interface
      const transformedHosts = apiHosts.map((host: ApiHostResponse) => ({
        id: host.id,
        hostname: host.hostname,
        displayName: host.display_name || host.hostname,
        ipAddress: host.ip_address,
        operatingSystem: host.operating_system,
        status:
          host.scan_status === 'running' || host.scan_status === 'pending'
            ? 'scanning'
            : host.status || 'offline',
        complianceScore: host.compliance_score || null,
        complianceTrend: 'stable' as const,
        lastScan: host.last_scan || null,
        lastCheck: host.last_check || null,
        nextScan: host.last_scan ? 'Pending' : null,
        criticalIssues: host.critical_issues || 0,
        highIssues: host.high_issues || 0,
        mediumIssues: host.medium_issues || 0,
        lowIssues: host.low_issues || 0,
        tags: host.tags || [],
        group: host.group_name || host.group || 'Ungrouped',
        group_id: host.group_id || null,
        group_name: host.group_name || null,
        group_description: host.group_description || null,
        group_color: host.group_color || null,
        owner: host.owner || 'Unassigned',
        cpuUsage: host.cpu_usage || null,
        memoryUsage: host.memory_usage || null,
        diskUsage: host.disk_usage || null,
        uptime: host.uptime || null,
        osVersion: host.os_version || host.operating_system,
        lastBackup: host.last_backup || null,
        sshKey: host.ssh_key || false,
        agent: host.agent_status || 'not_installed',
        profile: host.scan_profile || null,
        port: host.port || 22,
        username: host.username || '',
        authMethod: host.auth_method || 'ssh_key',
        ssh_key_fingerprint: host.ssh_key_fingerprint || null,
        ssh_key_type: host.ssh_key_type || null,
        ssh_key_bits: host.ssh_key_bits || null,
        ssh_key_comment: host.ssh_key_comment || null,
        // New scan information
        latestScanId: host.latest_scan_id || null,
        latestScanName: host.latest_scan_name || null,
        scanStatus: host.scan_status || null,
        scanProgress: host.scan_progress || null,
        failedRules: host.failed_rules || 0,
        passedRules: host.passed_rules || 0,
        totalRules: host.total_rules || 0,
      }));

      // Use only API hosts (no mock data)
      setHosts(transformedHosts);
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
  React.useEffect(() => {
    fetchHosts();
  }, []);

  // Auto-refresh effect with dynamic interval based on running scans
  React.useEffect(() => {
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
  React.useEffect(() => {
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

  // Bulk host selection handler - reserved for future multi-select operations
  const _handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allIds = Object.values(processedHosts)
        .flat()
        .map((h) => h.id);
      setSelectedHosts(allIds);
    } else {
      setSelectedHosts([]);
    }
  };

  const handleSelectHost = (hostId: string) => {
    setSelectedHosts((prev) =>
      prev.includes(hostId) ? prev.filter((id) => id !== hostId) : [...prev, hostId]
    );
  };

  const handleBulkAction = (action: string) => {
    if (action === 'scan') {
      // Open Phase 2 bulk scan dialog
      setBulkScanDialog(true);
    } else {
      setSelectedBulkAction(action);
      setBulkActionDialog(true);
    }
  };

  const executeBulkAction = () => {
    console.log(`Executing ${selectedBulkAction} on hosts:`, selectedHosts);
    setBulkActionDialog(false);
    setSelectedHosts([]);
  };

  // Phase 2: Handle bulk scan start
  const handleBulkScanStarted = (sessionId: string, sessionName: string) => {
    console.log(`Bulk scan session started: ${sessionId}`);
    setBulkScanProgress({
      open: true,
      sessionId,
      sessionName,
    });
    setBulkScanDialog(false);
    setSelectedHosts([]); // Clear selection
  };

  // Quick scan completion handler - reserved for future scan event handling
  const _handleQuickScanStarted = (scanId: string, scanName: string) => {
    console.log(`Quick scan started: ${scanId} - ${scanName}`);
    // Refresh hosts to show scan status
    setTimeout(() => fetchHosts(true), 1000);
  };

  // WEEK 2 PHASE 1: Pre-scan JIT validation (silent, compliance-focused)
  const handleQuickScanWithValidation = async (host: Host) => {
    try {
      // Silent JIT connectivity check (no UI blocking)
      console.log(`Pre-scan validation for ${host.hostname}...`);

      const _jitCheck = await api.post(`/api/monitoring/hosts/${host.id}/check-connectivity`);

      // Wait 3 seconds for check to complete
      await new Promise((resolve) => setTimeout(resolve, 3000));

      // Get updated state
      const stateResponse = await api.get(`/api/monitoring/hosts/${host.id}/state`);
      const state = stateResponse.data || stateResponse;

      // ONLY block scan if host is DOWN (completely unreachable)
      // Compliance priority: allow scans unless host is definitively down
      if (state.current_state === 'DOWN') {
        alert(
          `Cannot start scan: Host ${host.hostname} is unreachable.\n\n` +
            `Last error: ${state.recent_history?.[0]?.error_message || 'Connection failed'}\n\n` +
            `Please check network connectivity and SSH credentials.`
        );
        setQuickScanDialog({ open: false, host: null });
        return;
      }

      // For DEGRADED/CRITICAL: Log warning but proceed silently (don't confuse user)
      if (state.current_state === 'DEGRADED' || state.current_state === 'CRITICAL') {
        console.warn(
          `Host ${host.hostname} has connectivity issues (${state.current_state}), proceeding with scan anyway`
        );
      }

      // Proceed with scan - navigate to scan creation page
      setQuickScanDialog({ open: false, host: null });
      navigate('/scans/new-scap', { state: { preselectedHostId: host.id } });
    } catch (error) {
      console.error('Pre-scan JIT check failed:', error);
      // Fallback: if JIT check fails, proceed anyway (don't block compliance workflow)
      setQuickScanDialog({ open: false, host: null });
      navigate('/scans/new-scap', { state: { preselectedHostId: host.id } });
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

    if (import.meta.env.DEV) {
      console.debug('Initializing edit form with host data:', host);
      console.debug('Initial auth method:', host.authMethod);
      console.debug('Form data being set:', initialFormData);
    }

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

  // SSH key deletion handler - reserved for future credential management features
  const _handleDeleteSSHKey = async () => {
    if (!editDialog.host) return;

    setDeletingSSHKey(true);
    try {
      await api.delete(`/api/hosts/${editDialog.host.id}/ssh-key`);

      // Refresh hosts list to get latest data
      await fetchHosts();

      // Update edit dialog host state to reflect changes
      setEditDialog((prev) =>
        prev.host
          ? {
              ...prev,
              host: {
                ...prev.host,
                ssh_key_fingerprint: undefined,
                ssh_key_type: undefined,
                ssh_key_bits: undefined,
                ssh_key_comment: undefined,
                sshKey: false,
              },
            }
          : prev
      );
    } catch (error) {
      console.error('Error deleting SSH key:', error);
    } finally {
      setDeletingSSHKey(false);
    }
  };

  const confirmEdit = async () => {
    if (!editDialog.host) return;

    try {
      const requestData = {
        hostname: editFormData.hostname,
        ip_address: editFormData.ipAddress,
        display_name: editFormData.displayName,
        operating_system: editFormData.operatingSystem,
        port: editFormData.port,
        username: editFormData.username,
        auth_method: editFormData.authMethod,
        ssh_key: editFormData.sshKey,
        password: editFormData.password,
      };

      if (import.meta.env.DEV) {
        console.debug('Sending edit host request:', requestData);
        console.debug('Auth method being sent:', editFormData.authMethod);
      }

      await api.put(`/api/hosts/${editDialog.host.id}`, requestData);

      // Refresh hosts list to get latest data including SSH key metadata
      await fetchHosts();
      setEditDialog({ open: false, host: null });
    } catch (error) {
      console.error('Error updating host:', error);
    }
  };

  const checkHostStatus = async (hostId: string) => {
    try {
      // Perform IMMEDIATE comprehensive connectivity check (ping → port → SSH)
      const result = await api.post(`/api/monitoring/hosts/${hostId}/check-connectivity`);

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

      console.log(`Host comprehensive status check for ${host?.hostname}:`, result);

      // Show detailed popup
      alert(detailedMessage);

      // Refresh hosts list to show updated status
      setTimeout(() => fetchHosts(true), 1000);
    } catch (error) {
      console.error('Error checking host status:', error);
      alert('Failed to check host status. Please try again.');
    }
  };

  // Bulk host status check handler - reserved for future monitoring features
  const _checkAllHostsStatus = async () => {
    try {
      await api.post('/api/monitoring/hosts/check-all');

      // Refresh hosts after a delay to get updated statuses
      setTimeout(() => {
        fetchHosts();
      }, 3000);
    } catch (error) {
      console.error('Error starting host monitoring:', error);
    }
  };

  const fetchSystemCredentialsForEdit = async () => {
    try {
      // Use unified credentials API with scope filter
      const response = await api.get('/api/system/credentials?scope=system');
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
  const validateSshKeyForEdit = (keyContent: string) => {
    if (!keyContent.trim()) {
      setSshKeyValidated(false);
      return;
    }

    const isValid = validateSshKey(keyContent);
    setSshKeyValidated(isValid);
  };

  /**
   * NOTE: getStatusIcon and getComplianceScoreColor are now imported from utils/
   * - getStatusIcon: utils/hostStatus.ts (status icon components)
   * - getComplianceScoreColor: utils/hostStatus.ts (compliance score colors)
   *
   * These utilities are reusable across the application for consistent
   * status visualization and compliance scoring.
   */

  const HostCard: React.FC<{ host: Host; viewMode?: ViewMode }> = ({ host, viewMode = 'grid' }) => {
    const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

    // Render compact view - simplified card with minimal height
    if (viewMode === 'compact') {
      return (
        <Card
          onClick={() => navigate(`/hosts/${host.id}`)}
          sx={{
            height: 120,
            display: 'flex',
            flexDirection: 'column',
            position: 'relative',
            transition: 'all 0.3s',
            cursor: 'pointer',
            '&:hover': {
              transform: 'translateY(-2px)',
              boxShadow: theme.shadows[4],
            },
            ...(selectedHosts.includes(host.id) && {
              borderColor: theme.palette.primary.main,
              borderWidth: 2,
              borderStyle: 'solid',
            }),
          }}
        >
          <CardContent sx={{ p: 1.5, pb: '8px !important' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <Checkbox
                checked={selectedHosts.includes(host.id)}
                onChange={() => handleSelectHost(host.id)}
                onClick={(e) => e.stopPropagation()}
                size="small"
              />
              <Avatar
                sx={{
                  bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
                  color: getComplianceScoreColor(host.complianceScore, theme),
                  mr: 1,
                  width: 32,
                  height: 32,
                }}
              >
                <Computer fontSize="small" />
              </Avatar>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Typography variant="body2" fontWeight="bold" noWrap>
                  {host.displayName}
                </Typography>
                <Typography variant="caption" color="text.secondary" noWrap>
                  {host.hostname}
                </Typography>
              </Box>
            </Box>
            <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
              <StatusChip status={host.status} size="small" variant="filled" />
              {host.complianceScore !== null && (
                <Chip
                  label={`${host.complianceScore.toFixed(0)}%`}
                  size="small"
                  color={
                    host.complianceScore >= 70
                      ? 'success'
                      : host.complianceScore >= 40
                        ? 'warning'
                        : 'error'
                  }
                  sx={{ height: 18, fontSize: '0.65rem' }}
                />
              )}
            </Box>
          </CardContent>
        </Card>
      );
    }

    // Render list view - horizontal layout
    if (viewMode === 'list') {
      return (
        <Card
          onClick={() => navigate(`/hosts/${host.id}`)}
          sx={{
            display: 'flex',
            alignItems: 'center',
            p: 2,
            transition: 'all 0.3s',
            cursor: 'pointer',
            '&:hover': {
              boxShadow: theme.shadows[4],
              bgcolor: alpha(theme.palette.primary.main, 0.02),
            },
            ...(selectedHosts.includes(host.id) && {
              borderColor: theme.palette.primary.main,
              borderWidth: 2,
              borderStyle: 'solid',
            }),
          }}
        >
          <Checkbox
            checked={selectedHosts.includes(host.id)}
            onChange={() => handleSelectHost(host.id)}
            onClick={(e) => e.stopPropagation()}
            size="small"
            sx={{ mr: 2 }}
          />
          <Avatar
            sx={{
              bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
              color: getComplianceScoreColor(host.complianceScore, theme),
              mr: 2,
            }}
          >
            <Computer />
          </Avatar>
          <Box sx={{ flexGrow: 1, mr: 2, minWidth: 0 }}>
            <Typography variant="subtitle1" fontWeight="bold" noWrap>
              {host.displayName}
            </Typography>
            <Typography variant="body2" color="text.secondary" noWrap>
              {host.hostname} • {host.ipAddress}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, minWidth: 0, flexShrink: 0 }}>
            <StatusChip status={host.status} size="small" variant="filled" />
            <Chip label={host.operatingSystem} size="small" variant="outlined" />
            {host.complianceScore !== null && (
              <ComplianceRing
                score={host.complianceScore}
                size="small"
                trend={host.complianceTrend}
              />
            )}
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                setAnchorEl(e.currentTarget);
              }}
            >
              <MoreVert />
            </IconButton>
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
              <MenuItem
                onClick={() => {
                  setQuickScanDialog({ open: true, host });
                  setAnchorEl(null);
                }}
              >
                <ListItemIcon>
                  <Scanner fontSize="small" />
                </ListItemIcon>
                <ListItemText>Quick Scan</ListItemText>
              </MenuItem>
              <MenuItem onClick={() => handleEditHost(host)}>
                <ListItemIcon>
                  <Edit fontSize="small" />
                </ListItemIcon>
                <ListItemText>Edit</ListItemText>
              </MenuItem>
              <MenuItem>
                <ListItemIcon>
                  <VpnKey fontSize="small" />
                </ListItemIcon>
                <ListItemText>SSH Connect</ListItemText>
              </MenuItem>
              <MenuItem
                onClick={(e) => {
                  e.stopPropagation();
                  setAnchorEl(null);
                  navigate(`/hosts/${host.id}`);
                }}
              >
                <ListItemIcon>
                  <Timeline fontSize="small" />
                </ListItemIcon>
                <ListItemText>View History</ListItemText>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => checkHostStatus(host.id)}>
                <ListItemIcon>
                  <NetworkCheck fontSize="small" />
                </ListItemIcon>
                <ListItemText>Check Status</ListItemText>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => handleDeleteHost(host)} sx={{ color: 'error.main' }}>
                <ListItemIcon>
                  <Delete fontSize="small" color="error" />
                </ListItemIcon>
                <ListItemText>Remove</ListItemText>
              </MenuItem>
            </Menu>
          </Box>
        </Card>
      );
    }

    // Default grid view - original layout
    return (
      <Card
        onClick={() => navigate(`/hosts/${host.id}`)}
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          transition: 'all 0.3s',
          cursor: 'pointer',
          '&:hover': {
            transform: 'translateY(-4px)',
            boxShadow: theme.shadows[8],
          },
          ...(selectedHosts.includes(host.id) && {
            borderColor: theme.palette.primary.main,
            borderWidth: 2,
            borderStyle: 'solid',
          }),
        }}
      >
        <CardContent sx={{ pb: 1 }}>
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Checkbox
              checked={selectedHosts.includes(host.id)}
              onChange={() => handleSelectHost(host.id)}
              onClick={(e) => e.stopPropagation()}
              size="small"
            />
            <Avatar
              sx={{
                bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
                color: getComplianceScoreColor(host.complianceScore, theme),
                mr: 1,
              }}
            >
              <Computer />
            </Avatar>
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="subtitle1" fontWeight="bold" noWrap>
                {host.displayName}
              </Typography>
              <Typography variant="caption" color="text.secondary" noWrap>
                {host.hostname} • {host.ipAddress}
              </Typography>
            </Box>
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                setAnchorEl(e.currentTarget);
              }}
              sx={{ ml: 'auto' }}
            >
              <MoreVert />
            </IconButton>
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
              <MenuItem
                onClick={() => {
                  setQuickScanDialog({ open: true, host });
                  setAnchorEl(null);
                }}
              >
                <ListItemIcon>
                  <Scanner fontSize="small" />
                </ListItemIcon>
                <ListItemText>Quick Scan</ListItemText>
              </MenuItem>
              <MenuItem onClick={() => handleEditHost(host)}>
                <ListItemIcon>
                  <Edit fontSize="small" />
                </ListItemIcon>
                <ListItemText>Edit</ListItemText>
              </MenuItem>
              <MenuItem>
                <ListItemIcon>
                  <VpnKey fontSize="small" />
                </ListItemIcon>
                <ListItemText>SSH Connect</ListItemText>
              </MenuItem>
              <MenuItem
                onClick={(e) => {
                  e.stopPropagation();
                  setAnchorEl(null);
                  navigate(`/hosts/${host.id}`);
                }}
              >
                <ListItemIcon>
                  <Timeline fontSize="small" />
                </ListItemIcon>
                <ListItemText>View History</ListItemText>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => checkHostStatus(host.id)}>
                <ListItemIcon>
                  <NetworkCheck fontSize="small" />
                </ListItemIcon>
                <ListItemText>Check Status</ListItemText>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => handleDeleteHost(host)} sx={{ color: 'error.main' }}>
                <ListItemIcon>
                  <Delete fontSize="small" color="error" />
                </ListItemIcon>
                <ListItemText>Remove</ListItemText>
              </MenuItem>
            </Menu>
          </Box>

          {/* Status and OS */}
          <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
            <StatusChip status={host.status} size="small" variant="filled" />
            <Chip label={host.operatingSystem} size="small" variant="outlined" />
          </Box>

          {/* Compliance Score - Always show (empty ring if no data) */}
          <Box sx={{ mb: 2 }}>
            <ComplianceRing
              score={host.complianceScore || 0}
              size="large"
              showLabel={false}
              // Failed rule counts by severity
              criticalIssues={host.criticalIssues || 0}
              highIssues={host.highIssues || 0}
              mediumIssues={host.mediumIssues || 0}
              lowIssues={host.lowIssues || 0}
              // Per-severity pass/fail breakdown for accurate visualization
              criticalPassed={host.criticalPassed}
              criticalFailed={host.criticalFailed}
              highPassed={host.highPassed}
              highFailed={host.highFailed}
              mediumPassed={host.mediumPassed}
              mediumFailed={host.mediumFailed}
              lowPassed={host.lowPassed}
              lowFailed={host.lowFailed}
              tooltip={
                host.complianceScore !== null
                  ? `${host.complianceScore}% compliant - ${host.passedRules || 0} passed, ${(host.totalRules || 0) - (host.passedRules || 0)} failed`
                  : 'No scan data available'
              }
            />
          </Box>

          {/* System Resources - Only show if data is available */}
          {(host.cpuUsage !== null || host.diskUsage !== null) && (
            <Box sx={{ mb: 2 }}>
              {host.cpuUsage !== null && (
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                  <Memory fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                  <Typography variant="caption" sx={{ mr: 1, minWidth: 30 }}>
                    CPU
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={host.cpuUsage}
                    sx={{ flexGrow: 1, mr: 1, height: 4, borderRadius: 2 }}
                  />
                  <Typography variant="caption">{host.cpuUsage}%</Typography>
                </Box>
              )}
              {host.diskUsage !== null && (
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                  <StorageIcon fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                  <Typography variant="caption" sx={{ mr: 1, minWidth: 30 }}>
                    Disk
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={host.diskUsage}
                    sx={{ flexGrow: 1, mr: 1, height: 4, borderRadius: 2 }}
                    color={host.diskUsage > 80 ? 'warning' : 'primary'}
                  />
                  <Typography variant="caption">{host.diskUsage}%</Typography>
                </Box>
              )}
            </Box>
          )}

          {/* Tags - Only show if there are tags */}
          {host.tags && host.tags.length > 0 && (
            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
              {host.tags.map((tag) => (
                <Chip key={tag} label={tag} size="small" sx={{ height: 20, fontSize: '0.7rem' }} />
              ))}
            </Box>
          )}

          {/* Last Check and Last Scan - Show footer with available info */}
          <Box sx={{ mt: 2, pt: 2, borderTop: 1, borderColor: 'divider' }}>
            {/* Last Check - Always show if available */}
            {host.lastCheck && (
              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: 'block', mb: 0.5 }}
              >
                Last check:{' '}
                {(() => {
                  const lastCheck = new Date(host.lastCheck);
                  const now = new Date();
                  const diffMinutes = Math.floor(
                    Math.abs(now.getTime() - lastCheck.getTime()) / (1000 * 60)
                  );

                  if (diffMinutes < 1) return 'Just now';
                  if (diffMinutes < 60)
                    return `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;

                  const diffHours = Math.floor(diffMinutes / 60);
                  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;

                  const diffDays = Math.floor(diffHours / 24);
                  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
                })()}
              </Typography>
            )}

            {/* Latest Scan Information */}
            {host.latestScanId ? (
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ flexGrow: 1 }}>
                    Latest scan: {host.latestScanName || 'SCAP Compliance Scan'}
                  </Typography>
                  {host.scanStatus === 'running' && (
                    <Chip
                      label={`${host.scanProgress || 0}%`}
                      size="small"
                      color="primary"
                      sx={{ height: 16, fontSize: '0.6rem' }}
                    />
                  )}
                  {host.scanStatus === 'completed' && host.complianceScore !== null && (
                    <Chip
                      label={`${host.complianceScore.toFixed(1)}%`}
                      size="small"
                      color={
                        host.complianceScore >= 70
                          ? 'success'
                          : host.complianceScore >= 40
                            ? 'warning'
                            : 'error'
                      }
                      sx={{ height: 16, fontSize: '0.6rem' }}
                    />
                  )}
                  {host.scanStatus === 'failed' && (
                    <Chip
                      label="Failed"
                      size="small"
                      color="error"
                      sx={{ height: 16, fontSize: '0.6rem' }}
                    />
                  )}
                </Box>

                {host.scanStatus === 'running' && (
                  <Box sx={{ mb: 0.5 }}>
                    <LinearProgress
                      variant="determinate"
                      value={host.scanProgress || 0}
                      sx={{ height: 3, borderRadius: 2 }}
                    />
                  </Box>
                )}

                {host.scanStatus === 'completed' && host.totalRules && host.totalRules > 0 && (
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                    {host.passedRules}/{host.totalRules} rules passed • {host.failedRules} failed
                  </Typography>
                )}

                {host.lastScan && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ fontSize: '0.65rem', display: 'block' }}
                  >
                    {new Date(host.lastScan).toLocaleString()}
                  </Typography>
                )}
              </Box>
            ) : host.lastScan ? (
              <Typography variant="caption" color="text.secondary">
                Last scan: {new Date(host.lastScan).toLocaleDateString()}
              </Typography>
            ) : null}

            {/* No Check or Scan Message */}
            {!host.lastCheck && !host.lastScan && (
              <Typography variant="caption" color="text.secondary">
                Never monitored - Awaiting first connectivity check
              </Typography>
            )}
          </Box>
        </CardContent>

        {/* Quick Actions */}
        <Box
          sx={{
            mt: 'auto',
            p: 1,
            borderTop: 1,
            borderColor: 'divider',
            display: 'flex',
            justifyContent: 'space-around',
          }}
        >
          <Tooltip title={host.scanStatus === 'running' ? 'View Running Scan' : 'Start New Scan'}>
            <IconButton
              size="small"
              color="primary"
              onClick={(e) => {
                e.stopPropagation();
                if (host.latestScanId && host.scanStatus === 'running') {
                  navigate(`/scans/${host.latestScanId}`);
                } else {
                  // WEEK 2 PHASE 1: Use pre-scan JIT validation
                  handleQuickScanWithValidation(host);
                }
              }}
            >
              {host.scanStatus === 'running' ? <Visibility /> : <PlayArrow />}
            </IconButton>
          </Tooltip>
          <Tooltip title={host.latestScanId ? 'View Latest Scan Results' : 'View Host Details'}>
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                if (host.latestScanId) {
                  navigate(`/scans/${host.latestScanId}`);
                } else {
                  navigate(`/hosts/${host.id}`);
                }
              }}
            >
              {host.latestScanId ? <Assessment /> : <Info />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Edit Host">
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                handleEditHost(host);
              }}
            >
              <Edit />
            </IconButton>
          </Tooltip>
          <Tooltip title="SSH Connect">
            <IconButton size="small">
              <VpnKey />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete Host">
            <IconButton
              size="small"
              color="error"
              onClick={(e) => {
                e.stopPropagation();
                handleDeleteHost(host);
              }}
            >
              <Delete />
            </IconButton>
          </Tooltip>
        </Box>
      </Card>
    );
  };

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
          <Grid item xs={12} sm={6} md={2.4}>
            <StatCard
              title={autoRefreshEnabled ? 'Hosts Online (Auto)' : 'Hosts Online'}
              value={`${stats.online}/${stats.total}`}
              color="primary"
              icon={<Computer />}
              trend={stats.online === stats.total ? 'up' : 'flat'}
              trendValue={`${Math.round((stats.online / stats.total) * 100)}%`}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
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
          <Grid item xs={12} sm={6} md={2.4}>
            <StatCard
              title="Critical Issues"
              value={stats.criticalHosts}
              color="error"
              icon={<ErrorIcon />}
              trend={stats.criticalHosts === 0 ? 'up' : 'down'}
              subtitle={stats.criticalHosts === 0 ? 'All clear' : 'Needs attention'}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <StatCard
              title="Need Scanning"
              value={stats.needsScanning}
              color="warning"
              icon={<Scanner />}
              trend={stats.needsScanning === 0 ? 'up' : 'down'}
              subtitle={stats.needsScanning === 0 ? 'Up to date' : 'Behind schedule'}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
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
              <Grid item xs={12} sm={6} md={3} key={i}>
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
              {Object.entries(processedHosts).map(([groupName, hosts]) => (
                <Box key={groupName} sx={{ mb: 4 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6" sx={{ flexGrow: 1 }}>
                      {groupName} ({hosts.length})
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
                      {hosts.map((host) => (
                        <Grid item xs={12} sm={6} md={3} key={host.id}>
                          <HostCard host={host} viewMode={viewMode} />
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
                  <Grid item xs={12} sm={6} md={3} key={host.id}>
                    <HostCard host={host} viewMode={viewMode} />
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

      <Dialog
        open={editDialog.open}
        onClose={() => setEditDialog({ open: false, host: null })}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Edit Host</DialogTitle>
        <DialogContent>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Hostname"
                value={editFormData.hostname}
                onChange={(e) => setEditFormData((prev) => ({ ...prev, hostname: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Display Name"
                value={editFormData.displayName}
                onChange={(e) =>
                  setEditFormData((prev) => ({ ...prev, displayName: e.target.value }))
                }
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="IP Address"
                value={editFormData.ipAddress}
                onChange={(e) =>
                  setEditFormData((prev) => ({ ...prev, ipAddress: e.target.value }))
                }
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Operating System"
                value={editFormData.operatingSystem}
                onChange={(e) =>
                  setEditFormData((prev) => ({ ...prev, operatingSystem: e.target.value }))
                }
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Port"
                type="number"
                value={editFormData.port}
                onChange={(e) =>
                  setEditFormData((prev) => ({ ...prev, port: parseInt(e.target.value) }))
                }
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Username"
                value={editFormData.username}
                onChange={(e) => setEditFormData((prev) => ({ ...prev, username: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12}>
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  mb: 2,
                }}
              >
                <FormControl fullWidth sx={{ mr: editingAuthMethod ? 0 : 2 }}>
                  <InputLabel>Authentication Method</InputLabel>
                  <Select
                    value={editFormData.authMethod}
                    onChange={(e) => handleAuthMethodChange(e.target.value)}
                    disabled={
                      !editingAuthMethod &&
                      (sshKeyValidated || editFormData.authMethod === 'system_default')
                    }
                  >
                    <MenuItem value="system_default">System Default</MenuItem>
                    <MenuItem value="ssh_key">SSH Key</MenuItem>
                    <MenuItem value="password">Password</MenuItem>
                  </Select>
                </FormControl>
                {!editingAuthMethod &&
                  (sshKeyValidated || editFormData.authMethod === 'system_default') && (
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => setEditingAuthMethod(true)}
                      startIcon={<Edit />}
                    >
                      Edit
                    </Button>
                  )}
                {editingAuthMethod && (
                  <Button
                    variant="contained"
                    size="small"
                    onClick={() => setEditingAuthMethod(false)}
                    startIcon={<CheckCircle />}
                  >
                    Done
                  </Button>
                )}
              </Box>
            </Grid>

            {/* SSH Key Input - Show when SSH Key authentication is selected and editing or not validated */}
            {editFormData.authMethod === 'ssh_key' && (editingAuthMethod || !sshKeyValidated) && (
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="SSH Private Key"
                  value={editFormData.sshKey}
                  onChange={(e) => {
                    setEditFormData((prev) => ({ ...prev, sshKey: e.target.value }));
                    validateSshKeyForEdit(e.target.value);
                  }}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                  multiline
                  rows={6}
                  helperText={
                    sshKeyValidated ? 'SSH key is valid' : 'Paste your SSH private key content here'
                  }
                  error={editFormData.sshKey.length > 0 && !sshKeyValidated}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <VpnKey color={sshKeyValidated ? 'success' : 'inherit'} />
                      </InputAdornment>
                    ),
                    endAdornment: sshKeyValidated ? (
                      <InputAdornment position="end">
                        <CheckCircleOutline color="success" />
                      </InputAdornment>
                    ) : null,
                  }}
                />
              </Grid>
            )}

            {/* SSH Key Validated Display - Show when SSH key is validated and not editing */}
            {editFormData.authMethod === 'ssh_key' && sshKeyValidated && !editingAuthMethod && (
              <Grid item xs={12}>
                <Card
                  sx={{
                    border: '2px solid',
                    borderColor: 'success.main',
                    bgcolor: 'success.50',
                    '&:hover': { bgcolor: 'success.100' },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <CheckCircleOutline color="success" sx={{ mr: 1 }} />
                      <Typography variant="subtitle1" fontWeight="bold">
                        SSH Key Configured
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      Host-specific SSH key is configured and validated
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Password Input - Show when Password authentication is selected */}
            {editFormData.authMethod === 'password' && (
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type={showPassword ? 'text' : 'password'}
                  label="Password"
                  value={editFormData.password}
                  onChange={(e) =>
                    setEditFormData((prev) => ({ ...prev, password: e.target.value }))
                  }
                  helperText="Enter the password for SSH authentication - will be encrypted and stored securely"
                  disabled={!editingAuthMethod && editFormData.password.length === 0}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <VpnKey />
                      </InputAdornment>
                    ),
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
            )}

            {/* System Default Credentials Display */}
            {editFormData.authMethod === 'system_default' && (
              <Grid item xs={12}>
                <Card
                  sx={{
                    border: '2px solid',
                    borderColor: 'primary.main',
                    bgcolor: 'primary.50',
                    '&:hover': { bgcolor: 'primary.100' },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <Security color="primary" sx={{ mr: 1 }} />
                      <Typography variant="subtitle1" fontWeight="bold">
                        Using System Default Credentials
                      </Typography>
                    </Box>
                    {systemCredentialInfo ? (
                      <Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          <strong>Credential:</strong> {systemCredentialInfo.name}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          <strong>Username:</strong> {systemCredentialInfo.username}
                        </Typography>
                        {systemCredentialInfo.sshKeyType && (
                          <Typography variant="body2" color="text.secondary">
                            <strong>Key Type:</strong>{' '}
                            {systemCredentialInfo.sshKeyType.toUpperCase()}{' '}
                            {systemCredentialInfo.sshKeyBits}-bit
                            {systemCredentialInfo.sshKeyComment &&
                              ` (${systemCredentialInfo.sshKeyComment})`}
                          </Typography>
                        )}
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{ mt: 1, fontStyle: 'italic' }}
                        >
                          All credential input fields are hidden when using system default
                        </Typography>
                      </Box>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        Loading system credentials information...
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialog({ open: false, host: null })}>Cancel</Button>
          <Button onClick={confirmEdit} variant="contained">
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>

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
                  last_scan: host.lastScan,
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
          console.log('Cancelling bulk scan:', sessionId);
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
