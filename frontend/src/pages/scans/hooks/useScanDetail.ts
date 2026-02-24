/**
 * useScanDetail Hook
 *
 * Extracts all data fetching, state, filtering, and event handler logic
 * from ScanDetail.tsx so the component focuses on layout/rendering only.
 */

import type React from 'react';
import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../../../services/api';
import { storageGet, StorageKeys } from '../../../services/storage';
import { DEFAULT_FRAMEWORK } from '../../../constants/complianceFrameworks';
import type {
  ScanDetails,
  BackendRuleResult,
  RuleResult,
  SnackbarState,
} from '../components/scanTypes';
import {
  mapSeverity,
  mapResult,
  extractRuleTitle,
  extractRuleDescription,
  filterRules as filterRulesUtil,
  generateFallbackRuleResults,
} from '../components/scanUtils';

export interface UseScanDetailReturn {
  // Route
  id: string | undefined;
  navigate: ReturnType<typeof useNavigate>;

  // Data
  scan: ScanDetails | null;
  ruleResults: RuleResult[];
  filteredRules: RuleResult[];

  // Loading
  loading: boolean;
  refreshing: boolean;
  isLoading: boolean;

  // Filters
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  severityFilter: string;
  setSeverityFilter: (f: string) => void;
  resultFilter: string;
  setResultFilter: (f: string) => void;

  // Pagination
  page: number;
  setPage: (p: number) => void;
  rowsPerPage: number;
  handleChangePage: (event: unknown, newPage: number) => void;
  handleChangeRowsPerPage: (event: React.ChangeEvent<HTMLInputElement>) => void;

  // Tabs
  tabValue: number;
  handleTabChange: (event: React.SyntheticEvent, newValue: number) => void;

  // Menu
  anchorEl: HTMLElement | null;
  handleMenuOpen: (event: React.MouseEvent<HTMLElement>) => void;
  handleMenuClose: () => void;

  // Snackbar
  snackbar: SnackbarState;
  showSnackbar: (message: string, severity: SnackbarState['severity']) => void;
  closeSnackbar: () => void;

  // Dialogs
  remediationDialog: { open: boolean; rule: RuleResult | null };
  setRemediationDialog: (d: { open: boolean; rule: RuleResult | null }) => void;
  exportRuleDialog: { open: boolean; rule: RuleResult | null };
  setExportRuleDialog: (d: { open: boolean; rule: RuleResult | null }) => void;

  // Review
  reviewedRules: Set<string>;
  handleToggleReview: (ruleId: string) => void;

  // Actions
  handleRefresh: () => Promise<void>;
  handleExportReport: (format: 'html' | 'json' | 'csv') => Promise<void>;
  handleRescan: () => Promise<void>;
  handleRescanRule: (rule: RuleResult) => Promise<void>;
  handleExportRuleDetails: (format: 'json' | 'csv') => void;
  fetchScanDetails: (quiet?: boolean) => Promise<void>;
}

export function useScanDetail(): UseScanDetailReturn {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  // Data state
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [ruleResults, setRuleResults] = useState<RuleResult[]>([]);
  const [filteredRules, setFilteredRules] = useState<RuleResult[]>([]);

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [resultFilter, setResultFilter] = useState<string>('all');

  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  // Tabs
  const [tabValue, setTabValue] = useState(0);

  // Menu
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // Snackbar
  const [snackbar, setSnackbar] = useState<SnackbarState>({
    open: false,
    message: '',
    severity: 'info',
  });

  // Dialogs
  const [remediationDialog, setRemediationDialog] = useState<{
    open: boolean;
    rule: RuleResult | null;
  }>({ open: false, rule: null });
  const [exportRuleDialog, setExportRuleDialog] = useState<{
    open: boolean;
    rule: RuleResult | null;
  }>({ open: false, rule: null });

  // Review
  const [reviewedRules, setReviewedRules] = useState<Set<string>>(new Set());

  // ---- Helpers ----

  const showSnackbar = useCallback((message: string, severity: SnackbarState['severity']) => {
    setSnackbar({ open: true, message, severity });
  }, []);

  const closeSnackbar = useCallback(() => {
    setSnackbar((prev) => ({ ...prev, open: false }));
  }, []);

  // ---- Data fetching ----

  const fetchActualRuleResults = useCallback(async () => {
    try {
      interface ReportJsonResponse {
        rule_results?: BackendRuleResult[];
      }
      const data = await api.get<ReportJsonResponse>(`/api/scans/${id}/report/json`);

      if (data.rule_results && Array.isArray(data.rule_results)) {
        const actualRules: RuleResult[] = data.rule_results.map((rule: BackendRuleResult) => ({
          rule_id: rule.rule_id || 'unknown',
          title: rule.title || extractRuleTitle(rule.rule_id || '') || 'Unknown Rule',
          severity: mapSeverity(rule.severity || 'unknown'),
          result: mapResult(rule.result || 'unknown'),
          description:
            rule.description ||
            extractRuleDescription(rule.rule_id || '') ||
            'No description available',
          rationale: rule.rationale || '',
          remediation: rule.remediation || extractRuleDescription(rule.rule_id || '') || '',
        }));
        setRuleResults(actualRules);
      } else {
        // no rule_results from backend — use scan state for fallback
        setScan((prevScan) => {
          if (prevScan?.results) {
            setRuleResults(generateFallbackRuleResults(prevScan.results));
          }
          return prevScan;
        });
      }
    } catch (error) {
      console.warn('Failed to fetch actual rule results, using fallback:', error);
      setScan((prevScan) => {
        if (prevScan?.results) {
          setRuleResults(generateFallbackRuleResults(prevScan.results));
        }
        return prevScan;
      });
    }
  }, [id]);

  const fetchScanDetails = useCallback(
    async (quiet: boolean = false) => {
      try {
        if (!quiet) setLoading(true);
        const data = await api.get<ScanDetails>(`/api/scans/${id}`);
        setScan(data);

        if (data.status === 'completed' && data.results) {
          await fetchActualRuleResults();
        }
      } catch {
        if (!quiet) {
          showSnackbar('Failed to load scan details', 'error');
        }
      } finally {
        if (!quiet) setLoading(false);
      }
    },
    [id, fetchActualRuleResults, showSnackbar]
  );

  // ---- Effects ----

  useEffect(() => {
    fetchScanDetails();
  }, [fetchScanDetails]);

  // Auto-poll for running scans
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;

    if (scan && (scan.status === 'pending' || scan.status === 'running')) {
      interval = setInterval(() => {
        fetchScanDetails(true);
      }, 5000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
    // Only re-setup polling when status changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.status]);

  // Filter rules when criteria change
  useEffect(() => {
    const result = filterRulesUtil(ruleResults, searchQuery, severityFilter, resultFilter);
    setFilteredRules(result);
    setPage(0);
  }, [ruleResults, searchQuery, severityFilter, resultFilter]);

  // ---- Handlers ----

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    const useQuietMode = scan?.status === 'completed';
    await fetchScanDetails(useQuietMode);
    setRefreshing(false);
  }, [scan?.status, fetchScanDetails]);

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  }, []);

  const handleChangePage = useCallback((_event: unknown, newPage: number) => {
    setPage(newPage);
  }, []);

  const handleChangeRowsPerPage = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  }, []);

  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setAnchorEl(null);
  }, []);

  const handleToggleReview = useCallback(
    (ruleId: string) => {
      setReviewedRules((prev) => {
        const next = new Set(prev);
        if (next.has(ruleId)) {
          next.delete(ruleId);
          showSnackbar('Rule unmarked for review', 'info');
        } else {
          next.add(ruleId);
          showSnackbar('Rule marked for review', 'success');
        }
        return next;
      });
    },
    [showSnackbar]
  );

  const handleExportReport = useCallback(
    async (format: 'html' | 'json' | 'csv') => {
      try {
        showSnackbar(`Exporting report as ${format.toUpperCase()}...`, 'info');

        const downloadBlob = (blob: Blob, filename: string) => {
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        };

        if (format === 'html' || format === 'csv') {
          const blob = await api.get<Blob>(`/api/scans/${id}/report/${format}`, {
            responseType: 'blob',
          });
          downloadBlob(blob, `scan_${id}_report.${format}`);
        } else {
          const data = await api.get<Record<string, unknown>>(`/api/scans/${id}/report/${format}`);
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          downloadBlob(blob, `scan_${id}_report.json`);
        }

        showSnackbar(`Report exported successfully as ${format.toUpperCase()}`, 'success');
      } catch {
        showSnackbar(`Failed to export report as ${format.toUpperCase()}`, 'error');
      } finally {
        handleMenuClose();
      }
    },
    [id, showSnackbar, handleMenuClose]
  );

  const handleRescan = useCallback(async () => {
    if (!scan) return;

    try {
      showSnackbar('Initiating new scan with same configuration...', 'info');
      setIsLoading(true);

      interface HostData {
        platform?: string;
        platform_version?: string;
        hostname?: string;
      }
      const hostData = await api.get<HostData>(`/api/hosts/${scan.host_id}`);

      let platform = hostData?.platform;
      let platformVersion = hostData?.platform_version;

      if (!platform || !platformVersion) {
        const scanName = scan.name.toLowerCase();
        if (scanName.includes('rhel') || scanName.includes('red hat')) {
          platform = 'rhel';
          const m = scanName.match(/rhel\s*(\d+)|red\s*hat\s*(\d+)/i);
          if (m) platformVersion = m[1] || m[2];
        } else if (scanName.includes('ubuntu')) {
          platform = 'ubuntu';
          const m = scanName.match(/ubuntu\s*(\d+\.\d+)/i);
          if (m) platformVersion = m[1];
        } else if (scanName.includes('debian')) {
          platform = 'debian';
          const m = scanName.match(/debian\s*(\d+)/i);
          if (m) platformVersion = m[1];
        }
      }

      if (!platform || !platformVersion) {
        showSnackbar(
          'Cannot rescan: Host platform information is missing. Please update host details.',
          'error'
        );
        setIsLoading(false);
        handleMenuClose();
        return;
      }

      const framework = scan.profile_id || DEFAULT_FRAMEWORK;
      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_id: scan.host_id,
          hostname: scan.host_name || hostData.hostname,
          platform,
          platform_version: platformVersion,
          framework,
          include_enrichment: true,
          generate_report: true,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Failed to start rescan');
      }

      const result = await response.json();
      showSnackbar(
        `New scan started successfully! Scan ID: ${result.scan_id} (${platform} ${platformVersion})`,
        'success'
      );

      setTimeout(() => {
        navigate(`/scans/${result.scan_id}`);
      }, 1500);
    } catch (error: unknown) {
      console.error('Failed to start rescan:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to start new scan';
      showSnackbar(errorMessage, 'error');
    } finally {
      setIsLoading(false);
      handleMenuClose();
    }
  }, [scan, navigate, showSnackbar, handleMenuClose]);

  const handleRescanRule = useCallback(
    async (rule: RuleResult) => {
      try {
        setIsLoading(true);
        showSnackbar(`Initiating rescan for rule: ${rule.rule_id}...`, 'info');

        const result = await api.post<{ scan_id: string }>(`/api/scans/${id}/rescan/rule`, {
          rule_id: rule.rule_id,
          name: `Rule Rescan: ${rule.rule_id}`,
        });

        showSnackbar(
          `Rule rescan initiated successfully. New scan ID: ${result.scan_id}`,
          'success'
        );

        setTimeout(() => {
          navigate(`/scans/${result.scan_id}`);
        }, 1500);
      } catch (error: unknown) {
        console.error('Failed to rescan rule:', error);
        const msg = error instanceof Error ? error.message : 'Failed to rescan rule';
        showSnackbar(msg, 'error');
      } finally {
        setIsLoading(false);
      }
    },
    [id, navigate, showSnackbar]
  );

  const handleExportRuleDetails = useCallback(
    (format: 'json' | 'csv') => {
      const rule = exportRuleDialog.rule;
      if (!rule) return;

      try {
        let content: string;
        let filename: string;
        let mimeType: string;

        if (format === 'json') {
          const exportData = {
            rule_id: rule.rule_id,
            title: rule.title,
            severity: rule.severity,
            result: rule.result,
            description: rule.description,
            rationale: rule.rationale,
            remediation: rule.remediation,
            scan_id: id,
            scan_name: scan?.name,
            host_name: scan?.host_name,
            export_timestamp: new Date().toISOString(),
          };
          content = JSON.stringify(exportData, null, 2);
          filename = `rule_${rule.rule_id}_details.json`;
          mimeType = 'application/json';
        } else {
          const rows = [
            ['Field', 'Value'],
            ['Rule ID', rule.rule_id],
            ['Title', rule.title],
            ['Severity', rule.severity],
            ['Result', rule.result],
            ['Description', rule.description],
            ['Host Name', scan?.host_name || ''],
            ['Scan ID', id || ''],
          ];
          content = rows.map((row) => row.map((cell) => `"${cell}"`).join(',')).join('\n');
          filename = `rule_${rule.rule_id}_details.csv`;
          mimeType = 'text/csv';
        }

        const blob = new Blob([content], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showSnackbar(`Rule details exported as ${format.toUpperCase()}`, 'success');
        setExportRuleDialog({ open: false, rule: null });
      } catch {
        showSnackbar('Failed to export rule details', 'error');
      }
    },
    [exportRuleDialog.rule, id, scan, showSnackbar]
  );

  return {
    id,
    navigate,
    scan,
    ruleResults,
    filteredRules,
    loading,
    refreshing,
    isLoading,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    resultFilter,
    setResultFilter,
    page,
    setPage,
    rowsPerPage,
    handleChangePage,
    handleChangeRowsPerPage,
    tabValue,
    handleTabChange,
    anchorEl,
    handleMenuOpen,
    handleMenuClose,
    snackbar,
    showSnackbar,
    closeSnackbar,
    remediationDialog,
    setRemediationDialog,
    exportRuleDialog,
    setExportRuleDialog,
    reviewedRules,
    handleToggleReview,
    handleRefresh,
    handleExportReport,
    handleRescan,
    handleRescanRule,
    handleExportRuleDetails,
    fetchScanDetails,
  };
}
