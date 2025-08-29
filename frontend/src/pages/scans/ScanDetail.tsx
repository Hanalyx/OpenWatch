import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  Button,
  IconButton,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Alert,
  CircularProgress,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  Snackbar,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogContentText,
  FormControlLabel,
  Checkbox,
  Link,
  Stack,
  Stepper,
  Step,
  StepLabel,
  StepContent
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  GetApp as DownloadIcon,
  Share as ShareIcon,
  Print as PrintIcon,
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Assessment as AssessmentIcon,
  BugReport as BugReportIcon,
  Build as BuildIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  Flag as FlagIcon,
  FileCopy as FileCopyIcon,
  Terminal as TerminalIcon,
  Code as CodeIcon,
  OpenInNew as OpenInNewIcon,
  BookmarkBorder as BookmarkBorderIcon,
  Bookmark as BookmarkIcon
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ChartTooltip, ResponsiveContainer, Legend } from 'recharts';
import RemediationPanel from '../../components/remediation/RemediationPanel';
import { api } from '../../services/api';

interface ScanDetails {
  id: number;
  name: string;
  host_id: string;
  host_name: string;
  hostname: string;
  content_id: number;
  content_name: string;
  content_filename: string;
  profile_id: string;
  status: string;
  progress: number;
  result_file?: string;
  report_file?: string;
  error_message?: string;
  scan_options: any;
  started_at: string;
  completed_at?: string;
  started_by: number;
  results?: {
    total_rules: number;
    passed_rules: number;
    failed_rules: number;
    error_rules: number;
    unknown_rules: number;
    not_applicable_rules: number;
    score: string;
    severity_high: number;
    severity_medium: number;
    severity_low: number;
  };
}

interface RuleResult {
  rule_id: string;
  title: string;
  severity: 'high' | 'medium' | 'low' | 'unknown';
  result: 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable';
  description: string;
  rationale?: string;
  remediation?: string;
  markedForReview?: boolean;
}

interface RemediationStep {
  title: string;
  description: string;
  command?: string;
  type: 'command' | 'config' | 'manual';
  documentation?: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`scan-tabpanel-${index}`}
      aria-labelledby={`scan-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

const ScanDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [ruleResults, setRuleResults] = useState<RuleResult[]>([]);
  const [filteredRules, setFilteredRules] = useState<RuleResult[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [resultFilter, setResultFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' as 'success' | 'error' | 'warning' | 'info' });
  
  // New state for enhanced functionality
  const [remediationDialog, setRemediationDialog] = useState({ open: false, rule: null as RuleResult | null });
  const [exportRuleDialog, setExportRuleDialog] = useState({ open: false, rule: null as RuleResult | null });
  const [reviewedRules, setReviewedRules] = useState<Set<string>>(new Set());
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    fetchScanDetails();
  }, [id]);

  // Auto-polling for running scans with optimized refresh
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    
    if (scan && (scan.status === 'pending' || scan.status === 'running')) {
      // Poll every 5 seconds for running scans (reduced from 3 seconds)
      interval = setInterval(() => {
        fetchScanDetailsQuiet(); // Use quiet fetch to avoid loading spinner
      }, 5000);
    }
    
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [scan?.status]);

  useEffect(() => {
    filterRules();
  }, [ruleResults, searchQuery, severityFilter, resultFilter]);

  const fetchScanDetails = async (quiet: boolean = false) => {
    try {
      if (!quiet) setLoading(true);
      const data = await api.get(`/api/scans/${id}`);
      setScan(data);
      
      // Fetch actual rule results if scan is completed
      if (data.status === 'completed' && data.results) {
        await fetchActualRuleResults(quiet);
      }
    } catch (error) {
      if (!quiet) {
        showSnackbar('Failed to load scan details', 'error');
      }
    } finally {
      if (!quiet) setLoading(false);
    }
  };

  const fetchScanDetailsQuiet = () => fetchScanDetails(true);

  const fetchActualRuleResults = async (quiet: boolean = false) => {
    try {
      // Fetch actual rule results from JSON report endpoint
      const data = await api.get(`/api/scans/${id}/report/json`);
      
      // Check if we have actual rule results from XML parsing
      if (data.rule_results && Array.isArray(data.rule_results)) {
        const actualRules: RuleResult[] = data.rule_results.map((rule: any) => ({
          rule_id: rule.rule_id || 'unknown',
          title: rule.title || extractRuleTitle(rule.rule_id) || 'Unknown Rule',
          severity: mapSeverity(rule.severity || 'unknown'),
          result: mapResult(rule.result || 'unknown'),
          description: rule.description || extractRuleDescription(rule.rule_id) || 'No description available',
          rationale: rule.rationale || '',
          remediation: rule.remediation || extractRuleDescription(rule.rule_id) || ''
        }));
        
        console.log(`Using ${actualRules.length} real SCAP rules with${actualRules.some(r => r.remediation) ? '' : 'out'} remediation data`);
        setRuleResults(actualRules);
      } else {
        // Fallback to generating placeholder rules if XML parsing failed
        generateFallbackRuleResults();
      }
    } catch (error) {
      console.warn('Failed to fetch actual rule results, using fallback:', error);
      generateFallbackRuleResults();
    }
  };

  const extractRuleTitle = (ruleId: string): string => {
    // Extract meaningful title from SCAP rule ID
    if (!ruleId) return 'Unknown Rule';
    
    // Remove common prefixes to get the actual rule name
    const cleanId = ruleId
      .replace('xccdf_org.ssgproject.content_rule_', '')
      .replace('xccdf_', '')
      .replace(/_/g, ' ');
    
    // Common SCAP rule mappings
    const ruleMappings: { [key: string]: string } = {
      'package_aide_installed': 'Install AIDE',
      'service_auditd_enabled': 'Enable Audit Daemon',
      'accounts_password_minlen_login_defs': 'Set Minimum Password Length',
      'sshd_disable_root_login': 'Disable SSH Root Login',
      'kernel_module_usb_storage_disabled': 'Disable USB Storage',
      'service_firewalld_enabled': 'Enable Firewall Service',
      'file_permissions_etc_passwd': 'Set Correct Permissions on /etc/passwd',
      'accounts_max_concurrent_login_sessions': 'Limit Concurrent Login Sessions',
      'sysctl_kernel_randomize_va_space': 'Enable Address Space Randomization',
      'mount_option_tmp_noexec': 'Mount /tmp with noexec Option'
    };
    
    // Check for exact matches first
    const lastPart = ruleId.split('_').slice(-3).join('_');
    if (ruleMappings[lastPart]) {
      return ruleMappings[lastPart];
    }
    
    // Generate title from rule ID
    return cleanId
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim() || 'Security Configuration Rule';
  };

  const extractRuleDescription = (ruleId: string): string => {
    // Generate description based on rule ID patterns
    if (!ruleId) return 'No description available';
    
    if (ruleId.includes('package') && ruleId.includes('installed')) {
      return 'Ensures that the required security package is installed on the system.';
    }
    if (ruleId.includes('service') && ruleId.includes('enabled')) {
      return 'Ensures that the required security service is enabled and running.';
    }
    if (ruleId.includes('sshd')) {
      return 'Configures SSH daemon settings according to security best practices.';
    }
    if (ruleId.includes('password')) {
      return 'Implements password policy requirements for system security.';
    }
    if (ruleId.includes('file_permissions')) {
      return 'Sets appropriate file permissions on system configuration files.';
    }
    if (ruleId.includes('kernel') || ruleId.includes('sysctl')) {
      return 'Configures kernel parameters for enhanced system security.';
    }
    if (ruleId.includes('mount')) {
      return 'Applies security-focused mount options to filesystem mountpoints.';
    }
    if (ruleId.includes('firewall')) {
      return 'Configures firewall settings to protect network services.';
    }
    
    return 'Implements security configuration requirements as defined by the compliance profile.';
  };

  const mapSeverity = (severity: string): 'high' | 'medium' | 'low' | 'unknown' => {
    const s = severity.toLowerCase();
    if (['high', 'critical'].includes(s)) return 'high';
    if (['medium', 'moderate'].includes(s)) return 'medium';
    if (['low', 'info', 'informational'].includes(s)) return 'low';
    return 'unknown';
  };

  const mapResult = (result: string): 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable' => {
    const r = result.toLowerCase();
    if (r === 'pass') return 'pass';
    if (r === 'fail') return 'fail';
    if (r === 'error') return 'error';
    if (['notapplicable', 'na', 'n/a', 'not applicable'].includes(r)) return 'notapplicable';
    return 'unknown';
  };

  const generateFallbackRuleResults = () => {
    if (!scan?.results) return;
    
    const fallbackRules: RuleResult[] = [];
    
    // Generate a reasonable number of placeholder rules based on actual counts
    const totalToGenerate = Math.min(100, scan.results.total_rules || 50);
    
    for (let i = 0; i < totalToGenerate; i++) {
      const isFailedRule = i < (scan.results.failed_rules || 0);
      const severity = isFailedRule ? 
        (i < (scan.results.severity_high || 0) ? 'high' : 
         i < ((scan.results.severity_high || 0) + (scan.results.severity_medium || 0)) ? 'medium' : 'low') : 
        (['high', 'medium', 'low'] as const)[i % 3];
      
      fallbackRules.push({
        rule_id: `xccdf_org.ssgproject.content_rule_security_check_${i + 1}`,
        title: `Security Configuration Rule ${i + 1}`,
        severity,
        result: isFailedRule ? 'fail' : 'pass',
        description: 'Security configuration rule - detailed information not available from scan results.',
        rationale: '',
        remediation: ''
      });
    }
    
    setRuleResults(fallbackRules);
  };

  const filterRules = () => {
    let filtered = [...ruleResults];
    
    // Apply search filter
    if (searchQuery) {
      filtered = filtered.filter(rule => 
        rule.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        rule.description.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    
    // Apply severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(rule => rule.severity === severityFilter);
    }
    
    // Apply result filter
    if (resultFilter !== 'all') {
      filtered = filtered.filter(rule => rule.result === resultFilter);
    }
    
    setFilteredRules(filtered);
    setPage(0); // Reset to first page when filtering
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    // Use quiet mode for manual refresh if scan is completed to avoid full loading spinner
    const useQuietMode = scan?.status === 'completed';
    await fetchScanDetails(useQuietMode);
    setRefreshing(false);
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleExportReport = async (format: 'html' | 'json' | 'csv') => {
    try {
      showSnackbar(`Exporting report as ${format.toUpperCase()}...`, 'info');
      
      // Handle different formats
      if (format === 'html') {
        const blob = await api.get(`/api/scans/${id}/report/${format}`, {
          responseType: 'blob'
        });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${id}_report.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else if (format === 'json') {
        const data = await api.get(`/api/scans/${id}/report/${format}`);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${id}_report.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else if (format === 'csv') {
        const blob = await api.get(`/api/scans/${id}/report/${format}`, {
          responseType: 'blob'
        });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${id}_report.csv`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
      
      showSnackbar(`Report exported successfully as ${format.toUpperCase()}`, 'success');
    } catch (error) {
      showSnackbar(`Failed to export report as ${format.toUpperCase()}`, 'error');
    } finally {
      handleMenuClose();
    }
  };

  const handleRescan = async () => {
    if (!scan) return;
    
    try {
      showSnackbar('Initiating new scan with same configuration...', 'info');
      
      const result = await api.post('/api/scans/', {
        name: `${scan.name} - Rescan ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`,
        host_id: scan.host_id,
        content_id: scan.content_id,
        profile_id: scan.profile_id,
        scan_options: scan.scan_options || {}
      });
      
      showSnackbar('New scan started successfully!', 'success');
      
      // Navigate to new scan after a short delay
      setTimeout(() => {
        navigate(`/scans/${result.id}`);
      }, 1500);
    } catch (error) {
      showSnackbar('Failed to start new scan', 'error');
    } finally {
      handleMenuClose();
    }
  };

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'warning' | 'info') => {
    setSnackbar({ open: true, message, severity });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'primary';
      case 'failed': return 'error';
      case 'pending': return 'warning';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#ffeb3b';
      default: return '#9e9e9e';
    }
  };

  const getResultIcon = (result: string) => {
    switch (result) {
      case 'pass': return <CheckCircleIcon color="success" />;
      case 'fail': return <CancelIcon color="error" />;
      case 'error': return <ErrorIcon color="error" />;
      case 'notapplicable': return <InfoIcon color="disabled" />;
      default: return <WarningIcon color="warning" />;
    }
  };

  // New handler functions for enhanced functionality
  const handleViewRemediation = (rule: RuleResult) => {
    setRemediationDialog({ open: true, rule });
  };

  const handleExportRule = (rule: RuleResult) => {
    setExportRuleDialog({ open: true, rule });
  };

  const handleToggleReview = (ruleId: string) => {
    const newReviewedRules = new Set(reviewedRules);
    if (newReviewedRules.has(ruleId)) {
      newReviewedRules.delete(ruleId);
      showSnackbar('Rule removed from review queue', 'info');
    } else {
      newReviewedRules.add(ruleId);
      showSnackbar('Rule marked for review', 'success');
    }
    setReviewedRules(newReviewedRules);
  };

  const handleRescanRule = async (rule: RuleResult) => {
    try {
      setIsLoading(true);
      const response = await fetch(`/api/scans/${id}/rescan/rule`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          rule_id: rule.rule_id,
          name: `Rule Rescan: ${rule.rule_id}`
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.detail || `Failed to initiate rule rescan (${response.status})`;
        throw new Error(errorMessage);
      }

      const result = await response.json();
      showSnackbar(`Rule rescan initiated successfully. New scan ID: ${result.scan_id}`, 'success');
      
      // Navigate to the new scan to show progress
      navigate(`/scans/${result.scan_id}`);
      
    } catch (error) {
      console.error('Error initiating rule rescan:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to initiate rule rescan';
      showSnackbar(errorMessage, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const closeRemediationDialog = () => {
    setRemediationDialog({ open: false, rule: null });
  };

  const closeExportRuleDialog = () => {
    setExportRuleDialog({ open: false, rule: null });
  };

  const generateRemediationSteps = (rule: RuleResult): RemediationStep[] => {
    const steps: RemediationStep[] = [];
    
    // First, try to use real SCAP remediation data if available
    if (rule.remediation && typeof rule.remediation === 'object') {
      const scapRemediation = rule.remediation as any;
      
      // Priority 1: Use Fix Text from SCAP compliance checker
      if (scapRemediation.fix_text) {
        steps.push({
          title: 'SCAP Compliance Fix Text',
          description: scapRemediation.fix_text,
          type: 'manual',
          documentation: 'Official SCAP compliance checker remediation'
        });
        console.log(`Using SCAP Fix Text for rule: ${rule.rule_id}`);
      }
      // Priority 2: Use OpenSCAP Evaluation Report remediation
      else if (scapRemediation.description) {
        steps.push({
          title: 'OpenSCAP Evaluation Remediation',
          description: scapRemediation.description,
          type: 'manual',
          documentation: 'OpenSCAP evaluation report guidance'
        });
        console.log(`Using OpenSCAP remediation for rule: ${rule.rule_id}`);
      }
      
      // Add detailed description as separate step if available and different
      if (scapRemediation.detailed_description && 
          scapRemediation.detailed_description !== scapRemediation.description &&
          scapRemediation.detailed_description !== scapRemediation.fix_text) {
        steps.push({
          title: 'Detailed Description',
          description: scapRemediation.detailed_description,
          type: 'manual'
        });
      }
      
      // Add SCAP remediation commands if available
      if (scapRemediation.commands && Array.isArray(scapRemediation.commands)) {
        scapRemediation.commands.forEach((cmd: any, index: number) => {
          steps.push({
            title: cmd.description || `Command ${index + 1}`,
            description: cmd.description || 'Execute the following command:',
            command: cmd.command,
            type: cmd.type === 'shell' ? 'command' : 'config'
          });
        });
      }
      
      // Add SCAP configuration steps if available
      if (scapRemediation.configuration && Array.isArray(scapRemediation.configuration)) {
        scapRemediation.configuration.forEach((config: any, index: number) => {
          steps.push({
            title: config.description || `Configuration ${index + 1}`,
            description: config.description || 'Apply the following configuration:',
            command: config.setting,
            type: 'config'
          });
        });
      }
      
      // Add SCAP remediation steps if available
      if (scapRemediation.steps && Array.isArray(scapRemediation.steps)) {
        scapRemediation.steps.forEach((step: string, index: number) => {
          steps.push({
            title: `Remediation Step ${index + 1}`,
            description: step,
            type: 'manual'
          });
        });
      }
      
      // Add complexity and disruption warnings if available
      if (scapRemediation.complexity && scapRemediation.complexity !== 'unknown') {
        steps.push({
          title: 'Implementation Complexity',
          description: `This remediation has ${scapRemediation.complexity} complexity${scapRemediation.disruption && scapRemediation.disruption !== 'unknown' ? ` and ${scapRemediation.disruption} disruption` : ''}.`,
          type: 'manual'
        });
      }
      
      // If we found real SCAP remediation data, return it
      if (steps.length > 0) {
        console.log(`Using ${steps.length} real SCAP remediation steps for rule: ${rule.rule_id}`);
        return steps;
      }
    }
    
    // Fallback to pattern-based remediation if no real SCAP data
    console.log(`Using fallback remediation for rule: ${rule.rule_id}`);
    const ruleId = rule.rule_id.toLowerCase();

    if (ruleId.includes('package') && ruleId.includes('installed')) {
      const packageName = extractPackageName(rule.rule_id);
      steps.push({
        title: `Install ${packageName}`,
        description: `Install the required security package using the system package manager.`,
        command: `sudo yum install -y ${packageName} || sudo apt-get install -y ${packageName}`,
        type: 'command',
        documentation: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/'
      });
      steps.push({
        title: 'Enable and Start Service',
        description: 'Enable the service to start automatically on boot and start it now.',
        command: `sudo systemctl enable ${packageName} && sudo systemctl start ${packageName}`,
        type: 'command'
      });
    } else if (ruleId.includes('service') && ruleId.includes('enabled')) {
      const serviceName = extractServiceName(rule.rule_id);
      steps.push({
        title: `Enable ${serviceName} Service`,
        description: 'Enable the service to start automatically on system boot.',
        command: `sudo systemctl enable ${serviceName}`,
        type: 'command'
      });
      steps.push({
        title: `Start ${serviceName} Service`,
        description: 'Start the service immediately.',
        command: `sudo systemctl start ${serviceName}`,
        type: 'command'
      });
    } else if (ruleId.includes('sshd')) {
      steps.push({
        title: 'Edit SSH Configuration',
        description: 'Modify the SSH daemon configuration file.',
        command: 'sudo nano /etc/ssh/sshd_config',
        type: 'config'
      });
      if (ruleId.includes('root_login')) {
        steps.push({
          title: 'Disable Root Login',
          description: 'Add or modify the following line in /etc/ssh/sshd_config:',
          command: 'PermitRootLogin no',
          type: 'config'
        });
      }
      steps.push({
        title: 'Restart SSH Service',
        description: 'Restart the SSH service to apply changes.',
        command: 'sudo systemctl restart sshd',
        type: 'command'
      });
    } else if (ruleId.includes('password')) {
      steps.push({
        title: 'Edit Password Configuration',
        description: 'Modify the password policy configuration.',
        command: 'sudo nano /etc/login.defs',
        type: 'config'
      });
      if (ruleId.includes('minlen')) {
        steps.push({
          title: 'Set Minimum Password Length',
          description: 'Add or modify the following line in /etc/login.defs:',
          command: 'PASS_MIN_LEN 14',
          type: 'config'
        });
      }
    } else if (ruleId.includes('file_permissions')) {
      const filePath = extractFilePath(rule.rule_id);
      steps.push({
        title: `Set File Permissions for ${filePath}`,
        description: 'Set the correct permissions on the system file.',
        command: `sudo chmod 644 ${filePath}`,
        type: 'command'
      });
      steps.push({
        title: 'Verify Permissions',
        description: 'Verify the file permissions are set correctly.',
        command: `ls -la ${filePath}`,
        type: 'command'
      });
    } else if (ruleId.includes('kernel') || ruleId.includes('sysctl')) {
      const paramName = extractKernelParam(rule.rule_id);
      steps.push({
        title: 'Set Kernel Parameter',
        description: 'Add the kernel parameter to the sysctl configuration.',
        command: `echo "${paramName} = 2" | sudo tee -a /etc/sysctl.conf`,
        type: 'command'
      });
      steps.push({
        title: 'Apply Changes',
        description: 'Apply the sysctl changes immediately.',
        command: 'sudo sysctl -p',
        type: 'command'
      });
    } else {
      // Generic remediation steps
      steps.push({
        title: 'Review Security Configuration',
        description: 'This rule requires manual review and configuration.',
        type: 'manual',
        documentation: 'https://www.nist.gov/cyberframework/framework'
      });
      steps.push({
        title: 'Consult Documentation',
        description: 'Refer to your organization\'s security policies and SCAP content documentation.',
        type: 'manual'
      });
    }

    return steps;
  };

  const extractPackageName = (ruleId: string): string => {
    const match = ruleId.match(/package_([a-z0-9_-]+)_installed/i);
    return match ? match[1].replace(/_/g, '-') : 'package';
  };

  const extractServiceName = (ruleId: string): string => {
    const match = ruleId.match(/service_([a-z0-9_-]+)_enabled/i);
    return match ? match[1] : 'service';
  };

  const extractFilePath = (ruleId: string): string => {
    if (ruleId.includes('etc_passwd')) return '/etc/passwd';
    if (ruleId.includes('etc_shadow')) return '/etc/shadow';
    if (ruleId.includes('etc_group')) return '/etc/group';
    return '/etc/config';
  };

  const extractKernelParam = (ruleId: string): string => {
    if (ruleId.includes('randomize_va_space')) return 'kernel.randomize_va_space';
    if (ruleId.includes('exec_shield')) return 'kernel.exec-shield';
    return 'kernel.parameter';
  };

  const handleExportRuleDetails = (format: 'json' | 'csv') => {
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
          remediation_steps: generateRemediationSteps(rule),
          scan_id: id,
          scan_name: scan?.name,
          host_name: scan?.host_name,
          export_timestamp: new Date().toISOString()
        };
        content = JSON.stringify(exportData, null, 2);
        filename = `rule_${rule.rule_id}_details.json`;
        mimeType = 'application/json';
      } else {
        // CSV format
        const steps = generateRemediationSteps(rule);
        const csvRows = [
          ['Field', 'Value'],
          ['Rule ID', rule.rule_id],
          ['Title', rule.title],
          ['Severity', rule.severity],
          ['Result', rule.result],
          ['Description', rule.description],
          ['Scan ID', id || ''],
          ['Scan Name', scan?.name || ''],
          ['Host Name', scan?.host_name || ''],
          ['Export Timestamp', new Date().toISOString()],
          ['', ''],
          ['Remediation Steps', ''],
          ...steps.map((step, index) => [`Step ${index + 1}`, `${step.title}: ${step.description}${step.command ? ` Command: ${step.command}` : ''}`])
        ];
        content = csvRows.map(row => `"${row[0]}","${row[1]}"`).join('\n');
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
      closeExportRuleDialog();
    } catch (error) {
      showSnackbar(`Failed to export rule details as ${format.toUpperCase()}`, 'error');
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!scan) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Scan not found</Alert>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/scans')} sx={{ mt: 2 }}>
          Back to Scans
        </Button>
      </Box>
    );
  }

  const pieData = scan.results ? [
    { name: 'Passed', value: scan.results.passed_rules, color: '#4caf50' },
    { name: 'Failed', value: scan.results.failed_rules, color: '#f44336' },
    { name: 'Error', value: scan.results.error_rules, color: '#ff9800' },
    { name: 'N/A', value: scan.results.not_applicable_rules, color: '#9e9e9e' }
  ].filter(item => item.value > 0) : [];

  const severityData = scan.results ? [
    { name: 'High', value: scan.results.severity_high, color: '#f44336' },
    { name: 'Medium', value: scan.results.severity_medium, color: '#ff9800' },
    { name: 'Low', value: scan.results.severity_low, color: '#ffeb3b' }
  ] : [];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <IconButton onClick={() => navigate('/scans')}>
            <ArrowBackIcon />
          </IconButton>
          <Typography variant="h4" component="h1">
            Scan Details
          </Typography>
          <Chip 
            label={scan.status.toUpperCase()} 
            color={getStatusColor(scan.status)} 
            size="small"
          />
        </Box>
        
        <Box display="flex" gap={1}>
          <Button
            variant="outlined"
            startIcon={refreshing ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            Refresh
          </Button>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleMenuOpen}
          >
            Export
          </Button>
          <IconButton onClick={handleMenuOpen}>
            <MoreVertIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Scan Info Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={6} lg={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <ComputerIcon color="primary" />
                <Typography variant="subtitle2" color="text.secondary">
                  Target Host
                </Typography>
              </Box>
              <Typography variant="h6" fontWeight="bold">
                {scan.host_name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {scan.hostname}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6} lg={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <SecurityIcon color="primary" />
                <Typography variant="subtitle2" color="text.secondary">
                  Content
                </Typography>
              </Box>
              <Typography variant="h6" fontWeight="bold" noWrap>
                {scan.content_name}
              </Typography>
              <Typography variant="body2" color="text.secondary" noWrap>
                {scan.profile_id}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6} lg={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <AssessmentIcon color="primary" />
                <Typography variant="subtitle2" color="text.secondary">
                  Compliance Score
                </Typography>
              </Box>
              <Typography variant="h6" fontWeight="bold">
                {scan.results?.score || 'N/A'}
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={parseFloat(scan.results?.score || '0')} 
                sx={{ mt: 1 }}
                color={parseFloat(scan.results?.score || '0') > 80 ? 'success' : 
                       parseFloat(scan.results?.score || '0') > 60 ? 'warning' : 'error'}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6} lg={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <BugReportIcon color="primary" />
                <Typography variant="subtitle2" color="text.secondary">
                  Critical Findings
                </Typography>
              </Box>
              <Typography variant="h6" fontWeight="bold" color="error.main">
                {scan.results?.severity_high || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                High severity issues
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content */}
      <Paper sx={{ width: '100%' }}>
        <Tabs value={tabValue} onChange={handleTabChange} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab label="Overview" />
          <Tab label="Failed Rules" />
          <Tab label="All Rules" />
          <Tab label="Remediation" />
          <Tab label="Scan Information" />
        </Tabs>

        <TabPanel value={tabValue} index={0}>
          {/* Overview Tab */}
          {scan.status === 'completed' && scan.results ? (
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Compliance Summary
                </Typography>
                <Box height={300}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <ChartTooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>
                  Severity Distribution
                </Typography>
                <Box height={300}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={severityData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <ChartTooltip />
                      <Bar dataKey="value" fill="#8884d8">
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Summary Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {scan.results.total_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Total Rules
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {scan.results.passed_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Passed
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="error.main">
                        {scan.results.failed_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Failed
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="warning.main">
                        {scan.results.error_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Errors
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="text.secondary">
                        {scan.results.not_applicable_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        N/A
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={4} md={2}>
                    <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="info.main">
                        {scan.results.unknown_rules}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Unknown
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          ) : scan.status === 'running' || scan.status === 'pending' ? (
            <Box textAlign="center" py={4}>
              <CircularProgress size={60} />
              <Typography variant="h6" sx={{ mt: 2 }}>
                {scan.status === 'pending' ? 'Scan Initializing...' : 'Scan in Progress...'}
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={scan.progress || 0} 
                sx={{ mt: 2, maxWidth: 400, mx: 'auto' }}
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {scan.progress || 0}% Complete
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: '0.875rem' }}>
                {scan.progress === 0 && 'Initializing scan task...'}
                {scan.progress === 5 && 'Setting up scan environment...'}
                {scan.progress === 10 && 'Processing credentials...'}
                {scan.progress === 20 && 'Testing SSH connection...'}
                {scan.progress === 30 && 'Executing security scan...'}
                {scan.progress >= 90 && 'Finalizing results...'}
                {scan.progress > 30 && scan.progress < 90 && 'Running compliance checks...'}
              </Typography>
              {scan.started_at && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: '0.75rem' }}>
                  Started: {new Date(scan.started_at).toLocaleString()}
                </Typography>
              )}
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mt: 2, gap: 1 }}>
                <RefreshIcon sx={{ fontSize: '1rem', animation: 'spin 2s linear infinite' }} />
                <Typography variant="caption" color="text.secondary">
                  Auto-refreshing every 3 seconds...
                </Typography>
              </Box>
              <style>{`
                @keyframes spin {
                  from { transform: rotate(0deg); }
                  to { transform: rotate(360deg); }
                }
              `}</style>
            </Box>
          ) : scan.status === 'failed' ? (
            <Alert severity="error" sx={{ mt: 2 }}>
              <Typography variant="h6">Scan Failed</Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                {scan.error_message || 'Unknown error occurred'}
              </Typography>
              {scan.progress > 0 && (
                <Typography variant="body2" color="text.secondary">
                  Progress reached: {scan.progress}% before failure
                </Typography>
              )}
              {scan.completed_at && (
                <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem', mt: 1 }}>
                  Failed at: {new Date(scan.completed_at).toLocaleString()}
                </Typography>
              )}
            </Alert>
          ) : null}
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          {/* Failed Rules Tab */}
          <Box mb={2}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  variant="outlined"
                  placeholder="Search failed rules..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  select
                  label="Severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <MenuItem value="all">All Severities</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="text.secondary">
                  Showing {filteredRules.filter(r => r.result === 'fail').length} failed rules
                </Typography>
              </Grid>
            </Grid>
          </Box>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Rule ID</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredRules
                  .filter(rule => rule.result === 'fail')
                  .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                  .map((rule) => (
                    <TableRow key={rule.rule_id}>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {rule.rule_id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {rule.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={rule.severity.toUpperCase()} 
                          size="small"
                          sx={{ 
                            bgcolor: getSeverityColor(rule.severity),
                            color: 'white'
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <Tooltip title="View remediation">
                            <IconButton 
                              size="small" 
                              onClick={() => handleViewRemediation(rule)}
                              color="primary"
                            >
                              <BuildIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export rule details">
                            <IconButton 
                              size="small" 
                              onClick={() => handleExportRule(rule)}
                              color="info"
                            >
                              <FileCopyIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={reviewedRules.has(rule.rule_id) ? "Remove from review queue" : "Mark for review"}>
                            <IconButton 
                              size="small" 
                              onClick={() => handleToggleReview(rule.rule_id)}
                              color={reviewedRules.has(rule.rule_id) ? "warning" : "default"}
                            >
                              {reviewedRules.has(rule.rule_id) ? <BookmarkIcon /> : <BookmarkBorderIcon />}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Rescan this rule">
                            <IconButton 
                              size="small" 
                              onClick={() => handleRescanRule(rule)}
                              color="secondary"
                              disabled={isLoading}
                            >
                              <RefreshIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </TableContainer>
          
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={filteredRules.filter(r => r.result === 'fail').length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          {/* All Rules Tab */}
          <Box mb={2}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  variant="outlined"
                  placeholder="Search all rules..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  select
                  label="Result"
                  value={resultFilter}
                  onChange={(e) => setResultFilter(e.target.value)}
                >
                  <MenuItem value="all">All Results</MenuItem>
                  <MenuItem value="pass">Passed</MenuItem>
                  <MenuItem value="fail">Failed</MenuItem>
                  <MenuItem value="error">Error</MenuItem>
                  <MenuItem value="notapplicable">N/A</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  select
                  label="Severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <MenuItem value="all">All Severities</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12} md={2}>
                <Typography variant="body2" color="text.secondary">
                  {filteredRules.length} rules
                </Typography>
              </Grid>
            </Grid>
          </Box>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Result</TableCell>
                  <TableCell>Rule ID</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredRules
                  .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                  .map((rule) => (
                    <TableRow key={rule.rule_id}>
                      <TableCell>
                        {getResultIcon(rule.result)}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {rule.rule_id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {rule.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={rule.severity.toUpperCase()} 
                          size="small"
                          sx={{ 
                            bgcolor: getSeverityColor(rule.severity),
                            color: rule.severity === 'low' ? 'black' : 'white'
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <Tooltip title="View remediation">
                            <IconButton 
                              size="small" 
                              onClick={() => handleViewRemediation(rule)}
                              color="primary"
                            >
                              <BuildIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export rule details">
                            <IconButton 
                              size="small" 
                              onClick={() => handleExportRule(rule)}
                              color="info"
                            >
                              <FileCopyIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={reviewedRules.has(rule.rule_id) ? "Remove from review queue" : "Mark for review"}>
                            <IconButton 
                              size="small" 
                              onClick={() => handleToggleReview(rule.rule_id)}
                              color={reviewedRules.has(rule.rule_id) ? "warning" : "default"}
                            >
                              {reviewedRules.has(rule.rule_id) ? <BookmarkIcon /> : <BookmarkBorderIcon />}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Rescan this rule">
                            <IconButton 
                              size="small" 
                              onClick={() => handleRescanRule(rule)}
                              color="secondary"
                              disabled={isLoading}
                            >
                              <RefreshIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </TableContainer>
          
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={filteredRules.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={3}>
          {/* Remediation Tab */}
          <RemediationPanel
            scanId={id || ''}
            hostId={scan?.host_id || ''}
            scanStatus={scan?.status || ''}
            onRemediationStarted={() => {
              // Refresh scan data to show updated remediation status
              fetchScanDetails();
            }}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={4}>
          {/* Scan Information Tab */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Scan Configuration
              </Typography>
              <List>
                <ListItem>
                  <ListItemText 
                    primary="Scan Name" 
                    secondary={scan.name}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Scan ID" 
                    secondary={scan.id}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Profile ID" 
                    secondary={scan.profile_id}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Started At" 
                    secondary={new Date(scan.started_at).toLocaleString()}
                  />
                </ListItem>
                {scan.completed_at && (
                  <ListItem>
                    <ListItemText 
                      primary="Completed At" 
                      secondary={new Date(scan.completed_at).toLocaleString()}
                    />
                  </ListItem>
                )}
                <ListItem>
                  <ListItemText 
                    primary="Duration" 
                    secondary={
                      scan.completed_at 
                        ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)} seconds`
                        : 'In progress...'
                    }
                  />
                </ListItem>
              </List>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Technical Details
              </Typography>
              <List>
                <ListItem>
                  <ListItemText 
                    primary="Result File" 
                    secondary={scan.result_file || 'Not available'}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Report File" 
                    secondary={scan.report_file || 'Not available'}
                  />
                </ListItem>
                {scan.error_message && (
                  <ListItem>
                    <ListItemText 
                      primary="Error Message" 
                      secondary={scan.error_message}
                      secondaryTypographyProps={{ color: 'error' }}
                    />
                  </ListItem>
                )}
              </List>
              
              {scan.scan_options && Object.keys(scan.scan_options).length > 0 && (
                <>
                  <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
                    Scan Options
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <pre style={{ margin: 0, overflow: 'auto' }}>
                      {JSON.stringify(scan.scan_options, null, 2)}
                    </pre>
                  </Paper>
                </>
              )}
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={() => handleExportReport('html')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as HTML</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExportReport('json')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as JSON</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExportReport('csv')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as CSV</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleRescan}>
          <ListItemIcon>
            <PlayArrowIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Run New Scan</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => window.print()}>
          <ListItemIcon>
            <PrintIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Print Report</ListItemText>
        </MenuItem>
      </Menu>

      {/* Remediation Dialog */}
      <Dialog 
        open={remediationDialog.open} 
        onClose={closeRemediationDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <BuildIcon color="primary" />
            <Typography variant="h6">Remediation Steps</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {remediationDialog.rule && (
            <>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  {remediationDialog.rule.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', mb: 1 }}>
                  {remediationDialog.rule.rule_id}
                </Typography>
                <Chip 
                  label={remediationDialog.rule.severity.toUpperCase()} 
                  size="small"
                  color={remediationDialog.rule.severity === 'high' ? 'error' : 
                         remediationDialog.rule.severity === 'medium' ? 'warning' : 'info'}
                  sx={{ mb: 2 }}
                />
                <Typography variant="body2">
                  {remediationDialog.rule.description}
                </Typography>
              </Box>

              <Stepper orientation="vertical">
                {generateRemediationSteps(remediationDialog.rule).map((step, index) => (
                  <Step key={index} active>
                    <StepLabel>
                      <Typography variant="subtitle1" fontWeight="bold">
                        {step.title}
                      </Typography>
                    </StepLabel>
                    <StepContent>
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="body2" sx={{ mb: 1, whiteSpace: 'pre-wrap' }}>
                          {step.description}
                        </Typography>
                        
                        {/* Show source type for SCAP remediation */}
                        {(step.title.includes('SCAP Compliance Fix Text') || 
                          step.title.includes('OpenSCAP Evaluation Remediation')) && (
                          <Chip 
                            size="small" 
                            color="success" 
                            label={step.title.includes('Fix Text') ? 'SCAP Compliance Checker' : 'OpenSCAP Evaluation Report'}
                            sx={{ mb: 2 }}
                          />
                        )}
                      </Box>
                      
                      {step.command && (
                        <Paper 
                          variant="outlined" 
                          sx={{ 
                            p: 0, 
                            mb: 2, 
                            bgcolor: '#f8f9fa',
                            border: '1px solid #e9ecef',
                            borderRadius: 2,
                            overflow: 'hidden'
                          }}
                        >
                          <Box sx={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: 1, 
                            p: 1.5,
                            bgcolor: '#e9ecef', 
                            borderBottom: '1px solid #dee2e6' 
                          }}>
                            {step.type === 'command' ? <TerminalIcon color="primary" /> : <CodeIcon color="info" />}
                            <Typography variant="caption" fontWeight="bold" sx={{ color: '#495057' }}>
                              {step.type === 'command' ? 'Command:' : 'Configuration:'}
                            </Typography>
                            <IconButton 
                              size="small" 
                              onClick={() => {
                                navigator.clipboard.writeText(step.command || '');
                                showSnackbar('Command copied to clipboard', 'success');
                              }}
                              sx={{ ml: 'auto' }}
                            >
                              <FileCopyIcon fontSize="small" />
                            </IconButton>
                          </Box>
                          <Box 
                            component="pre" 
                            sx={{ 
                              p: 2,
                              m: 0,
                              fontFamily: '"Monaco", "Menlo", "Ubuntu Mono", monospace',
                              fontSize: '0.85rem',
                              lineHeight: 1.5,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              bgcolor: '#f8f9fa',
                              color: '#212529',
                              overflow: 'auto',
                              '&::-webkit-scrollbar': {
                                height: 6,
                                width: 6,
                              },
                              '&::-webkit-scrollbar-thumb': {
                                backgroundColor: 'rgba(0,0,0,0.2)',
                                borderRadius: 3,
                              },
                            }}
                          >
                            {step.command}
                          </Box>
                        </Paper>
                      )}
                      
                      {step.documentation && (
                        <Box sx={{ mt: 2 }}>
                          {step.documentation.startsWith('http') ? (
                            <Link 
                              href={step.documentation} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
                            >
                              <OpenInNewIcon fontSize="small" />
                              <Typography variant="caption">
                                View Documentation
                              </Typography>
                            </Link>
                          ) : (
                            <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                              Source: {step.documentation}
                            </Typography>
                          )}
                        </Box>
                      )}
                    </StepContent>
                  </Step>
                ))}
              </Stepper>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeRemediationDialog}>
            Close
          </Button>
          <Button 
            variant="contained" 
            startIcon={<FileCopyIcon />}
            onClick={() => {
              if (remediationDialog.rule) {
                const steps = generateRemediationSteps(remediationDialog.rule);
                const text = steps.map((step, i) => 
                  `${i + 1}. ${step.title}\n${step.description}${step.command ? `\n\nCommand: ${step.command}` : ''}`
                ).join('\n\n---\n\n');
                navigator.clipboard.writeText(text);
                showSnackbar('Remediation steps copied to clipboard', 'success');
              }
            }}
          >
            Copy All Steps
          </Button>
        </DialogActions>
      </Dialog>

      {/* Export Rule Dialog */}
      <Dialog 
        open={exportRuleDialog.open} 
        onClose={closeExportRuleDialog}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <FileCopyIcon color="info" />
            <Typography variant="h6">Export Rule Details</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {exportRuleDialog.rule && (
            <>
              <DialogContentText sx={{ mb: 2 }}>
                Export detailed information for the following rule:
              </DialogContentText>
              <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">
                  {exportRuleDialog.rule.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  {exportRuleDialog.rule.rule_id}
                </Typography>
              </Box>
              <DialogContentText>
                Choose the export format for the rule details including remediation steps:
              </DialogContentText>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeExportRuleDialog}>
            Cancel
          </Button>
          <Button 
            variant="outlined" 
            startIcon={<DownloadIcon />}
            onClick={() => handleExportRuleDetails('csv')}
          >
            Export CSV
          </Button>
          <Button 
            variant="contained" 
            startIcon={<DownloadIcon />}
            onClick={() => handleExportRuleDetails('json')}
          >
            Export JSON
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ScanDetail;