/**
 * Host Detail Page
 *
 * Redesigned host detail page with auto-scan centric design.
 * Displays 6 summary cards and 11 tabs of detailed information.
 *
 * Cards: Compliance, System Health, Auto-Scan, Exceptions, Alerts, Connectivity
 * Tabs: Overview, Compliance, Packages, Services, Users, Network, Audit Log, History, Audit Timeline, Remediation, Terminal
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module pages/hosts/HostDetail
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Box, Tabs, Tab, CircularProgress, Alert } from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Inventory as InventoryIcon,
  MiscellaneousServices as ServicesIcon,
  People as PeopleIcon,
  Lan as NetworkIcon,
  History as HistoryIcon,
  Terminal as TerminalIcon,
  EventNote as AuditIcon,
  Build as RemediationIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';

import HostDetailHeader from './HostDetailHeader';
import HostSummaryCards from './HostSummaryCards';
import {
  OverviewTab,
  ComplianceTab,
  PackagesTab,
  ServicesTab,
  UsersTab,
  NetworkTab,
  AuditLogTab,
  HistoryTab,
  TerminalTab,
  AuditTimelineTab,
} from './tabs';

import {
  useComplianceState,
  useHostSchedule,
  useSystemInfo,
  useIntelligenceSummary,
  useScanHistory,
} from '../../../hooks/useHostDetail';
import { api } from '../../../services/api';
import RemediationPanel from '../../../components/remediation/RemediationPanel';

interface Host {
  id: string;
  hostname: string;
  display_name: string;
  ip_address: string;
  operating_system: string;
  status: string;
  port: number;
  username: string;
  auth_method: string;
  created_at: string;
  updated_at: string;
  last_check: string | null;
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
      id={`host-tabpanel-${index}`}
      aria-labelledby={`host-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

const HostDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const _navigate = useNavigate();
  const [host, setHost] = useState<Host | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [maintenanceMode, setMaintenanceMode] = useState(false);

  // React Query hooks for host detail data
  const { data: complianceState, isLoading: complianceLoading } = useComplianceState(id);

  const { data: schedule, isLoading: scheduleLoading } = useHostSchedule(id);

  const { data: systemInfo, isLoading: systemInfoLoading } = useSystemInfo(id);

  const { data: intelligenceSummary, isLoading: intelligenceLoading } = useIntelligenceSummary(id);

  const { data: scanHistoryData, isLoading: scanHistoryLoading } = useScanHistory(id);

  // Sync maintenance mode from schedule data
  useEffect(() => {
    if (schedule) {
      setMaintenanceMode(schedule.maintenanceMode);
    }
  }, [schedule]);

  const handleMaintenanceModeChange = useCallback((enabled: boolean) => {
    setMaintenanceMode(enabled);
  }, []);

  // Fetch basic host data
  useEffect(() => {
    const fetchHost = async () => {
      if (!id) return;
      setLoading(true);
      try {
        const data = await api.get<Host>(`/api/hosts/${id}`);
        setHost(data);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch host:', err);
        setError('Failed to load host details');
      } finally {
        setLoading(false);
      }
    };

    fetchHost();
  }, [id]);

  if (loading) {
    return (
      <Box>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress />
        </Box>
      </Box>
    );
  }

  if (error || !host) {
    return (
      <Box>
        <Alert severity="error" sx={{ mt: 2 }}>
          {error || 'Host not found'}
        </Alert>
      </Box>
    );
  }

  const scanHistory = scanHistoryData?.scans || [];

  return (
    <Box>
      {/* Header */}
      <HostDetailHeader
        hostname={host.hostname}
        displayName={host.display_name}
        ipAddress={host.ip_address}
        operatingSystem={host.operating_system}
        status={host.status}
        systemInfo={systemInfo}
        hostId={host.id}
        maintenanceMode={maintenanceMode}
        onMaintenanceModeChange={handleMaintenanceModeChange}
      />

      {/* Summary Cards */}
      <HostSummaryCards
        host={{
          status: host.status,
          hostname: host.hostname,
          ipAddress: host.ip_address,
          port: host.port,
          username: host.username,
          authMethod: host.auth_method,
          lastCheck: host.last_check,
        }}
        complianceState={complianceState}
        complianceLoading={complianceLoading}
        schedule={schedule}
        scheduleLoading={scheduleLoading}
        systemInfo={systemInfo}
        systemInfoLoading={systemInfoLoading}
        // Exceptions and alerts - placeholder values until API is integrated
        exceptionsActive={0}
        exceptionsPending={0}
        exceptionsLoading={false}
        alertsActive={0}
        alertsCritical={0}
        alertsHigh={0}
        alertsLoading={false}
      />

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs
          value={tabValue}
          onChange={(_, newValue) => setTabValue(newValue)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Overview" icon={<DashboardIcon />} iconPosition="start" />
          <Tab label="Compliance" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Packages" icon={<InventoryIcon />} iconPosition="start" />
          <Tab label="Services" icon={<ServicesIcon />} iconPosition="start" />
          <Tab label="Users" icon={<PeopleIcon />} iconPosition="start" />
          <Tab label="Network" icon={<NetworkIcon />} iconPosition="start" />
          <Tab label="Audit Log" icon={<AuditIcon />} iconPosition="start" />
          <Tab label="History" icon={<HistoryIcon />} iconPosition="start" />
          <Tab label="Audit Timeline" icon={<TimelineIcon />} iconPosition="start" />
          <Tab label="Remediation" icon={<RemediationIcon />} iconPosition="start" />
          <Tab label="Terminal" icon={<TerminalIcon />} iconPosition="start" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        <OverviewTab
          systemInfo={systemInfo}
          systemInfoLoading={systemInfoLoading}
          intelligenceSummary={intelligenceSummary}
          intelligenceLoading={intelligenceLoading}
          scanHistory={scanHistory}
          scanHistoryLoading={scanHistoryLoading}
        />
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <ComplianceTab complianceState={complianceState} isLoading={complianceLoading} />
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <PackagesTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <ServicesTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        <UsersTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={5}>
        <NetworkTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={6}>
        <AuditLogTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={7}>
        <HistoryTab scanHistory={scanHistory} isLoading={scanHistoryLoading} />
      </TabPanel>

      <TabPanel value={tabValue} index={8}>
        <AuditTimelineTab hostId={host.id} />
      </TabPanel>

      <TabPanel value={tabValue} index={9}>
        <RemediationPanel
          hostId={host.id}
          failedFindings={complianceState?.findings?.filter((f) => f.status === 'fail') || []}
        />
      </TabPanel>

      <TabPanel value={tabValue} index={10}>
        <TerminalTab hostId={host.id} hostname={host.hostname} ipAddress={host.ip_address} />
      </TabPanel>
    </Box>
  );
};

export default HostDetail;
