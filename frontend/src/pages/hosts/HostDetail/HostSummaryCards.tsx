/**
 * Host Summary Cards Container
 *
 * Displays 6 summary cards with equal height in a responsive grid:
 * - Compliance: Score, pass/fail, critical findings
 * - System Health: OS, kernel, uptime, resources
 * - Auto-Scan: Enabled/paused, last/next scan
 * - Exceptions: Active/pending count
 * - Alerts: Active count, severity breakdown
 * - Connectivity: Online/offline, SSH info
 *
 * All cards maintain equal height using CSS minHeight.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/HostSummaryCards
 */

import React from 'react';
import Grid from '@mui/material/Grid';
import {
  ComplianceCard,
  SystemHealthCard,
  AutoScanCard,
  ExceptionsCard,
  AlertsCard,
  ConnectivityCard,
} from './cards';
import type { ComplianceState, HostSchedule, SystemInfo } from '../../../types/hostDetail';

interface HostSummaryCardsProps {
  /** Basic host info for connectivity card */
  host: {
    status: string;
    hostname: string;
    ipAddress: string;
    port: number;
    username: string;
    authMethod: string;
    lastCheck?: string | null;
  };

  /** Compliance state from Kensa scan */
  complianceState: ComplianceState | null | undefined;
  complianceLoading?: boolean;

  /** Schedule info from compliance scheduler */
  schedule: HostSchedule | null | undefined;
  scheduleLoading?: boolean;

  /** System info from server intelligence */
  systemInfo: SystemInfo | null | undefined;
  systemInfoLoading?: boolean;

  /** Exception counts (optional - requires OpenWatch+) */
  exceptionsActive?: number;
  exceptionsPending?: number;
  exceptionsExpiringSoon?: number;
  exceptionsLoading?: boolean;

  /** Alert counts (optional) */
  alertsActive?: number;
  alertsCritical?: number;
  alertsHigh?: number;
  recentAlertMessage?: string;
  recentAlertTime?: string;
  alertsLoading?: boolean;
}

const HostSummaryCards: React.FC<HostSummaryCardsProps> = ({
  host,
  complianceState,
  complianceLoading,
  schedule,
  scheduleLoading,
  systemInfo,
  systemInfoLoading,
  exceptionsActive = 0,
  exceptionsPending = 0,
  exceptionsExpiringSoon = 0,
  exceptionsLoading,
  alertsActive = 0,
  alertsCritical = 0,
  alertsHigh = 0,
  recentAlertMessage,
  recentAlertTime,
  alertsLoading,
}) => {
  return (
    <Grid container spacing={2} sx={{ mb: 3 }}>
      {/* Row 1: Compliance, System Health, Auto-Scan */}
      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <ComplianceCard complianceState={complianceState} isLoading={complianceLoading} />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <SystemHealthCard systemInfo={systemInfo} isLoading={systemInfoLoading} />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <AutoScanCard schedule={schedule} isLoading={scheduleLoading} />
      </Grid>

      {/* Row 2: Exceptions, Alerts, Connectivity */}
      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <ExceptionsCard
          activeCount={exceptionsActive}
          pendingCount={exceptionsPending}
          expiringSoonCount={exceptionsExpiringSoon}
          isLoading={exceptionsLoading}
        />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <AlertsCard
          activeCount={alertsActive}
          criticalCount={alertsCritical}
          highCount={alertsHigh}
          recentAlertMessage={recentAlertMessage}
          recentAlertTime={recentAlertTime}
          isLoading={alertsLoading}
        />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 4 }}>
        <ConnectivityCard
          status={host.status}
          hostname={host.hostname}
          ipAddress={host.ipAddress}
          port={host.port}
          username={host.username}
          authMethod={host.authMethod}
          lastCheck={host.lastCheck}
        />
      </Grid>
    </Grid>
  );
};

export default HostSummaryCards;
