/**
 * Host Management statistics cards.
 *
 * Displays online/total hosts, average compliance, critical issues,
 * hosts needing scanning, and a quick-add action card.
 */

import React from 'react';
import { Box } from '@mui/material';
import Grid from '@mui/material/Grid';
import { Add, Computer, Error as ErrorIcon, Scanner, Security } from '@mui/icons-material';
import { StatCard } from '../../../components/design-system';

interface HostStats {
  total: number;
  online: number;
  avgCompliance: number;
  criticalHosts: number;
  needsScanning: number;
}

interface HostStatCardsProps {
  stats: HostStats;
  autoRefreshEnabled: boolean;
  onAddHost: () => void;
}

const HostStatCards: React.FC<HostStatCardsProps> = ({ stats, autoRefreshEnabled, onAddHost }) => {
  return (
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
            onClick={onAddHost}
            subtitle="Register new system"
          />
        </Grid>
      </Grid>
    </Box>
  );
};

export default HostStatCards;
