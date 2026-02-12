/**
 * Monitoring Stats Hook
 *
 * React Query hooks for host monitoring statistics.
 * Used by the Command Center dashboard widgets.
 *
 * @module hooks/useMonitoringStats
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';

/**
 * Host monitoring state distribution from backend
 */
export interface MonitoringStats {
  total_hosts: number;
  status_breakdown: {
    online?: number;
    degraded?: number;
    critical?: number;
    down?: number;
    maintenance?: number;
    unknown?: number;
    [key: string]: number | undefined;
  };
  avg_response_time_ms?: number;
  checks_today?: number;
  online_percentage?: number;
}

/**
 * Hook to fetch host monitoring statistics.
 * Used by SummaryBar and FleetHealthWidget.
 */
export function useMonitoringStats() {
  return useQuery<MonitoringStats>({
    queryKey: ['monitoringStats'],
    queryFn: async () => {
      // Fetch hosts to compute status breakdown
      const hosts = await api.get<
        Array<{
          id: string;
          status?: string;
          response_time_ms?: number | null;
        }>
      >('/api/hosts/');

      // Compute stats from hosts
      const statusBreakdown: Record<string, number> = {};
      let totalResponseTime = 0;
      let hostsWithResponse = 0;

      hosts.forEach((host) => {
        const status = host.status || 'unknown';
        statusBreakdown[status] = (statusBreakdown[status] || 0) + 1;

        if (host.response_time_ms != null) {
          totalResponseTime += host.response_time_ms;
          hostsWithResponse++;
        }
      });

      const onlineCount = (statusBreakdown['online'] || 0) + (statusBreakdown['reachable'] || 0);

      return {
        total_hosts: hosts.length,
        status_breakdown: statusBreakdown,
        avg_response_time_ms:
          hostsWithResponse > 0 ? Math.round(totalResponseTime / hostsWithResponse) : undefined,
        checks_today: undefined, // Not available from this endpoint
        online_percentage: hosts.length > 0 ? Math.round((onlineCount / hosts.length) * 100) : 0,
      };
    },
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // 1 minute auto-refresh
  });
}

export default {
  useMonitoringStats,
};
