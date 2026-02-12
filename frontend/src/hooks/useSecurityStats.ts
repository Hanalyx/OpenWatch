/**
 * Security Stats Hook
 *
 * React Query hooks for security audit statistics.
 * Used by the Command Center dashboard widgets.
 *
 * @module hooks/useSecurityStats
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';

/**
 * Security audit statistics from backend
 */
export interface SecurityStats {
  total_events: number;
  login_attempts: number;
  failed_logins: number;
  scan_operations: number;
  admin_actions: number;
  security_events: number;
  unique_users: number;
  unique_ips: number;
}

/**
 * Audit event from backend
 */
export interface AuditEvent {
  id: number;
  user_id?: number;
  username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address: string;
  user_agent?: string;
  details?: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

/**
 * Hook to fetch security audit statistics.
 * Used by SummaryBar and SecurityEventsWidget.
 */
export function useSecurityStats() {
  return useQuery<SecurityStats>({
    queryKey: ['securityStats'],
    queryFn: async () => {
      return api.get<SecurityStats>('/api/audit/stats');
    },
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // 1 minute auto-refresh
  });
}

/**
 * Hook to fetch recent security events.
 * Used by SecurityEventsWidget.
 */
export function useRecentSecurityEvents(limit: number = 5) {
  return useQuery<{ events: AuditEvent[]; total: number }>({
    queryKey: ['securityEvents', 'recent', limit],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: '1',
        limit: limit.toString(),
      });
      return api.get<{ events: AuditEvent[]; total: number }>(`/api/audit/events?${params}`);
    },
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // 1 minute auto-refresh
  });
}

export default {
  useSecurityStats,
  useRecentSecurityEvents,
};
