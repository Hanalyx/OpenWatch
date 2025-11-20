/**
 * useHostFilters Hook
 *
 * Custom hook for managing host filtering, searching, sorting, and grouping logic.
 * Provides a clean interface for complex host list manipulation without cluttering
 * the main component.
 *
 * Features:
 * - Full-text search across hostname, IP, display name
 * - Status filtering (online, offline, maintenance, etc.)
 * - Compliance score range filtering
 * - Tag-based filtering
 * - Grouping by status, compliance, or host group
 * - Memoized processing for performance
 *
 * Used by:
 * - Hosts page (main filtering UI)
 * - Dashboard (filtered host views)
 * - Reporting components
 *
 * @module hooks/useHostFilters
 */

import { useState, useMemo } from 'react';
import type { Host } from '../types/host';
import type { GroupBy } from '../components/design-system';

/**
 * Grouped hosts structure for display.
 *
 * @interface GroupedHosts
 */
export interface GroupedHosts {
  /** Group identifier */
  groupName: string;
  /** Hosts in this group */
  hosts: Host[];
  /** Optional group color (hex code) */
  color?: string;
}

/**
 * Return type for useHostFilters hook.
 *
 * @interface UseHostFiltersReturn
 */
export interface UseHostFiltersReturn {
  /** Current search query */
  searchQuery: string;
  /** Update search query */
  setSearchQuery: (query: string) => void;
  /** Selected status filters */
  statusFilter: string[];
  /** Update status filters */
  setStatusFilter: (statuses: string[]) => void;
  /** Compliance score range [min, max] */
  complianceFilter: [number, number];
  /** Update compliance filter */
  setComplianceFilter: (range: [number, number]) => void;
  /** Selected tag filters */
  tagFilter: string[];
  /** Update tag filters */
  setTagFilter: (tags: string[]) => void;
  /** Current grouping mode */
  groupBy: GroupBy;
  /** Update grouping mode */
  setGroupBy: (mode: GroupBy) => void;
  /** Filtered and processed hosts */
  filteredHosts: Host[];
  /** Grouped hosts (if groupBy !== 'all') */
  groupedHosts: GroupedHosts[];
  /** Statistics about filtered results */
  stats: {
    total: number;
    online: number;
    offline: number;
    scanning: number;
    avgCompliance: number;
  };
}

/**
 * Custom hook for host filtering and grouping.
 *
 * Processes host array through search, filters, and grouping logic.
 * Uses memoization to avoid expensive recalculations.
 *
 * @param hosts - Array of all hosts
 * @returns Filtered hosts and filter controls
 *
 * @example
 * function HostsPage() {
 *   const { hosts } = useHostData();
 *   const {
 *     searchQuery,
 *     setSearchQuery,
 *     filteredHosts,
 *     groupedHosts,
 *     stats
 *   } = useHostFilters(hosts);
 *
 *   return (
 *     <div>
 *       <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
 *       <p>Showing {filteredHosts.length} of {hosts.length} hosts</p>
 *       {groupedHosts.map(group => (
 *         <HostGroup key={group.groupName} {...group} />
 *       ))}
 *     </div>
 *   );
 * }
 */
export function useHostFilters(hosts: Host[]): UseHostFiltersReturn {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [complianceFilter, setComplianceFilter] = useState<[number, number]>([0, 100]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [groupBy, setGroupBy] = useState<GroupBy>('all');

  /**
   * Filter and search hosts based on current filter state.
   *
   * Applies filters in order:
   * 1. Search query (hostname, IP, display name)
   * 2. Status filter
   * 3. Compliance score range
   * 4. Tag filter
   */
  const filteredHosts = useMemo(() => {
    return hosts.filter((host) => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          host.hostname.toLowerCase().includes(query) ||
          host.displayName.toLowerCase().includes(query) ||
          host.ipAddress.toLowerCase().includes(query) ||
          host.operatingSystem.toLowerCase().includes(query);

        if (!matchesSearch) return false;
      }

      // Status filter
      if (statusFilter.length > 0) {
        if (!statusFilter.includes(host.status)) return false;
      }

      // Compliance filter
      if (host.complianceScore !== null) {
        const [min, max] = complianceFilter;
        if (host.complianceScore < min || host.complianceScore > max) return false;
      }

      // Tag filter
      if (tagFilter.length > 0) {
        const hasMatchingTag = tagFilter.some((tag) => host.tags.includes(tag));
        if (!hasMatchingTag) return false;
      }

      return true;
    });
  }, [hosts, searchQuery, statusFilter, complianceFilter, tagFilter]);

  /**
   * Group filtered hosts based on groupBy setting.
   *
   * Grouping modes:
   * - 'all': No grouping (returns empty array)
   * - 'none': No grouping (returns empty array)
   * - 'status': Group by host status
   * - 'compliance': Group by compliance level
   * - 'group': Group by host group assignment
   */
  const groupedHosts = useMemo((): GroupedHosts[] => {
    if (groupBy === 'all' || groupBy === 'none') {
      return [];
    }

    const groups = new Map<string, Host[]>();

    filteredHosts.forEach((host) => {
      let groupKey: string;

      switch (groupBy) {
        case 'status':
          groupKey = host.status;
          break;
        case 'compliance':
          if (host.complianceScore === null) {
            groupKey = 'Not Scanned';
          } else if (host.complianceScore >= 95) {
            groupKey = 'Compliant (95%+)';
          } else if (host.complianceScore >= 75) {
            groupKey = 'Near Compliant (75-94%)';
          } else {
            groupKey = 'Non-Compliant (<75%)';
          }
          break;
        case 'group':
          groupKey = host.group || 'Ungrouped';
          break;
        default:
          groupKey = 'All Hosts';
      }

      if (!groups.has(groupKey)) {
        groups.set(groupKey, []);
      }
      groups.get(groupKey)!.push(host);
    });

    return Array.from(groups.entries()).map(([groupName, groupHosts]) => ({
      groupName,
      hosts: groupHosts,
      color: groupHosts[0]?.group_color,
    }));
  }, [filteredHosts, groupBy]);

  /**
   * Calculate statistics for filtered hosts.
   *
   * Provides quick metrics for dashboard display:
   * - Total count
   * - Status counts (online, offline, scanning)
   * - Average compliance score
   */
  const stats = useMemo(() => {
    const total = filteredHosts.length;
    const online = filteredHosts.filter((h) => h.status === 'online').length;
    const offline = filteredHosts.filter((h) => h.status === 'offline').length;
    const scanning = filteredHosts.filter((h) => h.status === 'scanning').length;

    const hostsWithScores = filteredHosts.filter((h) => h.complianceScore !== null);
    const avgCompliance =
      hostsWithScores.length > 0
        ? hostsWithScores.reduce((sum, h) => sum + (h.complianceScore || 0), 0) /
          hostsWithScores.length
        : 0;

    return {
      total,
      online,
      offline,
      scanning,
      avgCompliance,
    };
  }, [filteredHosts]);

  return {
    searchQuery,
    setSearchQuery,
    statusFilter,
    setStatusFilter,
    complianceFilter,
    setComplianceFilter,
    tagFilter,
    setTagFilter,
    groupBy,
    setGroupBy,
    filteredHosts,
    groupedHosts,
    stats,
  };
}
