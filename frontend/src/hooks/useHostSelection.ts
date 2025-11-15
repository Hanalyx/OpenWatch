/**
 * useHostSelection Hook
 *
 * Custom hook for managing host selection state for bulk operations.
 * Provides selection controls including select all, select none, and
 * toggle individual selections.
 *
 * Features:
 * - Individual host selection toggle
 * - Select all filtered hosts
 * - Clear all selections
 * - Selection count tracking
 * - Supports filtered host lists
 *
 * Used by:
 * - Hosts page (bulk operations toolbar)
 * - Bulk scan dialog
 * - Bulk delete operations
 *
 * @module hooks/useHostSelection
 */

import { useState, useCallback, useMemo } from 'react';
import type { Host } from '../types/host';

/**
 * Return type for useHostSelection hook.
 *
 * @interface UseHostSelectionReturn
 */
export interface UseHostSelectionReturn {
  /** Array of selected host IDs */
  selectedHosts: string[];
  /** Toggle selection for a single host */
  toggleHostSelection: (hostId: string) => void;
  /** Select all provided hosts */
  selectAll: (hosts: Host[]) => void;
  /** Clear all selections */
  clearSelection: () => void;
  /** Check if a host is selected */
  isSelected: (hostId: string) => boolean;
  /** Number of selected hosts */
  selectionCount: number;
  /** Whether any hosts are selected */
  hasSelection: boolean;
}

/**
 * Custom hook for managing host selection state.
 *
 * Handles selection logic for bulk operations, providing convenience
 * methods for common selection patterns (select all, clear, toggle).
 *
 * @returns Selection state and control functions
 *
 * @example
 * function HostsPage() {
 *   const { hosts } = useHostData();
 *   const { filteredHosts } = useHostFilters(hosts);
 *   const {
 *     selectedHosts,
 *     toggleHostSelection,
 *     selectAll,
 *     clearSelection,
 *     selectionCount
 *   } = useHostSelection();
 *
 *   return (
 *     <div>
 *       <button onClick={() => selectAll(filteredHosts)}>Select All</button>
 *       <button onClick={clearSelection}>Clear</button>
 *       <p>{selectionCount} hosts selected</p>
 *       {filteredHosts.map(host => (
 *         <HostCard
 *           key={host.id}
 *           host={host}
 *           selected={selectedHosts.includes(host.id)}
 *           onSelect={toggleHostSelection}
 *         />
 *       ))}
 *     </div>
 *   );
 * }
 */
export function useHostSelection(): UseHostSelectionReturn {
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);

  /**
   * Toggle selection for a single host.
   *
   * If host is currently selected, removes it from selection.
   * If host is not selected, adds it to selection.
   *
   * @param hostId - UUID of host to toggle
   */
  const toggleHostSelection = useCallback((hostId: string) => {
    setSelectedHosts((prev) => {
      if (prev.includes(hostId)) {
        return prev.filter((id) => id !== hostId);
      } else {
        return [...prev, hostId];
      }
    });
  }, []);

  /**
   * Select all hosts from provided list.
   *
   * Replaces current selection with all host IDs from the provided array.
   * Useful for "Select All" functionality on filtered results.
   *
   * @param hosts - Array of hosts to select
   */
  const selectAll = useCallback((hosts: Host[]) => {
    setSelectedHosts(hosts.map((h) => h.id));
  }, []);

  /**
   * Clear all selections.
   *
   * Resets selection state to empty array.
   */
  const clearSelection = useCallback(() => {
    setSelectedHosts([]);
  }, []);

  /**
   * Check if a specific host is selected.
   *
   * @param hostId - UUID of host to check
   * @returns True if host is in selection
   */
  const isSelected = useCallback(
    (hostId: string): boolean => {
      return selectedHosts.includes(hostId);
    },
    [selectedHosts]
  );

  /**
   * Number of currently selected hosts.
   */
  const selectionCount = useMemo(() => selectedHosts.length, [selectedHosts]);

  /**
   * Whether any hosts are currently selected.
   */
  const hasSelection = useMemo(() => selectedHosts.length > 0, [selectedHosts]);

  return {
    selectedHosts,
    toggleHostSelection,
    selectAll,
    clearSelection,
    isSelected,
    selectionCount,
    hasSelection,
  };
}
